package wisp

import (
	"net"
	"net/http"
	"strings"
	"time"

	"mrrowisp/wisp/protection"

	"github.com/lxzan/gws"
)

const (
	defaultStreamLimitPerHost    = 512
	defaultStreamLimitTotal      = 16384
	defaultMaxConnectsPerSecond  = 20
	defaultConnectionsLimitPerIP = 120
	defaultHandshakeFailures     = 10
)

func (cfg *Config) InitResolver() {
	cfg.DNSCache = NewDNSCache(
		DNSCacheConfig{
			Servers:     cfg.DnsServers,
			Method:      cfg.DnsMethod,
			ResultOrder: cfg.DnsResultOrder,
		})
	// if cfg.BandwidthLimitKbps > 0 {
	// 	cfg.BandwidthLimiter = protection.NewBandwidthLimiter(cfg.BandwidthLimitKbps, time.Duration(cfg.ConnectionWindowSeconds)*time.Second)
	// }
	// if cfg.ConnectionsLimitPerIP > 0 {
	// 	cfg.ConnectionLimiter = protection.NewConnectionLimiter(cfg.ConnectionsLimitPerIP, time.Duration(cfg.ConnectionWindowSeconds)*time.Second)
	// }
	cfg.Logger = newLogger(cfg.LogLevel)
}

type upgradeHandler struct {
	gws.BuiltinEventHandler
}

func CreateWispHandler(config *Config) http.HandlerFunc {
	config.InitResolver()

	upgrader := gws.NewUpgrader(&upgradeHandler{}, &gws.ServerOption{
		PermessageDeflate: gws.PermessageDeflate{
			Enabled: false,
		},
	})

	guard := newProtection(config)

	return func(w http.ResponseWriter, r *http.Request) {
		useV2 := config.EnableV2 && r.Header.Get("Sec-WebSocket-Protocol") != ""
		remoteIP := protection.RemoteIPFromRequest(r, protection.IPConfig{
			AllowDirectIP:    config.AllowDirectIP,
			AllowPrivateIPs:  config.AllowPrivateIPs,
			AllowLoopbackIPs: config.AllowLoopbackIPs,
			ParseRealIP:      config.ParseRealIP,
		})
		config.Logger.Info("incoming connection", "ip", remoteIP, "path", r.URL.Path, "origin", r.Header.Get("Origin"))
		if config.requiresV2() && !useV2 {
			config.Logger.Warn("v2 required but not negotiated", "ip", remoteIP)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if status, response, ok := guard.allowHTTP(r, remoteIP, useV2); !ok {
			w.WriteHeader(status)
			if response != "" {
				_, _ = w.Write([]byte(response))
			}
			return
		}

		wsConn, err := upgrader.Upgrade(w, r)
		if err != nil {
			if config.NonWSResponse != "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(config.NonWSResponse))
			}
			config.Logger.Debug("websocket upgrade failed", "error", err)
			return
		}

		netConn := wsConn.NetConn()

		if tc, ok := netConn.(*net.TCPConn); ok {
			tc.SetReadBuffer(1 << 20)
			tc.SetWriteBuffer(1 << 20)
		}

		wc := &wispConnection{
			netConn: netConn,
			// writeCh:   make(chan writeReq, writeQSize),
			config:       config,
			twispStreams: newTwisp(),
			isV2:         useV2,
			remoteIP:     remoteIP,
			dialSem:      make(chan struct{}, maxConcurrentDials),
			closeCh:      make(chan struct{}),
			createdAt:    time.Now(),
		}

		config.Logger.Info("connection established", "ip", remoteIP, "v2", useV2)
		go wc.writeLoop()

		if useV2 {
			go wc.v2Handshake()
		} else {
			wc.sendPacket(0, config.BufferRemainingLength)
			go wc.readLoop()
		}
	}
}

func (cfg *Config) requiresV2() bool {
	if cfg == nil {
		return false
	}
	return cfg.PasswordAuthRequired || cfg.EnableTwisp
}

func originAllowed(r *http.Request, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	for _, allowed := range allowedOrigins {
		if origin == strings.TrimSpace(allowed) {
			return true
		}
	}
	return false
}
