package wisp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FilterSet struct {
	Hostnames map[string]struct{}
	Ports     map[uint16]struct{}
}

func (f *FilterSet) UnmarshalJSON(data []byte) error {
	if f.Hostnames == nil {
		f.Hostnames = map[string]struct{}{}
	}
	if f.Ports == nil {
		f.Ports = map[uint16]struct{}{}
	}

	var raw struct {
		Hostnames json.RawMessage `json:"hostnames"`
		Ports     json.RawMessage `json:"ports"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if len(raw.Hostnames) > 0 {
		var arr []string
		if err := json.Unmarshal(raw.Hostnames, &arr); err == nil {
			for _, h := range arr {
				f.Hostnames[strings.ToLower(h)] = struct{}{}
			}
		} else {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw.Hostnames, &obj); err != nil {
				return fmt.Errorf("hostnames: expected array of strings, got %s", string(raw.Hostnames))
			}
			for h := range obj {
				f.Hostnames[strings.ToLower(h)] = struct{}{}
			}
		}
	}

	if len(raw.Ports) > 0 {
		var arr []interface{}
		if err := json.Unmarshal(raw.Ports, &arr); err == nil {
			for _, p := range arr {
				switch v := p.(type) {
				case float64:
					f.Ports[uint16(v)] = struct{}{}
				case []interface{}:
					if len(v) != 2 {
						return fmt.Errorf("ports range must have exactly 2 elements")
					}
					start, ok1 := v[0].(float64)
					end, ok2 := v[1].(float64)
					if !ok1 || !ok2 {
						return fmt.Errorf("ports range elements must be numbers")
					}
					if end < start {
						start, end = end, start
					}
					for i := int(start); i <= int(end); i++ {
						f.Ports[uint16(i)] = struct{}{}
					}
				default:
					return fmt.Errorf("port entry must be number or [start, end]")
				}
			}
		} else {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw.Ports, &obj); err != nil {
				return fmt.Errorf("ports: expected array, got %s", string(raw.Ports))
			}
			for k := range obj {
				n, perr := strconv.ParseUint(k, 10, 16)
				if perr != nil {
					return fmt.Errorf("ports: object key %q is not a valid port number", k)
				}
				f.Ports[uint16(n)] = struct{}{}
			}
		}
	}

	return nil
}

type Config struct {
	Port int `json:"port"`

	AllowTCP bool `json:"allowTCP"`
	AllowUDP bool `json:"allowUDP"`

	AllowDirectIP    bool `json:"allowDirectIP"`
	AllowPrivateIPs  bool `json:"allowPrivateIPs"`
	AllowLoopbackIPs bool `json:"allowLoopbackIPs"`

	TcpBufferSize int  `json:"tcpBufferSize"`
	TcpNoDelay    bool `json:"tcpNoDelay"`

	Blacklist FilterSet `json:"blacklist"`
	Whitelist FilterSet `json:"whitelist"`

	WebsocketPermessageDeflate bool `json:"websocketPermessageDeflate"`

	DnsServers     []string `json:"dnsServers"`
	DnsMethod      string   `json:"dnsMethod"`
	DnsResultOrder string   `json:"dnsResultOrder"`

	EnableTwisp bool `json:"enableTwisp"`

	EnableV2             bool              `json:"enableV2"`
	Motd                 string            `json:"motd"`
	PasswordAuth         bool              `json:"passwordAuth"`
	PasswordAuthRequired bool              `json:"passwordAuthRequired"`
	PasswordUsers        map[string]string `json:"passwordUsers"`

	ParseRealIP    bool     `json:"parseRealIP"`
	TrustedProxies []string `json:"trustedProxies"`
	TrustedHeaders []string `json:"trustedHeaders"`
	NonWSResponse  string   `json:"nonWSResponse"`

	trustedProxyNets []*net.IPNet

	LogLevel string `json:"logLevel"`

	Proxy                   string `json:"proxy"`
	MaxMessageSize          int    `json:"maxMessageSize"`
	StaticDir               string `json:"staticDir"`
	BandwidthLimitKbps      int    `json:"bandwidthLimitKbps"`
	ConnectionsLimitPerIP   int    `json:"connectionsLimitPerIP"`
	ConnectionWindowSeconds int    `json:"connectionWindowSeconds"`

	BufferRemainingLength uint32 `json:"bufferRemainingLength"`

	FloodProtection *FloodProtectionConfig `json:"floodProtection"`
	Reputation      *ReputationConfig      `json:"reputation"`

	Logger      Logger
	DNSCache    *DNSCache
	ReadBufPool *sync.Pool
	Dialer      net.Dialer
	Globals     *Globals
}

type FloodProtectionConfig struct {
	Enabled                           bool `json:"enabled"`
	MaxConnectsPerSourceIPPerSecond   int  `json:"maxConnectsPerSourceIPPerSecond"`
	MaxConnectsPerDestPerSecond       int  `json:"maxConnectsPerDestPerSecond"`
	MaxConnectsPerDestPerMinute       int  `json:"maxConnectsPerDestPerMinute"`
	MaxInFlightSyns                   int  `json:"maxInFlightSyns"`
	MaxConcurrentStreamsPerConnection int  `json:"maxConcurrentStreamsPerConnection"`
	MaxConcurrentConnections          int  `json:"maxConcurrentConnections"`
	SynFloodSignature                 struct {
		Enabled              bool    `json:"enabled"`
		WindowMs             int     `json:"windowMs"`
		MinSamples           int     `json:"minSamples"`
		FailedHandshakeRatio float64 `json:"failedHandshakeRatio"`
	} `json:"synFloodSignature"`
	WsCloseAfterViolations int  `json:"wsCloseAfterViolations"`
	LogBlockedDials        bool `json:"logBlockedDials"`
}

type ReputationConfig struct {
	Enabled      bool   `json:"enabled"`
	StorePath    string `json:"storePath"`
	DecayPerHour int    `json:"scoreDecayPerHour"`
	EvictAfter   time.Duration
	EvictDays    int            `json:"evictAfterDays"`
	Weights      map[string]int `json:"weights"`
	DestWeights  map[string]int `json:"destinationWeights"`
	Thresholds   struct {
		Warn     int `json:"warn"`
		Throttle int `json:"throttle"`
		Strict   int `json:"strict"`
	} `json:"thresholds"`
	SaveIntervalSeconds int `json:"saveIntervalSeconds"`
}

type Globals struct {
	PerSource    *SlidingWindow
	PerDestSec   *SlidingWindow
	PerDestMin   *SlidingWindow
	InFlightSyns *Semaphore
	Connections  *Semaphore
	Egress       *EgressPolicy
	Reputation   *Reputation
	Signature    *Signatures
}

type SignatureConfig struct {
	Enabled              bool
	Window               time.Duration
	MinSamples           int
	FailedHandshakeRatio float64
}

type DNSCacheConfig struct {
	Servers     []string
	TTLSeconds  int
	Method      string
	ResultOrder string
}

func DefaultConfig() Config {
	return Config{
		Port: 6001,

		Blacklist: FilterSet{Hostnames: map[string]struct{}{}, Ports: map[uint16]struct{}{}},
		Whitelist: FilterSet{Hostnames: map[string]struct{}{}, Ports: map[uint16]struct{}{}},

		AllowTCP: true,
		AllowUDP: true,

		AllowDirectIP:    false,
		AllowPrivateIPs:  false,
		AllowLoopbackIPs: false,

		TcpBufferSize: 32768,
		TcpNoDelay:    true,

		DnsServers:     []string{},
		DnsMethod:      "resolve",
		DnsResultOrder: "ipv4first",

		EnableTwisp: false,

		EnableV2:             true,
		Motd:                 "",
		PasswordAuth:         false,
		PasswordAuthRequired: false,
		PasswordUsers:        map[string]string{},

		ParseRealIP:    true,
		TrustedProxies: []string{},
		TrustedHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For"},
		NonWSResponse:  "",

		LogLevel: "info",

		Proxy:                   "",
		MaxMessageSize:          0,
		StaticDir:               "",
		BandwidthLimitKbps:      0,
		ConnectionsLimitPerIP:   0,
		ConnectionWindowSeconds: 0,
		BufferRemainingLength:   32768,
	}
}

func CreateWispConfig(cfg *Config) *Config {
	wispCfg := &Config{
		Port: cfg.Port,

		AllowTCP: cfg.AllowTCP,
		AllowUDP: cfg.AllowUDP,

		AllowDirectIP:    cfg.AllowDirectIP,
		AllowPrivateIPs:  cfg.AllowPrivateIPs,
		AllowLoopbackIPs: cfg.AllowLoopbackIPs,

		TcpBufferSize: cfg.TcpBufferSize,
		TcpNoDelay:    cfg.TcpNoDelay,

		Blacklist: cfg.Blacklist,
		Whitelist: cfg.Whitelist,

		WebsocketPermessageDeflate: cfg.WebsocketPermessageDeflate,

		DnsServers:     cfg.DnsServers,
		DnsMethod:      cfg.DnsMethod,
		DnsResultOrder: cfg.DnsResultOrder,

		EnableTwisp: cfg.EnableTwisp,

		EnableV2:             cfg.EnableV2,
		Motd:                 cfg.Motd,
		PasswordAuth:         cfg.PasswordAuth,
		PasswordAuthRequired: cfg.PasswordAuthRequired,
		PasswordUsers:        cfg.PasswordUsers,

		ParseRealIP:    cfg.ParseRealIP,
		TrustedProxies: cfg.TrustedProxies,
		TrustedHeaders: cfg.TrustedHeaders,
		NonWSResponse:  cfg.NonWSResponse,

		FloodProtection: cfg.FloodProtection,
		Reputation:      cfg.Reputation,

		LogLevel: cfg.LogLevel,

		Proxy:                   cfg.Proxy,
		MaxMessageSize:          cfg.MaxMessageSize,
		StaticDir:               cfg.StaticDir,
		BandwidthLimitKbps:      cfg.BandwidthLimitKbps,
		ConnectionsLimitPerIP:   cfg.ConnectionsLimitPerIP,
		ConnectionWindowSeconds: cfg.ConnectionWindowSeconds,

		BufferRemainingLength: cfg.BufferRemainingLength,
	}

	return wispCfg
}

func LoadConfig(config string) (Config, error) {
	cfg := DefaultConfig()

	trimConfig := strings.TrimSpace(config)
	if strings.HasPrefix(trimConfig, "{") {
		if err := json.Unmarshal([]byte(trimConfig), &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}

	file, err := os.Open(config)
	if err != nil {
		return cfg, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
