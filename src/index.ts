import { spawn, type ChildProcess } from "child_process";
import { binPath, configPath } from "./path.js";
import * as fs from "node:fs";
import { detect } from "detect-port";
import logger from "./logger.js";
import { request, type IncomingMessage } from "node:http";
import type { Socket } from "node:net";

type PortEntry = number | [number, number];

type FilterList = {
	hostnames: string[];
	ports: PortEntry[];
};

type FloodProtectionConfig = {
	enabled: boolean;
	maxConnectsPerSourceIPPerSecond?: number;
	maxConnectsPerDestPerSecond?: number;
	maxConnectsPerDestPerMinute?: number;
	maxInFlightSyns?: number;
	maxConcurrentStreamsPerConnection?: number;
	maxConcurrentConnections?: number;
	synFloodSignature?: {
		enabled: boolean;
		windowMs: number;
		minSamples: number;
		failedHandshakeRatio: number;
	};
	wsCloseAfterViolations?: number;
	logBlockedDials?: boolean;
};

type ReputationConfig = {
	enabled: boolean;
	storePath?: string;
	saveIntervalSeconds?: number;
	scoreDecayPerHour?: number;
	evictAfterDays?: number;
	thresholds?: { warn: number; throttle: number; strict: number };
	weights?: Record<string, number>;
	destinationWeights?: Record<string, number>;
};

type MrrowispConfig = {
	/** TCP port the server listens on. */
	port: number | number[];
	/** Allow clients to open TCP streams. */
	allowTCP: boolean;
	/** Allow clients to open UDP streams. */
	allowUDP: boolean;
	/** Allow direct connections to IP addresses. */
	allowDirectIP: boolean;
	/** Allow connections to private/local IP ranges. */
	allowPrivateIPs: boolean;
	/** Allow connections to loopback IP addresses. */
	allowLoopbackIPs: boolean;
	/** Size of the TCP stream buffer in bytes. */
	tcpBufferSize: number;
	/** Bytes of unacked data tolerated before backpressure. */
	bufferRemainingLength: number;
	/** Enable TCP_NODELAY on TCP sockets. */
	tcpNoDelay: boolean;
	/** Hostname and port blacklist rules. */
	blacklist: FilterList;
	/** Hostname and port whitelist rules. */
	whitelist: FilterList;
	/** Enable WebSocket permessage-deflate extension. */
	websocketPermessageDeflate: boolean;
	/** DNS servers used for hostname resolution. */
	dnsServers: string[];
	/** DNS resolution method. */
	dnsMethod: "lookup" | "resolve";
	/** Preferred ordering for resolved IP addresses. */
	dnsResultOrder: "ipv4first" | "ipv6first" | "verbatim";
	/** Enable TWisp experimental protocol. */
	enableTwisp: boolean;
	/** Enable Wisp v2 protocol support. */
	enableV2: boolean;
	/** Message of the day sent during handshake. */
	motd: string;
	/** Enable password authentication. */
	passwordAuth: boolean;
	/** Require password authentication for all clients. */
	passwordAuthRequired: boolean;
	/** Username/password credential map. */
	passwordUsers: Record<string, string>;
	/** Parse reverse-proxy real IP headers. */
	parseRealIP: boolean;
	/** CIDRs/IPs whose forwarded headers are trusted. */
	trustedProxies: string[];
	/** Header names to honor from trusted proxies. */
	trustedHeaders: string[];
	/** HTTP response returned for non-WebSocket requests. */
	nonWSResponse: string;
	/** Logging verbosity level. */
	logLevel: "debug" | "info" | "warn" | "error" | "none";
	/** Optional upstream proxy URL (SOCKS/HTTP). */
	proxy: string;
	/** Maximum WebSocket message size in bytes. */
	maxMessageSize: number;
	/** Directory for static file serving. */
	staticDir: string;
	/** Bandwidth limit per IP in Kbps. */
	bandwidthLimitKbps: number;
	/** Connection rate limit per IP. */
	connectionsLimitPerIP: number;
	/** Connection rate limit window in seconds. */
	connectionWindowSeconds: number;
	/** Flood-protection options. */
	floodProtection: FloodProtectionConfig;
	/** IP reputation options. */
	reputation: ReputationConfig;
};

type Process = Array<{
	process: ChildProcess;
	index: number;
}>;

let cachedDefaultConfig: MrrowispConfig | undefined;

function loadDefaultConfig(): MrrowispConfig {
	if (cachedDefaultConfig) return cachedDefaultConfig;
	try {
		cachedDefaultConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
		return cachedDefaultConfig as MrrowispConfig;
	} catch (err) {
		throw new Error(
			`mrrowisp: failed to read bundled config at ${configPath}. `
		);
	}
}

export class Mrrowisp {
	config: MrrowispConfig;
	processes: Process | undefined;
	private reqIndex: number = 0;
	private processPorts: number[] = [];

	constructor(config?: Partial<MrrowispConfig>) {
		this.config = loadDefaultConfig();
		this.processes = undefined;
		if (config) {
			this.config = { ...this.config, ...config };
		}
		logger.level = this.config.logLevel;
	}

	async getAvailablePort(port: number): Promise<number> {
		if ((await detect(port)) !== port) {
			logger.error(`port ${port} is not available!! >w<`);
			return this.getAvailablePort(port + 1);
		}
		return port;
	}

	async start(count: number = 1) {
		this.processes = [];
		this.processPorts = [];

		for (let i = 0; i < count; i++) {
			if (Array.isArray(this.config.port) ? !this.config.port[i] : !this.config.port) {
				logger.error("mrrowisp: port is not configured!! >w<");
				return;
			}
			const nextPort = Array.isArray(this.config.port)
				? (this.config.port[i] ?? this.config.port[this.config.port.length - 1])
				: this.config.port;
			const port = await this.getAvailablePort(nextPort!);
			const { port: _port, ...config } = this.config;

			const proc = spawn(
				binPath,
				["--config", JSON.stringify(config), "--port", port.toString()],
				{ stdio: "pipe" },
			);

			this.processes.push({ process: proc, index: i });
			this.processPorts.push(port);

			const handleData = (data: Buffer) => {
				const msg = data.toString().trim();
				const levelMatch = msg.match(/^\[(DEBUG|INFO|WARN|ERROR)\]/);
				if (levelMatch) {
					switch (levelMatch[1]) {
						case "DEBUG": logger.debug(msg, i); break;
						case "INFO": logger.info(msg, i); break;
						case "WARN": logger.warn(msg, i); break;
						case "ERROR": logger.error(msg, i); break;
					}
				} else {
					logger.error(msg, i);
				}
			};

			proc.stdout?.on("data", handleData);
			proc.stderr?.on("data", handleData);

			proc.on("close", (code) => {
				logger.info(`child process ${i} exited with code ${code} D:`);
				if (this.processes) {
					const idx = this.processes.findIndex((p) => p.index === i);
					if (idx !== -1) {
						this.processes.splice(idx, 1);
						this.processPorts.splice(idx, 1);
					}
				}
				if (this.processes?.length === 0) {
					this.processes = undefined;
				}
			});
		}
	}

	private nextPort(): number | null {
		if (!this.processes) return null;
		const len = this.processPorts.length;
		if (len === 0) return null;
		const idx = this.reqIndex % len;
		const port = this.processPorts[idx] ?? null;
		this.reqIndex = (this.reqIndex + 1) % len;
		return port;
	}

	route(req: IncomingMessage, socket: Socket, head: Buffer) {
		const port = this.nextPort();
		if (port === null) {
			logger.error("mrrowisp is not running!! >w<");
			socket.destroy();
			return;
		}

		const proxyReq = request({
			hostname: "127.0.0.1",
			port,
			path: req.url,
			method: req.method,
			headers: req.headers,
		});

		proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
			socket.write(
				`HTTP/1.1 101 Switching Protocols\r\n` +
				Object.entries(proxyRes.headers)
					.map(([k, v]) => `${k}: ${v}`)
					.join("\r\n") +
				"\r\n\r\n",
			);

			if (proxyHead?.length) proxySocket.unshift(proxyHead);
			if (head?.length) socket.unshift(head);

			proxySocket.pipe(socket);
			socket.pipe(proxySocket);

			proxySocket.on("error", () => socket.destroy());
			socket.on("error", () => proxySocket.destroy());
		});

		proxyReq.on("error", (err) => {
			logger.error(`proxy request error: ${err.message}`);
			socket.destroy();
		});

		proxyReq.end();
	}

	stop() { this.signal("SIGTERM"); }
	kill() { this.signal("SIGKILL"); }

	private signal(sig: "SIGTERM" | "SIGKILL") {
		if (this.processes) {
			for (const { process } of this.processes) process.kill(sig);
			this.processes = undefined;
			this.processPorts = [];
		} else {
			logger.warn("mrrowisp is not running...");
		}
	}
}
