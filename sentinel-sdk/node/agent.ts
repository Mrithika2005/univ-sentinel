/* ============================================================
   SENTINEL SDK — Node Agent  (final, complete)
   Auto-instruments:
     • HTTP/HTTPS server (inbound) + client (outbound)
     • console (all levels)
     • fs (file I/O with byte counts)
     • process (signals, crashes, vitals: CPU + memory + disk + network)
     • TLS certificate expiry monitoring
     • Auth event detection from HTTP status + path
     • CORS violation detection
     • Bot/scraper signal from User-Agent
     • Rate-limit event detection
     • pg / mongoose / neo4j / ioredis
       – query time, slow query, deadlock, transaction, replication lag,
         connection pool, migration, cache hit/miss/eviction
   Sends logs → ClickHouse directly
   ============================================================ */

import {
  LogLayer, LogLevel, LogRecord, inferLayer,
  type InstrumentedClassMeta, type LogContext,
} from '../core/types.ts';

import http   from 'http';
import https  from 'https';
import fs     from 'fs';
import os     from 'os';
import tls    from 'tls';

/* ── Config ──────────────────────────────────────────────── */

export interface SentinelNodeConfig {
  serviceName?:        string;
  clickhouseHost?:     string;
  clickhouseDatabase?: string;
  clickhouseTable?:    string;
  clickhouseUser?:     string;
  clickhousePassword?: string;
  batchSize?:          number;
  flushInterval?:      number;   // ms
  slowQueryMs?:        number;
  slowHttpMs?:         number;
  debug?:              boolean;
  autoInstrument?:     boolean;
  samplingRate?:       number;   // 0.0–1.0, default 1.0
  certCheckHosts?:     string[]; // hostnames to check TLS cert expiry
  certCheckIntervalMs?: number;  // default 6h
}

/* ── ClickHouse writer ───────────────────────────────────── */

class ClickHouseWriter {
  private host:       string;
  private database:   string;
  private table:      string;
  private authHeader?: string;
  private queue:      LogRecord[] = [];
  private batchSize:  number;
  private debug:      boolean;
  private ready       = false;

  constructor(cfg: Required<SentinelNodeConfig>) {
    this.host      = cfg.clickhouseHost;
    this.database  = cfg.clickhouseDatabase;
    this.table     = cfg.clickhouseTable;
    this.batchSize = cfg.batchSize;
    this.debug     = cfg.debug;
    if (cfg.clickhouseUser) {
      this.authHeader = `Basic ${Buffer.from(`${cfg.clickhouseUser}:${cfg.clickhousePassword || ''}`).toString('base64')}`;
    }
  }

  async init(): Promise<void> {
    await this._exec(`CREATE DATABASE IF NOT EXISTS ${this.database}`);
    await this._exec(`
      CREATE TABLE IF NOT EXISTS ${this.database}.${this.table}
      (
        timestamp  String,
        record_id  String,
        trace_id   String,
        span_id    String,
        service    String,
        env        String,
        layer      String,
        level      String,
        message    String,
        context    String
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(parseDateTimeBestEffort(timestamp))
      ORDER BY (timestamp, service, layer)
      TTL parseDateTimeBestEffort(timestamp) + INTERVAL 90 DAY
    `);
    this.ready = true;
    this._startFlush();
  }

  enqueue(record: LogRecord): void {
    this.queue.push(record);
    if (this.queue.length >= this.batchSize) void this._flush();
  }

  private _startFlush(): void {
    setInterval(() => void this._flush(), 2000).unref();
    process.on('exit',    () => void this._flush());
    process.on('SIGINT',  () => { void this._flush(); process.exit(0); });
    process.on('SIGTERM', () => { void this._flush(); process.exit(0); });
  }

  private async _flush(): Promise<void> {
    if (!this.ready || this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    const rows  = batch.map((r) => JSON.stringify({
      timestamp: r.timestamp,
      record_id: r.record_id,
      trace_id:  r.trace_id,
      span_id:   r.span_id,
      service:   r.service,
      env:       r.env,
      layer:     r.layer,
      level:     r.level,
      message:   r.message,
      context:   JSON.stringify(r.context || {}),
    })).join('\n');

    const query = `INSERT INTO ${this.database}.${this.table} FORMAT JSONEachRow`;
    try {
      const res = await fetch(`${this.host}/?query=${encodeURIComponent(query)}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-ndjson', ...(this.authHeader ? { Authorization: this.authHeader } : {}) },
        body:    rows,
      });
      if (!res.ok && this.debug) {
        console.error('[SENTINEL] ClickHouse ingest error:', res.status, (await res.text()).slice(0, 200));
      }
    } catch (err) {
      if (this.debug) console.error('[SENTINEL] flush error:', err);
      this.queue.unshift(...batch);
    }
  }

  private async _exec(query: string): Promise<void> {
    const res = await fetch(`${this.host}/?query=${encodeURIComponent(query)}`, {
      method:  'POST',
      headers: this.authHeader ? { Authorization: this.authHeader } : {},
    });
    if (!res.ok) throw new Error(`ClickHouse DDL failed: ${(await res.text()).slice(0, 300)}`);
  }
}

/* ── Main class ──────────────────────────────────────────── */

export class SentinelNode {
  private cfg:         Required<SentinelNodeConfig>;
  private writer:      ClickHouseWriter;
  private instrumented = new WeakSet<object>();
  private traceId      = this._genId();
  private processStart = Date.now();
  // Network throughput counters
  private netBytesIn   = 0;
  private netBytesOut  = 0;

  constructor(config: SentinelNodeConfig = {}) {
    this.cfg = {
      serviceName:          config.serviceName          || 'node-service',
      clickhouseHost:       config.clickhouseHost       || process.env.CLICKHOUSE_HOST     || 'http://localhost:8123',
      clickhouseDatabase:   config.clickhouseDatabase   || process.env.CLICKHOUSE_DATABASE || 'sentinel',
      clickhouseTable:      config.clickhouseTable      || process.env.CLICKHOUSE_TABLE    || 'logs',
      clickhouseUser:       config.clickhouseUser       || process.env.CLICKHOUSE_USER     || '',
      clickhousePassword:   config.clickhousePassword   || process.env.CLICKHOUSE_PASSWORD || '',
      batchSize:            config.batchSize            ?? 50,
      flushInterval:        config.flushInterval        ?? 2000,
      slowQueryMs:          config.slowQueryMs          ?? 200,
      slowHttpMs:           config.slowHttpMs           ?? 1000,
      debug:                config.debug                ?? false,
      autoInstrument:       config.autoInstrument       ?? true,
      samplingRate:         config.samplingRate         ?? 1.0,
      certCheckHosts:       config.certCheckHosts       ?? [],
      certCheckIntervalMs:  config.certCheckIntervalMs  ?? 6 * 60 * 60 * 1000,
    };
    this.writer = new ClickHouseWriter(this.cfg);
  }

  /* ── Public API ─────────────────────────────────────────── */

  async hook(): Promise<this> {
    await this.writer.init();
    this._patchConsole();
    this._patchHttp();
    this._patchHttpClient();
    this._patchFS();
    this._hookProcess();
    if (this.cfg.autoInstrument) this._patchDatabaseDrivers();
    if (this.cfg.certCheckHosts.length > 0) this._startCertMonitor();

    this._emit({
      message: `Sentinel Node Agent hooked on "${this.cfg.serviceName}"`,
      layer:   LogLayer.INFRASTRUCTURE,
      level:   LogLevel.INFO,
      context: {
        nodeVersion:          process.version,
        pid:                  process.pid,
        processUptimeSeconds: 0,
        cpuCoreCount:         os.cpus().length,
      } as LogContext,
    });
    return this;
  }

  instrument<T extends object>(target: T | (new (...a: any[]) => T), layer?: LogLayer): this {
    const proto = typeof target === 'function' ? (target as any).prototype : Object.getPrototypeOf(target);
    if (!proto || this.instrumented.has(proto)) return this;
    this.instrumented.add(proto);

    const className     = (typeof target === 'function' ? (target as any).name : target.constructor?.name) || 'UnknownClass';
    const resolvedLayer = layer || inferLayer(className);
    const methodNames: string[] = [];

    let p: object | null = proto;
    while (p && p !== Object.prototype) {
      Object.getOwnPropertyNames(p).forEach((key) => {
        if (key === 'constructor') return;
        const desc = Object.getOwnPropertyDescriptor(p!, key);
        if (!desc || typeof desc.value !== 'function') return;
        methodNames.push(key);
        this._wrapMethod(proto, key, className, resolvedLayer);
      });
      p = Object.getPrototypeOf(p);
    }

    if (this.cfg.debug) {
      this._emit({
        message: `Auto-instrumented: ${className} (${methodNames.length} methods → ${resolvedLayer})`,
        layer:   LogLayer.OBSERVABILITY,
        level:   LogLevel.DEBUG,
        context: { className, layer: resolvedLayer, methodNames } as unknown as LogContext,
      });
    }
    return this;
  }

  log(partial: Partial<LogRecord> & { message: string }): void {
    this._emit(partial);
  }

  /* ── Emitter ────────────────────────────────────────────── */

  private _emit(partial: Partial<LogRecord> & { message: string }): void {
    if (this.cfg.samplingRate < 1.0 && Math.random() > this.cfg.samplingRate) return;
    const record = new LogRecord({
      ...partial,
      service:  this.cfg.serviceName,
      trace_id: partial.trace_id || this.traceId,
      context:  { ...(partial.context || {}), samplingRate: this.cfg.samplingRate },
    });
    this.writer.enqueue(record);
  }

  /* ── console patch ──────────────────────────────────────── */

  private _patchConsole(): void {
    const self   = this;
    const prefix = '[SENTINEL]';
    const colors: Record<string, string> = {
      DEBUG: '\x1b[36m', INFO: '\x1b[32m', WARN: '\x1b[33m', ERROR: '\x1b[31m', FATAL: '\x1b[35m',
    };
    const map: Array<[keyof Console, LogLevel]> = [
      ['log', LogLevel.INFO], ['info', LogLevel.INFO], ['warn', LogLevel.WARN],
      ['error', LogLevel.ERROR], ['debug', LogLevel.DEBUG],
    ];
    map.forEach(([method, level]) => {
      const orig = (console as any)[method].bind(console);
      (console as any)[method] = (...args: any[]) => {
        const msg = args.map((a) => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
        if (msg.includes(prefix)) { orig(...args); return; }
        self._emit({ message: msg, layer: LogLayer.BUSINESS_LOGIC, level });
        orig(`${prefix} ${colors[level]}[${level}]\x1b[0m ${msg}`);
      };
    });
  }

  /* ── HTTP server patch (inbound) ────────────────────────── */

  private _patchHttp(): void {
    const self = this;

    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    const wrapListener = (
      listener: ((req: http.IncomingMessage, res: http.ServerResponse) => void) | undefined
    ) => (req: http.IncomingMessage, res: http.ServerResponse) => {
      const start  = Date.now();
      const reqId  = self._genId();
      const bodyBytes = Number(req.headers['content-length'] || 0);
      self.netBytesIn += bodyBytes;

      self._emit({
        message: `→ ${req.method} ${req.url}`,
        layer:   LogLayer.API_GATEWAY,
        level:   LogLevel.INFO,
        context: {
          method:           req.method,
          path:             req.url,
          requestId:        reqId,
          clientIp:         req.socket.remoteAddress,
          userAgent:        req.headers['user-agent'],
          requestSizeBytes: bodyBytes,
          userId:           req.headers['x-user-id'] as string || undefined,
          sessionId:        req.headers['x-session-id'] as string || undefined,
          tlsVersion:       (req.socket as any).getProtocol?.() || undefined,
          tlsCipherSuite:   (req.socket as any).getCipher?.()?.name || undefined,
        } as LogContext,
      });

      // CORS origin tracking
      const origin = req.headers['origin'];
      if (origin) {
        self._emit({
          message: `CORS request from origin: ${origin}`,
          layer:   LogLayer.API_GATEWAY,
          level:   LogLevel.DEBUG,
          context: { corsOrigin: origin, path: req.url, method: req.method } as LogContext,
        });
      }

      res.on('finish', () => {
        const durationMs   = Date.now() - start;
        const isSlow       = durationMs > self.cfg.slowHttpMs;
        const rateLimitHit = res.statusCode === 429;
        const corsViolation = res.statusCode === 403 && !!origin;
        const resBytes     = Number(res.getHeader('content-length') || 0);
        self.netBytesOut  += resBytes;

        // Auth event detection
        const isAuthPath    = AUTH_PATHS.test(req.url || '');
        const isAuthFailure = res.statusCode === 401 || res.statusCode === 403;
        if (isAuthPath || isAuthFailure) {
          self._emit({
            message: `Auth event: ${req.method} ${req.url} → ${res.statusCode}`,
            layer:   LogLayer.SECURITY,
            level:   isAuthFailure ? LogLevel.WARN : LogLevel.INFO,
            context: {
              authResult:  res.statusCode < 400 ? 'success' : 'failure',
              ipAddress:   req.socket.remoteAddress,
              userAgent:   req.headers['user-agent'],
              path:        req.url,
              userId:      req.headers['x-user-id'] as string || undefined,
              failureReason: isAuthFailure ? `HTTP ${res.statusCode}` : undefined,
            } as LogContext,
          });
        }

        // Bot signal: simple UA heuristic
        const ua = (req.headers['user-agent'] || '').toLowerCase();
        const botSignal = /bot|crawl|spider|scraper|curl|wget|python-requests|go-http/.test(ua);

        self._emit({
          message: `← ${req.method} ${req.url} ${res.statusCode} (${durationMs}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:   LogLayer.API_GATEWAY,
          level:   res.statusCode >= 500 ? LogLevel.ERROR : res.statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO,
          context: {
            method:            req.method,
            path:              req.url,
            statusCode:        res.statusCode,
            durationMs,
            requestId:         reqId,
            userAgent:         req.headers['user-agent'],
            rateLimitHit,
            rateLimitRemaining: Number(res.getHeader('X-RateLimit-Remaining') ?? -1) >= 0
              ? Number(res.getHeader('X-RateLimit-Remaining'))
              : undefined,
            responseSizeBytes: resBytes || undefined,
            corsViolation,
            botSignal,
          } as LogContext,
        });
      });

      listener?.(req, res);
    };

    const origHttp = http.createServer.bind(http);
    (http as any).createServer = (...args: any[]) => {
      if (typeof args[0] === 'function') args[0] = wrapListener(args[0]);
      else if (typeof args[1] === 'function') args[1] = wrapListener(args[1]);
      return origHttp(...(args as Parameters<typeof http.createServer>));
    };

    const origHttps = https.createServer.bind(https);
    (https as any).createServer = (...args: any[]) => {
      const last = args[args.length - 1];
      if (typeof last === 'function') args[args.length - 1] = wrapListener(last);
      return origHttps(...(args as Parameters<typeof https.createServer>));
    };
  }

  /* ── Outbound HTTP client ────────────────────────────────── */

  private _patchHttpClient(): void {
    const self = this;
    const wrapRequest = (origRequest: typeof http.request, scheme: string) =>
      (...args: any[]): http.ClientRequest => {
        const req: http.ClientRequest = origRequest(...(args as Parameters<typeof http.request>));
        const urlStr = typeof args[0] === 'string' ? args[0]
                     : args[0] instanceof URL       ? args[0].toString()
                     : `${(args[0] as http.RequestOptions).host}${(args[0] as http.RequestOptions).path}`;
        const method = (args[0] as http.RequestOptions).method || 'GET';
        const start  = Date.now();

        self._emit({
          message: `Outbound ${scheme}: ${method} ${urlStr}`,
          layer:   LogLayer.SERVICE,
          level:   LogLevel.INFO,
          context: { method, path: urlStr } as LogContext,
        });

        req.on('response', (res) => {
          const durationMs = Date.now() - start;
          self._emit({
            message: `Outbound ${scheme} response: ${method} ${urlStr} ${res.statusCode} (${durationMs}ms)`,
            layer:   LogLayer.SERVICE,
            level:   (res.statusCode || 200) >= 400 ? LogLevel.WARN : LogLevel.INFO,
            context: {
              method,
              path:                 urlStr,
              statusCode:           res.statusCode,
              durationMs,
              downstreamService:    urlStr,
              downstreamStatusCode: res.statusCode,
              downstreamDurationMs: durationMs,
              thirdPartyLatencyMs:  durationMs,
              rateLimitHit:         res.statusCode === 429,
            } as LogContext,
          });
        });

        req.on('error', (err) => {
          const durationMs = Date.now() - start;
          self._emit({
            message: `Outbound ${scheme} error: ${method} ${urlStr} — ${err.message}`,
            layer:   LogLayer.SERVICE,
            level:   LogLevel.ERROR,
            context: { method, path: urlStr, durationMs, exceptionType: err.constructor.name, stackTrace: err.stack } as LogContext,
          });
        });

        return req;
      };

    http.request  = wrapRequest(http.request.bind(http),   'HTTP')  as typeof http.request;
    https.request = wrapRequest(https.request.bind(https), 'HTTPS') as typeof https.request;
  }

  /* ── File system patch ──────────────────────────────────── */

  private _patchFS(): void {
    const self = this;
    const ops: Array<keyof typeof fs> = ['readFile', 'writeFile', 'appendFile', 'unlink', 'readdir', 'stat', 'mkdir', 'rmdir'];

    ops.forEach((op) => {
      const orig = (fs as any)[op] as Function;
      if (typeof orig !== 'function') return;

      (fs as any)[op] = (...args: any[]) => {
        const filePath = args[0];
        const start    = Date.now();
        const isRead   = op === 'readFile';
        const isWrite  = op === 'writeFile' || op === 'appendFile';

        self._emit({
          message: `FS.${op}: ${filePath}`,
          layer:   LogLayer.DATA_ACCESS,
          level:   LogLevel.DEBUG,
          context: { fileOperation: op, filePath: String(filePath) } as LogContext,
        });

        const cbIdx = args.findIndex((a, i) => i > 0 && typeof a === 'function');
        if (cbIdx !== -1) {
          const origCb = args[cbIdx];
          args[cbIdx] = (err: NodeJS.ErrnoException | null, ...cbArgs: any[]) => {
            const durationMs = Date.now() - start;
            if (err) {
              self._emit({
                message: `FS.${op} failed: ${filePath} — ${err.message}`,
                layer:   LogLayer.DATA_ACCESS,
                level:   LogLevel.ERROR,
                context: { fileOperation: op, filePath: String(filePath), durationMs, exceptionType: err.code } as LogContext,
              });
            } else {
              const statResult   = op === 'stat' ? cbArgs[0] : undefined;
              const fileSizeBytes = statResult?.size;
              const dataArg      = isWrite ? (typeof args[1] === 'string' ? args[1] : '') : '';
              self._emit({
                message: `FS.${op} completed: ${filePath} (${durationMs}ms)`,
                layer:   LogLayer.DATA_ACCESS,
                level:   LogLevel.DEBUG,
                context: {
                  fileOperation:  op,
                  filePath:       String(filePath),
                  durationMs,
                  fileSizeBytes,
                  fileReadBytes:  isRead  ? (cbArgs[0] ? Buffer.byteLength(cbArgs[0]) : undefined) : undefined,
                  fileWriteBytes: isWrite ? Buffer.byteLength(dataArg)                              : undefined,
                } as LogContext,
              });
            }
            origCb(err, ...cbArgs);
          };
        }
        return orig.apply(fs, args);
      };
    });
  }

  /* ── Process hooks + vitals ─────────────────────────────── */

  private _hookProcess(): void {
    const self = this;

    process.on('uncaughtException', (err) => {
      self._emit({
        message: `Uncaught Exception: ${err.message}`,
        layer:   LogLayer.SECURITY,
        level:   LogLevel.FATAL,
        context: {
          exceptionType:        err.constructor.name,
          stackTrace:           err.stack,
          processUptimeSeconds: (Date.now() - self.processStart) / 1000,
        } as LogContext,
      });
    });

    process.on('unhandledRejection', (reason) => {
      self._emit({
        message: `Unhandled Rejection: ${reason}`,
        layer:   LogLayer.OBSERVABILITY,
        level:   LogLevel.ERROR,
        context: { exceptionType: String(reason) } as LogContext,
      });
    });

    (['SIGTERM', 'SIGINT'] as NodeJS.Signals[]).forEach((sig) => {
      process.on(sig, () => {
        self._emit({
          message: `Process signal: ${sig}`,
          layer:   LogLayer.INFRASTRUCTURE,
          level:   LogLevel.WARN,
          context: {
            containerEvent:       'stop',
            containerName:        self.cfg.serviceName,
            processUptimeSeconds: (Date.now() - self.processStart) / 1000,
          } as LogContext,
        });
      });
    });

    // ── CPU + memory + disk + network vitals every 30s ────────
    let prevCpuTimes = os.cpus().map((c) => ({ ...c.times }));

    setInterval(() => {
      const mem     = process.memoryUsage();
      const freeMem = os.freemem();
      const totMem  = os.totalmem();

      // CPU delta calculation
      const cpus       = os.cpus();
      const cpuPercents = cpus.map((cpu, i) => {
        const prev  = prevCpuTimes[i] || cpu.times;
        const delta = (k: keyof typeof cpu.times) => cpu.times[k] - (prev as any)[k];
        const total = (['user','nice','sys','idle','irq'] as const).reduce((s, k) => s + delta(k), 0);
        const idle  = delta('idle');
        return total > 0 ? ((total - idle) / total) * 100 : 0;
      });
      prevCpuTimes = cpus.map((c) => ({ ...c.times }));
      const cpuPercent = cpuPercents.reduce((a, b) => a + b, 0) / cpuPercents.length;

      self._emit({
        message: `Process vitals: cpu=${cpuPercent.toFixed(1)}% heap=${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB rss=${(mem.rss / 1024 / 1024).toFixed(1)}MB`,
        layer:   LogLayer.INFRASTRUCTURE,
        level:   cpuPercent > 85 ? LogLevel.WARN : LogLevel.INFO,
        context: {
          cpuPercent:            parseFloat(cpuPercent.toFixed(2)),
          cpuCoreCount:          cpus.length,
          memoryUsedBytes:       mem.heapUsed,
          memoryTotalBytes:      mem.heapTotal,
          memoryAvailableBytes:  freeMem,
          swapUsedBytes:         totMem - freeMem - mem.heapUsed,
          networkInBytes:        self.netBytesIn,
          networkOutBytes:       self.netBytesOut,
          containerName:         self.cfg.serviceName,
          processUptimeSeconds:  (Date.now() - self.processStart) / 1000,
        } as LogContext,
      });
    }, 30_000).unref();

    // ── Disk usage every 60s (Node 16+ has statfs) ────────────
    setInterval(async () => {
      try {
        const { statfs } = await import('fs/promises' as any);
        if (!statfs) return;
        const s: any = await (statfs as any)('/');
        const total   = s.bsize * s.blocks;
        const free    = s.bsize * s.bavail;
        const used    = total - free;
        const pct     = Math.round((used / total) * 100);

        self._emit({
          message: `Disk vitals: ${pct}% used (${(used / 1024 / 1024 / 1024).toFixed(2)}GB / ${(total / 1024 / 1024 / 1024).toFixed(2)}GB)`,
          layer:   LogLayer.INFRASTRUCTURE,
          level:   pct > 85 ? LogLevel.WARN : LogLevel.INFO,
          context: {
            diskUsedBytes:    used,
            diskTotalBytes:   total,
            diskUsedPercent:  pct,
            containerName:    self.cfg.serviceName,
          } as LogContext,
        });
      } catch { /* statfs not available — skip */ }
    }, 60_000).unref();
  }

  /* ── TLS certificate expiry monitor ─────────────────────── */

  private _startCertMonitor(): void {
    const self    = this;
    const check   = () => {
      self.cfg.certCheckHosts.forEach((hostname) => {
        const socket = tls.connect(443, hostname, { servername: hostname }, () => {
          try {
            const cert     = socket.getPeerCertificate();
            const expiry   = new Date(cert.valid_to);
            const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
            const issuer   = cert.issuer?.O || cert.issuer?.CN || 'unknown';

            self._emit({
              message: `TLS cert: ${hostname} expires in ${daysLeft} days`,
              layer:   LogLayer.INFRASTRUCTURE,
              level:   daysLeft < 7 ? LogLevel.FATAL : daysLeft < 14 ? LogLevel.ERROR : daysLeft < 30 ? LogLevel.WARN : LogLevel.INFO,
              context: {
                certDomain:     hostname,
                certExpiryDays: daysLeft,
                certIssuer:     issuer,
              } as LogContext,
            });
          } catch { /* cert parse failed */ }
          socket.destroy();
        });
        socket.on('error', () => {
          self._emit({
            message: `TLS cert check failed: ${hostname}`,
            layer:   LogLayer.INFRASTRUCTURE,
            level:   LogLevel.ERROR,
            context: { certDomain: hostname } as LogContext,
          });
        });
      });
    };

    check();
    setInterval(check, this.cfg.certCheckIntervalMs).unref();
  }

  /* ── DB driver patches ───────────────────────────────────── */

  private _patchDatabaseDrivers(): void {
    this._tryPatchPg();
    this._tryPatchNeo4j();
    this._tryPatchMongoose();
    this._tryPatchRedis();
  }

  private _tryPatchPg(): void {
    try {
      const pg   = require('pg');
      const self = this;

      // Connection pool stats
      if (pg.Pool) {
        const origPoolConnect = pg.Pool.prototype.connect?.bind(pg.Pool.prototype);
        if (origPoolConnect) {
          pg.Pool.prototype.connect = async function (...args: any[]) {
            const waitStart = Date.now();
            const client    = await origPoolConnect.apply(this, args);
            const waitMs    = Date.now() - waitStart;
            if (waitMs > 50) {
              self._emit({
                message: `PG pool: connection acquired (waited ${waitMs}ms)`,
                layer:   LogLayer.DATA_ACCESS,
                level:   LogLevel.DEBUG,
                context: {
                  database:           'postgres',
                  connectionPoolSize: this.totalCount,
                  connectionPoolUsed: this.totalCount - this.idleCount,
                  connectionPoolIdle: this.idleCount,
                  connectionWaitMs:   waitMs,
                } as LogContext,
              });
            }
            return client;
          };
        }
      }

      // Query patch
      const origQuery = pg.Client.prototype.query.bind(pg.Client.prototype);
      pg.Client.prototype.query = async function (...args: any[]) {
        const sql   = typeof args[0] === 'string' ? args[0] : args[0]?.text || '';
        const start = Date.now();
        const sqlUp = sql.trim().toUpperCase();

        const isCommit    = sqlUp.startsWith('COMMIT');
        const isRollback  = sqlUp.startsWith('ROLLBACK');
        const isMigration = /^(CREATE|DROP|ALTER)\s+TABLE/.test(sqlUp);

        try {
          const result     = await origQuery.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;

          self._emit({
            message: `PG Query${isSlow ? ' [SLOW]' : ''}: ${sql.slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: {
              queryType:            sqlUp.split(' ')[0] as any,
              database:             'postgres',
              durationMs,
              rowsAffected:         result?.rowCount,
              slowQuery:            isSlow,
              slowQueryThresholdMs: self.cfg.slowQueryMs,
              queryHash:            `${sql.length}:${sql.slice(0, 20)}`,
              transactionAction:    isCommit ? 'commit' : isRollback ? 'rollback' : undefined,
              migrationName:        isMigration ? sql.slice(0, 80) : undefined,
              migrationStatus:      isMigration ? 'completed' : undefined,
            } as LogContext,
          });
          return result;
        } catch (err: any) {
          const durationMs = Date.now() - start;
          self._emit({
            message: `PG Query failed: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   LogLevel.ERROR,
            context: {
              database:      'postgres',
              durationMs,
              deadlock:      err.code === '40P01',
              lockTimeout:   err.code === '55P03',
              exceptionType: err.code,
              stackTrace:    err.stack,
            } as LogContext,
          });
          throw err;
        }
      };

      // Replication lag polling (replica-only, silently skips if not replica)
      const checkLag = async (client: any) => {
        try {
          const r   = await client.query(`SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) AS lag`);
          const lag = parseFloat(r.rows[0]?.lag ?? 0) * 1000;
          if (lag > 0) {
            self._emit({
              message: `PG replication lag: ${lag.toFixed(0)}ms`,
              layer:   LogLayer.DATA_ACCESS,
              level:   lag > 5000 ? LogLevel.WARN : LogLevel.INFO,
              context: { database: 'postgres', replicationLagMs: lag } as LogContext,
            });
          }
        } catch { /* not a replica */ }
      };
      if (pg.Pool) {
        const pool = new pg.Pool();
        pool.on('connect', (client: any) => {
          setInterval(() => checkLag(client), 30_000).unref();
        });
        // Don't keep this pool open; it's only for monitoring
        pool.end().catch(() => {});
      }

      this._emit({ message: 'pg driver patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch { /* pg not installed */ }
  }

  private _tryPatchNeo4j(): void {
    try {
      const neo4j = require('neo4j-driver');
      const self  = this;
      const orig  = neo4j.Session.prototype.run?.bind(neo4j.Session.prototype);
      if (!orig) return;

      neo4j.Session.prototype.run = async function (...args: any[]) {
        const cypher = typeof args[0] === 'string' ? args[0] : '';
        const start  = Date.now();
        try {
          const result     = await orig.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `Neo4j${isSlow ? ' [SLOW]' : ''}: ${cypher.slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: { database: 'neo4j', durationMs, slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs } as LogContext,
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `Neo4j failed: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   LogLevel.ERROR,
            context: { database: 'neo4j', durationMs: Date.now() - start, exceptionType: err.code, stackTrace: err.stack } as LogContext,
          });
          throw err;
        }
      };
      this._emit({ message: 'neo4j-driver patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch { /* not installed */ }
  }

  private _tryPatchMongoose(): void {
    try {
      const mongoose = require('mongoose');
      const self     = this;
      mongoose.plugin((schema: any) => {
        ['save','find','findOne','findOneAndUpdate','deleteOne','deleteMany','updateOne','updateMany'].forEach((hook) => {
          schema.pre(hook,  function (this: any, next: Function) { (this as any)._sentinelStart = Date.now(); next(); });
          schema.post(hook, function (this: any, result: any) {
            const durationMs = Date.now() - ((this as any)._sentinelStart || Date.now());
            const isSlow     = durationMs > self.cfg.slowQueryMs;
            self._emit({
              message: `Mongoose ${hook}${isSlow ? ' [SLOW]' : ''}`,
              layer:   LogLayer.DATA_ACCESS,
              level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
              context: {
                database: 'mongodb', queryType: hook.toUpperCase() as any,
                durationMs, rowCount: Array.isArray(result) ? result.length : 1,
                slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs,
              } as LogContext,
            });
          });
        });
      });
      this._emit({ message: 'mongoose patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch { /* not installed */ }
  }

  private _tryPatchRedis(): void {
    try {
      const Redis = require('ioredis');
      const self  = this;
      const orig  = Redis.prototype.sendCommand.bind(Redis.prototype);

      Redis.prototype.sendCommand = async function (...args: any[]) {
        const cmd   = args[0]?.name || 'CMD';
        const start = Date.now();
        try {
          const result     = await orig.apply(this, args);
          const durationMs = Date.now() - start;
          self._emit({
            message: `Redis ${cmd} (${durationMs}ms)`,
            layer:   LogLayer.DATA_ACCESS,
            level:   LogLevel.DEBUG,
            context: {
              database:      'redis',
              queryType:     cmd as any,
              durationMs,
              cacheHit:      result !== null,
              cacheMiss:     result === null,
              cacheEviction: ['DEL','UNLINK','EXPIRE','EXPIREAT'].includes(cmd),
            } as LogContext,
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `Redis ${cmd} error: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   LogLevel.ERROR,
            context: { database: 'redis', exceptionType: err.constructor.name } as LogContext,
          });
          throw err;
        }
      };
      this._emit({ message: 'ioredis patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch { /* not installed */ }
  }

  /* ── Class method wrapping ──────────────────────────────── */

  private _wrapMethod(proto: object, key: string, className: string, layer: LogLayer): void {
    const self = this;
    const orig = (proto as any)[key] as (...args: any[]) => any;

    (proto as any)[key] = function (...args: any[]) {
      const start   = Date.now();
      let isAsync   = false;
      try {
        const result = orig.apply(this, args);
        if (result && typeof (result as any).then === 'function') {
          isAsync = true;
          return (result as Promise<any>)
            .then((val) => {
              const durationMs = Date.now() - start;
              self._emit({ message: `${className}.${key} → ok (${durationMs}ms)`, layer, level: LogLevel.INFO,
                context: { className, functionName: key, durationMs, isAsync: true } as LogContext });
              return val;
            })
            .catch((err: any) => {
              const durationMs = Date.now() - start;
              self._emit({ message: `${className}.${key} → error: ${err?.message}`, layer, level: LogLevel.ERROR,
                context: { className, functionName: key, durationMs, isAsync: true, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext });
              throw err;
            });
        }
        const durationMs = Date.now() - start;
        self._emit({ message: `${className}.${key} → ok (${durationMs}ms)`, layer, level: LogLevel.INFO,
          context: { className, functionName: key, durationMs, isAsync: false } as LogContext });
        return result;
      } catch (err: any) {
        if (!isAsync) {
          const durationMs = Date.now() - start;
          self._emit({ message: `${className}.${key} → threw: ${err?.message}`, layer, level: LogLevel.ERROR,
            context: { className, functionName: key, durationMs, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext });
        }
        throw err;
      }
    };
  }

  /* ── Helpers ─────────────────────────────────────────────── */

  private _genId(): string {
    return (crypto as any).randomUUID?.() ||
      Math.random().toString(36).slice(2, 15) + Math.random().toString(36).slice(2, 15);
  }
}

/* ── Factory ─────────────────────────────────────────────── */

export const initSentinel = async (config?: SentinelNodeConfig): Promise<SentinelNode> => {
  const s = new SentinelNode(config);
  await s.hook();
  return s;
};

