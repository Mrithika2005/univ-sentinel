"""
SENTINEL SDK — Python Agent  (v2, full parity with Node agent)
==============================================================
Auto-instruments:
  • print() / logging module
  • requests / httpx  (outbound HTTP — with rate-limit, auth, retry detection)
  • SQLAlchemy (query events — slow query, migration, transaction)
  • psycopg2   (raw postgres — slow, deadlock, lock-timeout, replication lag,
                connection-pool stats)
  • neo4j driver
  • redis-py   (cache hit/miss/eviction)
  • celery tasks
  • Flask / FastAPI / Django middleware
    (CORS, bot-signal, auth-event, rate-limit detection)
  • process signals & uncaught exceptions  (with uptime)
  • Infrastructure vitals every 30 s:
      CPU (per-core delta), memory (rss / heap / available / swap),
      disk usage, network bytes in/out
  • TLS certificate expiry monitoring for configurable host list
  • Code health: slow-function detection, async-function tagging
  • Configurable sampling rate (0.0 – 1.0)
  • SentinelMeta metaclass for zero-effort class instrumentation
  • sentinel.instrument() for existing instances
  • sentinel.track() decorator for standalone functions

Sends logs → ClickHouse HTTP interface (batch, with re-queue on failure)

Usage
-----
    from sentinel_sdk.python.agent import init_sentinel, SentinelMeta

    sentinel = init_sentinel("my-service", debug=True)

    class OrderService(metaclass=SentinelMeta):
        _sentinel_layer = "domain"
        def place_order(self, order): ...

    sentinel.instrument(my_existing_service)

    @sentinel.track(layer="business_logic")
    def process_payment(data): ...
"""

from __future__ import annotations

import base64
import builtins
import datetime
import functools
import inspect
import json
import logging
import os
import re as _re
import signal
import ssl
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

# ── Optional imports (graceful) ───────────────────────────────────────────────

try:
    import requests as _requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import httpx as _httpx  # type: ignore
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import sqlalchemy as _sa  # type: ignore
    from sqlalchemy import event as _sa_event  # type: ignore
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    import psycopg2 as _psycopg2  # type: ignore
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import neo4j as _neo4j  # type: ignore
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    import redis as _redis  # type: ignore
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    import psutil as _psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ── Layer & Level constants ───────────────────────────────────────────────────

class LogLayer:
    PRESENTATION   = 'presentation'
    API_GATEWAY    = 'api_gateway'
    BUSINESS_LOGIC = 'business_logic'
    DATA_ACCESS    = 'data_access'
    SERVICE        = 'service'
    SECURITY       = 'security'
    OBSERVABILITY  = 'observability'
    INFRASTRUCTURE = 'infrastructure'
    DOMAIN         = 'domain'


class LogLevel:
    DEBUG = 'DEBUG'
    INFO  = 'INFO'
    WARN  = 'WARN'
    ERROR = 'ERROR'
    FATAL = 'FATAL'


# ── Layer inference ───────────────────────────────────────────────────────────

_LAYER_PATTERNS: List[Tuple[_re.Pattern, str]] = [
    (_re.compile(r'auth|jwt|token|oauth|permission|acl|rbac|guard|firewall|waf|encrypt|decrypt|password|credential|session|csrf|cors', _re.I), LogLayer.SECURITY),
    (_re.compile(r'repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|entity|store|persist|storage', _re.I), LogLayer.DATA_ACCESS),
    (_re.compile(r'controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor|view', _re.I), LogLayer.API_GATEWAY),
    (_re.compile(r'service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk|consent', _re.I), LogLayer.DOMAIN),
    (_re.compile(r'infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk|celery', _re.I), LogLayer.INFRASTRUCTURE),
    (_re.compile(r'trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm', _re.I), LogLayer.OBSERVABILITY),
    (_re.compile(r'component|page|ui|render|form|modal|widget|screen|layout|theme|template', _re.I), LogLayer.PRESENTATION),
]

_AUTH_PATH_RE = _re.compile(r'/(login|logout|auth|token|oauth|signin|signup|refresh|verify)', _re.I)
_BOT_UA_RE    = _re.compile(r'bot|crawl|spider|scraper|curl|wget|python-requests|go-http|aiohttp', _re.I)
_MIGRATION_RE = _re.compile(r'^\s*(CREATE|DROP|ALTER)\s+TABLE', _re.I)


def infer_layer(name: str) -> str:
    for pattern, layer in _LAYER_PATTERNS:
        if pattern.search(name):
            return layer
    return LogLayer.BUSINESS_LOGIC


# ── LogRecord ─────────────────────────────────────────────────────────────────

class LogRecord:
    __slots__ = (
        'message', 'level', 'layer', 'timestamp',
        'record_id', 'trace_id', 'span_id',
        'service', 'env', 'context',
    )

    def __init__(
        self,
        message:  str,
        layer:    str = LogLayer.BUSINESS_LOGIC,
        level:    str = LogLevel.INFO,
        service:  str = 'unknown-python-service',
        context:  Optional[Dict[str, Any]] = None,
        trace_id: str = 'untracked',
        span_id:  str = 'untracked',
    ):
        self.message   = message
        self.layer     = layer
        self.level     = level
        self.service   = service
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.record_id = str(uuid.uuid4())
        self.trace_id  = trace_id
        self.span_id   = span_id
        self.env       = os.getenv('ENV', os.getenv('PYTHON_ENV', 'development'))
        self.context   = context or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'record_id': self.record_id,
            'trace_id':  self.trace_id,
            'span_id':   self.span_id,
            'service':   self.service,
            'env':       self.env,
            'layer':     self.layer,
            'level':     self.level,
            'message':   self.message,
            'context':   json.dumps(self.context or {}),
        }

    def __str__(self) -> str:
        _colors = {
            LogLevel.DEBUG: '\033[36m',
            LogLevel.INFO:  '\033[92m',
            LogLevel.WARN:  '\033[93m',
            LogLevel.ERROR: '\033[91m',
            LogLevel.FATAL: '\033[95m',
        }
        reset = '\033[0m'
        c = _colors.get(self.level, '\033[92m')
        return f'{c}[{self.timestamp}] [{self.layer.upper()}] [{self.level}] {self.message}{reset}'


# ── ClickHouse batch writer ───────────────────────────────────────────────────

class _ClickHouseWriter:
    def __init__(self, cfg: Dict[str, Any]):
        self._host     = cfg.get('clickhouse_host',     'http://localhost:8123')
        self._db       = cfg.get('clickhouse_database', 'sentinel')
        self._table    = cfg.get('clickhouse_table',    'logs')
        self._user     = cfg.get('clickhouse_user',     '')
        self._password = cfg.get('clickhouse_password', '')
        self._batch    = cfg.get('batch_size',          50)
        self._debug    = cfg.get('debug',               False)
        self._queue:   List[LogRecord] = []
        self._lock     = threading.Lock()
        self._timer:   Optional[threading.Timer] = None

    def init(self) -> None:
        self._exec(f'CREATE DATABASE IF NOT EXISTS {self._db}')
        self._exec(f"""
            CREATE TABLE IF NOT EXISTS {self._db}.{self._table}
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
        """)
        self._schedule_flush()

    def enqueue(self, record: LogRecord) -> None:
        with self._lock:
            self._queue.append(record)
            if len(self._queue) >= self._batch:
                self._flush_locked()

    def _schedule_flush(self) -> None:
        self._timer = threading.Timer(2.0, self._flush_and_reschedule)
        self._timer.daemon = True
        self._timer.start()

    def _flush_and_reschedule(self) -> None:
        self.flush()
        self._schedule_flush()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._queue:
            return
        batch = self._queue[:]
        self._queue.clear()
        rows  = '\n'.join(json.dumps(r.to_dict()) for r in batch)
        query = f'INSERT INTO {self._db}.{self._table} FORMAT JSONEachRow'
        try:
            url  = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
            data = rows.encode('utf-8')
            req  = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-ndjson')
            if self._user:
                cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
                req.add_header('Authorization', f'Basic {cred}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 201) and self._debug:
                    print(f'[SENTINEL] ClickHouse error: {resp.status}', file=sys.stderr)
        except Exception as exc:
            if self._debug:
                print(f'[SENTINEL] Flush error: {exc}', file=sys.stderr)
            self._queue = batch + self._queue  # re-queue — don't lose logs

    def _exec(self, query: str) -> None:
        url = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
        req = urllib.request.Request(url, method='POST')
        if self._user:
            cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
            req.add_header('Authorization', f'Basic {cred}')
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f'ClickHouse DDL failed: status={resp.status}')


# ── SentinelMeta — zero-effort class instrumentation ─────────────────────────

class SentinelMeta(type):
    """
    Metaclass — every non-dunder method is auto-wrapped with
    enter / exit / error / duration logging.

        class OrderService(metaclass=SentinelMeta):
            _sentinel_layer = LogLayer.DOMAIN   # optional
            ...
    """
    _sentinel_agent: Optional['SentinelPython'] = None

    def __new__(mcs, name, bases, namespace, **kwargs):
        cls   = super().__new__(mcs, name, bases, namespace, **kwargs)
        layer = namespace.get('_sentinel_layer') or infer_layer(name)
        for attr, val in namespace.items():
            if attr.startswith('_'):
                continue
            if callable(val) and not isinstance(val, (classmethod, staticmethod, property)):
                setattr(cls, attr, mcs._wrap(val, name, attr, layer))
        return cls

    @staticmethod
    def _wrap(fn: Callable, cls_name: str, method: str, layer: str) -> Callable:
        is_async = inspect.iscoroutinefunction(fn)

        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                if agent:
                    agent._emit(f'{cls_name}.{method} called', layer=layer, level=LogLevel.INFO,
                                context={'className': cls_name, 'functionName': method, 'isAsync': True})
                try:
                    result = await fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(f'{cls_name}.{method} → ok ({ms:.1f}ms)', layer=layer, level=LogLevel.INFO,
                                    context={'className': cls_name, 'functionName': method,
                                             'durationMs': ms, 'isAsync': True,
                                             'asyncDurationMs': ms})
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(f'{cls_name}.{method} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                    context={'className': cls_name, 'functionName': method,
                                             'durationMs': ms, 'isAsync': True,
                                             'exceptionType': type(exc).__name__,
                                             'stackTrace': traceback.format_exc()})
                    raise
            return async_wrapper
        else:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                if agent:
                    agent._emit(f'{cls_name}.{method} called', layer=layer, level=LogLevel.INFO,
                                context={'className': cls_name, 'functionName': method, 'isAsync': False})
                try:
                    result = fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(f'{cls_name}.{method} → ok ({ms:.1f}ms)', layer=layer, level=LogLevel.INFO,
                                    context={'className': cls_name, 'functionName': method,
                                             'durationMs': ms, 'isAsync': False})
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(f'{cls_name}.{method} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                    context={'className': cls_name, 'functionName': method,
                                             'durationMs': ms, 'isAsync': False,
                                             'exceptionType': type(exc).__name__,
                                             'stackTrace': traceback.format_exc()})
                    raise
            return wrapper


T = TypeVar('T')


# ── Main agent ────────────────────────────────────────────────────────────────

class SentinelPython:
    def __init__(self, service_name: str = 'python-service', **cfg):
        self.service_name  = service_name
        self._process_start = time.time()
        # Network byte counters (incremented by HTTP patches)
        self._net_bytes_in  = 0
        self._net_bytes_out = 0

        self._cfg = {
            'clickhouse_host':     cfg.get('clickhouse_host',     os.getenv('CLICKHOUSE_HOST',     'http://localhost:8123')),
            'clickhouse_database': cfg.get('clickhouse_database', os.getenv('CLICKHOUSE_DATABASE', 'sentinel')),
            'clickhouse_table':    cfg.get('clickhouse_table',    os.getenv('CLICKHOUSE_TABLE',    'logs')),
            'clickhouse_user':     cfg.get('clickhouse_user',     os.getenv('CLICKHOUSE_USER',     '')),
            'clickhouse_password': cfg.get('clickhouse_password', os.getenv('CLICKHOUSE_PASSWORD', '')),
            'batch_size':          cfg.get('batch_size',          50),
            'slow_query_ms':       cfg.get('slow_query_ms',       200),
            'slow_http_ms':        cfg.get('slow_http_ms',        1000),
            'slow_function_ms':    cfg.get('slow_function_ms',    500),
            'debug':               cfg.get('debug',               False),
            'sampling_rate':       cfg.get('sampling_rate',       1.0),
            'cert_check_hosts':    cfg.get('cert_check_hosts',    []),
            'cert_check_interval': cfg.get('cert_check_interval', 6 * 3600),  # seconds
        }
        self._writer       = _ClickHouseWriter(self._cfg)
        self._instrumented: set = set()
        self._trace_id     = str(uuid.uuid4())

        # CPU timing baseline for delta calculation
        if HAS_PSUTIL:
            self._prev_cpu_times = _psutil.cpu_times()  # type: ignore

    # ── Public API ────────────────────────────────────────────────────────────

    def hook(self) -> 'SentinelPython':
        """Call once at startup — patches everything."""
        self._writer.init()
        SentinelMeta._sentinel_agent = self

        self._patch_print()
        self._patch_logging()
        self._patch_requests()
        self._patch_httpx()
        self._patch_sqlalchemy()
        self._patch_psycopg2()
        self._patch_neo4j()
        self._patch_redis()
        self._hook_process()
        self._start_vitals()
        if self._cfg['cert_check_hosts']:
            self._start_cert_monitor()

        self._emit(
            f'Sentinel Python Agent hooked on "{self.service_name}"',
            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
            context={
                'python_version':      sys.version,
                'pid':                 os.getpid(),
                'processUptimeSeconds': 0,
                'cpuCoreCount':        os.cpu_count() or 1,
            },
        )
        return self

    def instrument(self, target: Any, layer: Optional[str] = None) -> 'SentinelPython':
        """Instrument any existing class instance or class."""
        cls    = target if isinstance(target, type) else type(target)
        cls_id = id(cls)
        if cls_id in self._instrumented:
            return self
        self._instrumented.add(cls_id)

        resolved_layer = layer or infer_layer(cls.__name__)
        methods = [
            name for name, val in inspect.getmembers(cls, predicate=inspect.isfunction)
            if not name.startswith('__')
        ]
        for method_name in methods:
            try:
                orig    = getattr(cls, method_name)
                wrapped = SentinelMeta._wrap(orig, cls.__name__, method_name, resolved_layer)
                setattr(cls, method_name, wrapped)
            except (AttributeError, TypeError):
                pass

        self._emit(
            f'Instrumented: {cls.__name__} ({len(methods)} methods → {resolved_layer})',
            layer=LogLayer.OBSERVABILITY, level=LogLevel.DEBUG,
        )
        return self

    def track(self, layer: str = LogLayer.BUSINESS_LOGIC, slow_ms: Optional[float] = None):
        """
        Decorator for standalone functions (sync or async):
            @sentinel.track(layer=LogLayer.DOMAIN)
            def place_order(order): ...
        """
        def decorator(fn: Callable) -> Callable:
            threshold = slow_ms or self._cfg['slow_function_ms']
            is_async  = inspect.iscoroutinefunction(fn)

            if is_async:
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    self._emit(f'{fn.__qualname__} called', layer=layer, level=LogLevel.INFO,
                               context={'functionName': fn.__qualname__, 'isAsync': True})
                    try:
                        result = await fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer,
                            level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            context={'functionName': fn.__qualname__, 'durationMs': ms,
                                     'isAsync': True, 'asyncDurationMs': ms})
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(f'{fn.__qualname__} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                   context={'functionName': fn.__qualname__, 'durationMs': ms,
                                            'isAsync': True, 'exceptionType': type(exc).__name__,
                                            'stackTrace': traceback.format_exc()})
                        raise
                return async_wrapper
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    self._emit(f'{fn.__qualname__} called', layer=layer, level=LogLevel.INFO,
                               context={'functionName': fn.__qualname__, 'isAsync': False})
                    try:
                        result = fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer,
                            level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            context={'functionName': fn.__qualname__, 'durationMs': ms, 'isAsync': False})
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(f'{fn.__qualname__} → error: {exc}', layer=layer, level=LogLevel.ERROR,
                                   context={'functionName': fn.__qualname__, 'durationMs': ms,
                                            'isAsync': False, 'exceptionType': type(exc).__name__,
                                            'stackTrace': traceback.format_exc()})
                        raise
                return wrapper
        return decorator

    def log(self, message: str, layer: str = LogLayer.BUSINESS_LOGIC,
            level: str = LogLevel.INFO, context: Optional[Dict] = None) -> None:
        self._emit(message, layer=layer, level=level, context=context)

    def flush(self) -> None:
        self._writer.flush()

    # ── Flask middleware ──────────────────────────────────────────────────────

    def flask_middleware(self, app: Any) -> Any:
        sentinel = self

        @app.before_request
        def before():
            import flask
            flask.g._sentinel_start = time.perf_counter()
            req = flask.request
            body_bytes = int(req.content_length or 0)
            sentinel._net_bytes_in += body_bytes
            sentinel._emit(
                f'→ {req.method} {req.path}',
                layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                context={
                    'method':           req.method,
                    'path':             req.path,
                    'clientIp':         req.remote_addr,
                    'userAgent':        req.headers.get('User-Agent'),
                    'userId':           req.headers.get('X-User-Id'),
                    'sessionId':        req.headers.get('X-Session-Id'),
                    'requestSizeBytes': body_bytes,
                    'corsOrigin':       req.headers.get('Origin'),
                },
            )

        @app.after_request
        def after(response):
            import flask
            req  = flask.request
            ms   = (time.perf_counter() - getattr(flask.g, '_sentinel_start', time.perf_counter())) * 1000

            res_bytes = int(response.content_length or 0)
            sentinel._net_bytes_out += res_bytes

            rate_limit_hit      = response.status_code == 429
            rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
            cors_violation       = response.status_code == 403 and bool(req.headers.get('Origin'))
            bot_signal           = bool(_BOT_UA_RE.search(req.headers.get('User-Agent', '')))

            # Auth event
            is_auth_path    = bool(_AUTH_PATH_RE.search(req.path))
            is_auth_failure = response.status_code in (401, 403)
            if is_auth_path or is_auth_failure:
                sentinel._emit(
                    f'Auth event: {req.method} {req.path} → {response.status_code}',
                    layer=LogLayer.SECURITY,
                    level=LogLevel.WARN if is_auth_failure else LogLevel.INFO,
                    context={
                        'authResult':    'success' if response.status_code < 400 else 'failure',
                        'ipAddress':     req.remote_addr,
                        'userAgent':     req.headers.get('User-Agent'),
                        'path':          req.path,
                        'userId':        req.headers.get('X-User-Id'),
                        'failureReason': f'HTTP {response.status_code}' if is_auth_failure else None,
                    },
                )

            sentinel._emit(
                f'← {req.method} {req.path} {response.status_code} ({ms:.1f}ms)'
                f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                layer=LogLayer.API_GATEWAY,
                level=(LogLevel.ERROR if response.status_code >= 500
                       else LogLevel.WARN if response.status_code >= 400
                       else LogLevel.INFO),
                context={
                    'method':             req.method,
                    'path':               req.path,
                    'statusCode':         response.status_code,
                    'durationMs':         ms,
                    'rateLimitHit':       rate_limit_hit,
                    'rateLimitRemaining': rate_limit_remaining if rate_limit_remaining >= 0 else None,
                    'responseSizeBytes':  res_bytes or None,
                    'corsViolation':      cors_violation,
                    'botSignal':          bot_signal,
                },
            )
            return response

        return app

    # ── FastAPI / ASGI middleware ─────────────────────────────────────────────

    def fastapi_middleware(self, app: Any) -> Any:
        sentinel = self

        class _Middleware:
            def __init__(self, asgi_app):
                self.app = asgi_app

            async def __call__(self, scope, receive, send):
                if scope['type'] != 'http':
                    await self.app(scope, receive, send)
                    return

                start      = time.perf_counter()
                method     = scope.get('method', '')
                path       = scope.get('path', '')
                headers    = dict(scope.get('headers', []))
                origin     = headers.get(b'origin', b'').decode()
                user_agent = headers.get(b'user-agent', b'').decode()
                user_id    = headers.get(b'x-user-id', b'').decode() or None
                session_id = headers.get(b'x-session-id', b'').decode() or None

                sentinel._emit(
                    f'→ {method} {path}',
                    layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                    context={
                        'method':    method,
                        'path':      path,
                        'userAgent': user_agent,
                        'userId':    user_id,
                        'sessionId': session_id,
                        'corsOrigin': origin or None,
                    },
                )

                status_code = [200]

                async def send_wrapper(message):
                    if message['type'] == 'http.response.start':
                        status_code[0] = message['status']
                    await send(message)

                await self.app(scope, receive, send_wrapper)
                ms         = (time.perf_counter() - start) * 1000
                sc         = status_code[0]
                rate_limit_hit  = sc == 429
                cors_violation  = sc == 403 and bool(origin)
                bot_signal      = bool(_BOT_UA_RE.search(user_agent))
                is_auth_path    = bool(_AUTH_PATH_RE.search(path))
                is_auth_failure = sc in (401, 403)

                if is_auth_path or is_auth_failure:
                    sentinel._emit(
                        f'Auth event: {method} {path} → {sc}',
                        layer=LogLayer.SECURITY,
                        level=LogLevel.WARN if is_auth_failure else LogLevel.INFO,
                        context={
                            'authResult':    'success' if sc < 400 else 'failure',
                            'path':          path,
                            'statusCode':    sc,
                            'userAgent':     user_agent,
                            'failureReason': f'HTTP {sc}' if is_auth_failure else None,
                        },
                    )

                sentinel._emit(
                    f'← {method} {path} {sc} ({ms:.1f}ms)'
                    f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.API_GATEWAY,
                    level=LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                    context={
                        'method':       method,
                        'path':         path,
                        'statusCode':   sc,
                        'durationMs':   ms,
                        'rateLimitHit': rate_limit_hit,
                        'corsViolation': cors_violation,
                        'botSignal':    bot_signal,
                    },
                )

        app.add_middleware(_Middleware)
        return app

    # ── Internal emitter ──────────────────────────────────────────────────────

    def _emit(self, message: str, layer: str = LogLayer.BUSINESS_LOGIC,
              level: str = LogLevel.INFO, context: Optional[Dict] = None) -> None:
        rate = self._cfg['sampling_rate']
        if rate < 1.0:
            import random
            if random.random() > rate:
                return

        ctx = context or {}
        ctx.setdefault('samplingRate',     rate)
        ctx.setdefault('samplingDecision', 'sampled')

        record = LogRecord(
            message=message,
            layer=layer,
            level=level,
            service=self.service_name,
            context=ctx,
            trace_id=self._trace_id,
        )
        if self._cfg['debug']:
            print(f'[SENTINEL] {record}', file=sys.stderr)
        self._writer.enqueue(record)

    # ── print() patch ─────────────────────────────────────────────────────────

    def _patch_print(self) -> None:
        sentinel   = self
        orig_print = builtins.print

        def sentinel_print(*args, **kwargs):
            msg = ' '.join(str(a) for a in args)
            if '[SENTINEL]' in msg:
                orig_print(*args, **kwargs)
                return
            sentinel._emit(msg, layer=LogLayer.BUSINESS_LOGIC, level=LogLevel.INFO)
            orig_print(f'[SENTINEL] {msg}', **kwargs)

        builtins.print = sentinel_print

    # ── logging module patch ──────────────────────────────────────────────────

    def _patch_logging(self) -> None:
        sentinel = self
        _LEVEL_MAP = {
            logging.DEBUG:    LogLevel.DEBUG,
            logging.INFO:     LogLevel.INFO,
            logging.WARNING:  LogLevel.WARN,
            logging.ERROR:    LogLevel.ERROR,
            logging.CRITICAL: LogLevel.FATAL,
        }

        class SentinelHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                sentinel._emit(
                    record.getMessage(),
                    layer=LogLayer.OBSERVABILITY,
                    level=_LEVEL_MAP.get(record.levelno, LogLevel.INFO),
                    context={
                        'logger':   record.name,
                        'module':   record.module,
                        'funcName': record.funcName,
                    },
                )

        logging.getLogger().addHandler(SentinelHandler())

    # ── requests patch ────────────────────────────────────────────────────────

    def _patch_requests(self) -> None:
        if not HAS_REQUESTS:
            return
        sentinel = self
        orig_send = _requests.Session.send  # type: ignore

        def patched_send(self_session, request, **kwargs):
            start = time.perf_counter()
            url   = str(request.url)
            body  = request.body or b''
            body_bytes = len(body) if isinstance(body, (bytes, str)) else 0
            sentinel._net_bytes_in += body_bytes

            sentinel._emit(
                f'→ {request.method} {url}',
                layer=LogLayer.SERVICE, level=LogLevel.INFO,
                context={'method': request.method, 'path': url, 'requestSizeBytes': body_bytes},
            )
            try:
                response = orig_send(self_session, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                res_bytes = len(response.content) if response.content else 0
                sentinel._net_bytes_out += res_bytes

                rate_limit_hit      = sc == 429
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
                retry_count          = int(request.headers.get('X-Retry-Count', 0))

                # Auth event detection
                if _AUTH_PATH_RE.search(url) or sc in (401, 403):
                    sentinel._emit(
                        f'Auth event: {request.method} {url} → {sc}',
                        layer=LogLayer.SECURITY,
                        level=LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                        context={
                            'authResult':    'success' if sc < 400 else 'failure',
                            'path':          url,
                            'statusCode':    sc,
                            'failureReason': f'HTTP {sc}' if sc >= 400 else None,
                        },
                    )

                sentinel._emit(
                    f'← {request.method} {url} {sc} ({ms:.1f}ms)'
                    f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=(LogLevel.ERROR if sc >= 500
                           else LogLevel.WARN if sc >= 400
                           else LogLevel.INFO),
                    context={
                        'method':               request.method,
                        'path':                 url,
                        'statusCode':           sc,
                        'durationMs':           ms,
                        'responseSizeBytes':    res_bytes or None,
                        'rateLimitHit':         rate_limit_hit,
                        'rateLimitRemaining':   rate_limit_remaining if rate_limit_remaining >= 0 else None,
                        'downstreamService':    url,
                        'downstreamStatusCode': sc,
                        'downstreamDurationMs': ms,
                        'thirdPartyLatencyMs':  ms,
                        'retryCount':           retry_count or None,
                    },
                )
                return response
            except Exception as exc:
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'✗ {request.method} {url} — {exc}',
                    layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                    context={'method': request.method, 'path': url, 'durationMs': ms,
                             'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc()},
                )
                raise

        _requests.Session.send = patched_send  # type: ignore

    # ── httpx patch ───────────────────────────────────────────────────────────

    def _patch_httpx(self) -> None:
        if not HAS_HTTPX:
            return
        sentinel = self
        orig_send = _httpx.Client.send  # type: ignore

        def patched_send(self_client, request, **kwargs):
            start = time.perf_counter()
            url   = str(request.url)
            sentinel._emit(f'→ httpx {request.method} {url}', layer=LogLayer.SERVICE, level=LogLevel.INFO,
                           context={'method': request.method, 'path': url})
            try:
                response = orig_send(self_client, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                rate_limit_hit = sc == 429
                sentinel._emit(
                    f'← httpx {request.method} {url} {sc} ({ms:.1f}ms)'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                    context={'method': request.method, 'path': url, 'statusCode': sc,
                             'durationMs': ms, 'rateLimitHit': rate_limit_hit,
                             'downstreamStatusCode': sc, 'thirdPartyLatencyMs': ms},
                )
                return response
            except Exception as exc:
                sentinel._emit(f'✗ httpx {request.method} {url} — {exc}', layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                               context={'method': request.method, 'path': url, 'exceptionType': type(exc).__name__})
                raise

        _httpx.Client.send = patched_send  # type: ignore

    # ── SQLAlchemy patch ──────────────────────────────────────────────────────

    def _patch_sqlalchemy(self) -> None:
        if not HAS_SQLALCHEMY:
            return
        sentinel  = self
        slow_ms   = self._cfg['slow_query_ms']
        _starts: Dict[int, float] = {}

        @_sa_event.listens_for(_sa.engine.Engine, 'before_cursor_execute')  # type: ignore
        def before(conn, cursor, statement, parameters, context, executemany):
            _starts[id(cursor)] = time.perf_counter()

        @_sa_event.listens_for(_sa.engine.Engine, 'after_cursor_execute')  # type: ignore
        def after(conn, cursor, statement, parameters, context, executemany):
            start   = _starts.pop(id(cursor), time.perf_counter())
            ms      = (time.perf_counter() - start) * 1000
            is_slow = ms > slow_ms
            stmt_up = statement.strip().upper()
            is_migration = bool(_MIGRATION_RE.match(stmt_up))
            is_commit    = stmt_up.startswith('COMMIT')
            is_rollback  = stmt_up.startswith('ROLLBACK')

            sentinel._emit(
                f'SQLAlchemy{"[SLOW]" if is_slow else ""}: {statement[:120]}',
                layer=LogLayer.DATA_ACCESS,
                level=LogLevel.WARN if is_slow else LogLevel.INFO,
                context={
                    'database':             'sqlalchemy',
                    'queryType':            stmt_up.split()[0],
                    'durationMs':           ms,
                    'slowQuery':            is_slow,
                    'slowQueryThresholdMs': slow_ms,
                    'migrationName':        statement[:80] if is_migration else None,
                    'migrationStatus':      'completed' if is_migration else None,
                    'transactionAction':    'commit' if is_commit else 'rollback' if is_rollback else None,
                },
            )

    # ── psycopg2 patch ────────────────────────────────────────────────────────

    def _patch_psycopg2(self) -> None:
        if not HAS_PSYCOPG2:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']
        orig_execute = _psycopg2.extensions.cursor.execute  # type: ignore

        def patched_execute(self_cursor, query, vars=None):
            start = time.perf_counter()
            try:
                result  = orig_execute(self_cursor, query, vars)
                ms      = (time.perf_counter() - start) * 1000
                is_slow = ms > slow_ms
                stmt_up = str(query).strip().upper()
                is_migration  = bool(_MIGRATION_RE.match(stmt_up))
                is_commit     = stmt_up.startswith('COMMIT')
                is_rollback   = stmt_up.startswith('ROLLBACK')

                # Connection pool stats (if using a pool cursor)
                pool     = getattr(getattr(self_cursor, 'connection', None), '_pool', None)
                pool_size = getattr(pool, 'maxconn', None)
                pool_used = getattr(pool, '_used',   None)

                sentinel._emit(
                    f'psycopg2{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                    layer=LogLayer.DATA_ACCESS,
                    level=LogLevel.WARN if is_slow else LogLevel.INFO,
                    context={
                        'database':             'postgres',
                        'queryType':            stmt_up.split()[0] if stmt_up else 'UNKNOWN',
                        'durationMs':           ms,
                        'rowsAffected':         self_cursor.rowcount,
                        'slowQuery':            is_slow,
                        'slowQueryThresholdMs': slow_ms,
                        'migrationName':        str(query)[:80] if is_migration else None,
                        'migrationStatus':      'completed'      if is_migration else None,
                        'transactionAction':    'commit'   if is_commit   else 'rollback' if is_rollback else None,
                        'connectionPoolSize':   pool_size,
                        'connectionPoolUsed':   len(pool_used) if pool_used is not None else None,
                    },
                )
                return result
            except Exception as exc:
                ms  = (time.perf_counter() - start) * 1000
                msg = str(exc).lower()
                sentinel._emit(
                    f'psycopg2 error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    context={
                        'database':     'postgres',
                        'durationMs':   ms,
                        'deadlock':     'deadlock' in msg,
                        'lockTimeout':  'lock timeout' in msg,
                        'exceptionType': type(exc).__name__,
                        'stackTrace':   traceback.format_exc(),
                    },
                )
                raise

        _psycopg2.extensions.cursor.execute = patched_execute  # type: ignore

    # ── neo4j patch ───────────────────────────────────────────────────────────

    def _patch_neo4j(self) -> None:
        if not HAS_NEO4J:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']
        orig_run = _neo4j.Session.run  # type: ignore

        def patched_run(self_session, query, parameters=None, **kwargs):
            start = time.perf_counter()
            try:
                result  = orig_run(self_session, query, parameters, **kwargs)
                ms      = (time.perf_counter() - start) * 1000
                is_slow = ms > slow_ms
                sentinel._emit(
                    f'Neo4j{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                    layer=LogLayer.DATA_ACCESS,
                    level=LogLevel.WARN if is_slow else LogLevel.INFO,
                    context={
                        'database':             'neo4j',
                        'durationMs':           ms,
                        'slowQuery':            is_slow,
                        'slowQueryThresholdMs': slow_ms,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(f'Neo4j error: {exc}', layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                               context={'database': 'neo4j', 'exceptionType': type(exc).__name__,
                                        'stackTrace': traceback.format_exc()})
                raise

        _neo4j.Session.run = patched_run  # type: ignore

    # ── redis patch ───────────────────────────────────────────────────────────

    def _patch_redis(self) -> None:
        if not HAS_REDIS:
            return
        sentinel = self
        _EVICTION_CMDS = {'DEL', 'UNLINK', 'EXPIRE', 'EXPIREAT', 'PEXPIRE', 'PEXPIREAT'}
        orig_execute_command = _redis.StrictRedis.execute_command  # type: ignore

        def patched_execute_command(self_redis, *args, **kwargs):
            cmd   = str(args[0]).upper() if args else 'CMD'
            start = time.perf_counter()
            try:
                result = orig_execute_command(self_redis, *args, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'Redis {cmd} ({ms:.1f}ms)',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.DEBUG,
                    context={
                        'database':      'redis',
                        'queryType':     cmd,
                        'durationMs':    ms,
                        'cacheHit':      result is not None,
                        'cacheMiss':     result is None,
                        'cacheEviction': cmd in _EVICTION_CMDS,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Redis {cmd} error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    context={'database': 'redis', 'queryType': cmd, 'exceptionType': type(exc).__name__},
                )
                raise

        _redis.StrictRedis.execute_command = patched_execute_command  # type: ignore

    # ── process hooks ─────────────────────────────────────────────────────────

    def _hook_process(self) -> None:
        sentinel = self

        def handle_exception(exc_type, exc_value, exc_tb):
            sentinel._emit(
                f'Uncaught exception: {exc_value}',
                layer=LogLayer.SECURITY, level=LogLevel.FATAL,
                context={
                    'exceptionType':        exc_type.__name__,
                    'stackTrace':           ''.join(traceback.format_tb(exc_tb)),
                    'processUptimeSeconds': time.time() - sentinel._process_start,
                    'processExitCode':      1,
                },
            )
            sentinel._writer.flush()
            sys.__excepthook__(exc_type, exc_value, exc_tb)

        sys.excepthook = handle_exception

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                orig_handler = signal.getsignal(sig)

                def make_handler(s, oh):
                    def handler(signum, frame):
                        sentinel._emit(
                            f'Process signal: {s.name}',
                            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.WARN,
                            context={
                                'containerEvent':       'stop',
                                'containerName':         sentinel.service_name,
                                'processUptimeSeconds':  time.time() - sentinel._process_start,
                            },
                        )
                        sentinel._writer.flush()
                        if callable(oh):
                            oh(signum, frame)
                        else:
                            sys.exit(0)
                    return handler

                signal.signal(sig, make_handler(sig, orig_handler))
            except (ValueError, OSError):
                pass

    # ── Infrastructure vitals ─────────────────────────────────────────────────

    def _start_vitals(self) -> None:
        """Emit CPU, memory, disk, and network metrics every 30 s."""
        sentinel = self

        def vitals_loop():
            while True:
                time.sleep(30)
                try:
                    sentinel._emit_vitals()
                except Exception:
                    pass  # never crash the vitals thread

        t = threading.Thread(target=vitals_loop, daemon=True)
        t.start()

        # Also emit disk stats every 60 s on a separate timer
        def disk_loop():
            while True:
                time.sleep(60)
                try:
                    sentinel._emit_disk_vitals()
                except Exception:
                    pass

        d = threading.Thread(target=disk_loop, daemon=True)
        d.start()

    def _emit_vitals(self) -> None:
        ctx: Dict[str, Any] = {
            'containerName':         self.service_name,
            'processUptimeSeconds':  time.time() - self._process_start,
            'networkInBytes':        self._net_bytes_in,
            'networkOutBytes':       self._net_bytes_out,
        }

        if HAS_PSUTIL:
            # CPU — delta since last sample
            curr  = _psutil.cpu_times()  # type: ignore
            prev  = self._prev_cpu_times
            delta = lambda k: getattr(curr, k, 0) - getattr(prev, k, 0)
            total = sum(delta(k) for k in ('user','system','idle','nice','iowait','irq','softirq','steal') if hasattr(curr, k))
            idle  = delta('idle')
            cpu_pct = round(((total - idle) / total) * 100, 2) if total > 0 else 0.0
            self._prev_cpu_times = curr

            mem  = _psutil.virtual_memory()  # type: ignore
            swap = _psutil.swap_memory()  # type: ignore
            proc = _psutil.Process(os.getpid())  # type: ignore
            p_mem = proc.memory_info()

            ctx.update({
                'cpuPercent':          cpu_pct,
                'cpuCoreCount':        _psutil.cpu_count(logical=True) or os.cpu_count() or 1,  # type: ignore
                'cpuStealPercent':     round(delta('steal') / total * 100, 2) if total > 0 and hasattr(curr, 'steal') else None,
                'memoryUsedBytes':     p_mem.rss,
                'memoryTotalBytes':    mem.total,
                'memoryAvailableBytes': mem.available,
                'swapUsedBytes':       swap.used,
            })

            level = LogLevel.WARN if cpu_pct > 85 else LogLevel.INFO
            msg   = (f'Process vitals: cpu={cpu_pct}% '
                     f'rss={p_mem.rss // 1024 // 1024}MB '
                     f'mem_avail={mem.available // 1024 // 1024}MB')
        else:
            # Fallback — basic info from /proc or nothing
            try:
                import resource as _resource
                usage = _resource.getrusage(_resource.RUSAGE_SELF)
                ctx['memoryUsedBytes'] = usage.ru_maxrss * 1024  # macOS: bytes, Linux: KB
            except Exception:
                pass
            level = LogLevel.INFO
            msg   = f'Process vitals: uptime={ctx["processUptimeSeconds"]:.0f}s'

        self._emit(msg, layer=LogLayer.INFRASTRUCTURE, level=level, context=ctx)

    def _emit_disk_vitals(self) -> None:
        if not HAS_PSUTIL:
            return
        try:
            disk = _psutil.disk_usage('/')  # type: ignore
            pct  = round(disk.percent, 1)
            self._emit(
                f'Disk vitals: {pct}% used ({disk.used // 1024 // 1024 // 1024}GB / {disk.total // 1024 // 1024 // 1024}GB)',
                layer=LogLayer.INFRASTRUCTURE,
                level=LogLevel.WARN if pct > 85 else LogLevel.INFO,
                context={
                    'diskUsedBytes':    disk.used,
                    'diskTotalBytes':   disk.total,
                    'diskUsedPercent':  pct,
                    'containerName':    self.service_name,
                },
            )
        except Exception:
            pass

    # ── TLS certificate expiry monitor ────────────────────────────────────────

    def _start_cert_monitor(self) -> None:
        sentinel = self

        def check_all():
            for hostname in sentinel._cfg['cert_check_hosts']:
                try:
                    ctx_ssl = ssl.create_default_context()
                    conn    = ctx_ssl.wrap_socket(
                        socket.create_connection((hostname, 443), timeout=5),
                        server_hostname=hostname,
                    )
                    cert       = conn.getpeercert()
                    conn.close()

                    if not cert:
                        return

                    expiry_str: str = cert.get('notAfter', '')  # type: ignore
                    # format: 'Jan  1 00:00:00 2026 GMT'
                    expiry_dt  = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc)
                    days_left  = (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).days

                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))  # type: ignore
                    issuer      = issuer_dict.get(b'organizationName') or issuer_dict.get(b'commonName') or 'unknown'  # type: ignore

                    level = (LogLevel.FATAL if days_left < 7
                             else LogLevel.ERROR if days_left < 14
                             else LogLevel.WARN  if days_left < 30
                             else LogLevel.INFO)

                    sentinel._emit(
                        f'TLS cert: {hostname} expires in {days_left} days',
                        layer=LogLayer.INFRASTRUCTURE, level=level,
                        context={
                            'certDomain':     hostname,
                            'certExpiryDays': days_left,
                            'certIssuer':     issuer,
                        },
                    )
                except Exception as exc:
                    sentinel._emit(
                        f'TLS cert check failed: {hostname} — {exc}',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                        context={'certDomain': hostname, 'exceptionType': type(exc).__name__},
                    )

        def monitor_loop():
            check_all()
            interval = sentinel._cfg['cert_check_interval']
            while True:
                time.sleep(interval)
                check_all()

        t = threading.Thread(target=monitor_loop, daemon=True)
        t.start()


# ── Factory ───────────────────────────────────────────────────────────────────

def init_sentinel(service_name: str = 'python-service', **kwargs) -> SentinelPython:
    """
    One-liner initialisation::

        sentinel = init_sentinel(
            "my-service",
            clickhouse_host="http://ch:8123",
            debug=True,
            sampling_rate=0.1,
            cert_check_hosts=["api.example.com"],
            slow_function_ms=300,
        )

    Keyword args
    ------------
    clickhouse_host, clickhouse_database, clickhouse_table,
    clickhouse_user, clickhouse_password,
    batch_size, slow_query_ms, slow_http_ms, slow_function_ms,
    debug, sampling_rate (0.0–1.0),
    cert_check_hosts (list[str]), cert_check_interval (seconds, default 21600)
    """
    agent = SentinelPython(service_name, **kwargs)
    agent.hook()
    return agent
