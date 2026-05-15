/* ============================================================
   SENTINEL SDK — Core Types & LogRecord Schema
   All 9 layers, fully typed, zero gaps
   ============================================================ */

export enum LogLayer {
  PRESENTATION   = 'presentation',
  API_GATEWAY    = 'api_gateway',
  BUSINESS_LOGIC = 'business_logic',
  DATA_ACCESS    = 'data_access',
  SERVICE        = 'service',
  SECURITY       = 'security',
  OBSERVABILITY  = 'observability',
  INFRASTRUCTURE = 'infrastructure',
  DOMAIN         = 'domain',
}

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO  = 'INFO',
  WARN  = 'WARN',
  ERROR = 'ERROR',
  FATAL = 'FATAL',
}

/* ── Context shapes per layer ────────────────────────────── */

export interface PresentationContext {
  page?: string;
  component?: string;
  sessionDuration?: number;
  renderTimeMs?: number;
  interactionType?: 'click' | 'scroll' | 'submit' | 'navigate' | 'focus' | 'form_abandon' | string;
  elementId?: string;
  elementTag?: string;
  elementText?: string;
  featureFlag?: string;
  flagValue?: boolean | string;
  flagVariant?: string;
  assetUrl?: string;
  errorType?: string;
  accessibilityIssue?: string;
  scrollDepthPercent?: number;
  cacheHit?: boolean;
  // Web Vitals
  lcpMs?: number;          // Largest Contentful Paint
  clsScore?: number;       // Cumulative Layout Shift
  fcpMs?: number;          // First Contentful Paint
  fpMs?: number;           // First Paint
  ttfbMs?: number;         // Time to First Byte
  fidMs?: number;          // First Input Delay
  inpMs?: number;          // Interaction to Next Paint
  fpsAverage?: number;     // Frames per second
  longTaskMs?: number;     // Long task duration
  // Browser / device
  browserName?: string;
  browserVersion?: string;
  osName?: string;
  deviceType?: 'mobile' | 'tablet' | 'desktop' | string;
  screenWidth?: number;
  screenHeight?: number;
  viewportWidth?: number;
  viewportHeight?: number;
  connectionType?: string;
  // Form
  formId?: string;
  formFieldsCompleted?: number;
  formFieldsTotal?: number;
  formAbandonedAtField?: string;
  // Navigation
  previousPage?: string;
  navigationTrigger?: string;
  [key: string]: any;
}

export interface ApiGatewayContext {
  method?: string;
  path?: string;
  statusCode?: number;
  durationMs?: number;
  requestId?: string;
  clientIp?: string;
  geoRegion?: string;
  geoCountry?: string;
  userAgent?: string;
  userId?: string;
  sessionId?: string;
  requestSizeBytes?: number;
  responseSizeBytes?: number;
  tlsVersion?: string;
  tlsCipherSuite?: string;
  tlsHandshakeMs?: number;
  upstreamService?: string;
  downstreamService?: string;
  downstreamStatusCode?: number;
  downstreamDurationMs?: number;
  rateLimitHit?: boolean;
  rateLimitRemaining?: number;
  corsViolation?: boolean;
  corsOrigin?: string;
  botSignal?: boolean;
  botScore?: number;
  authEvent?: 'login' | 'logout' | 'token_refresh' | 'denied' | string;
  authResult?: 'success' | 'failure' | 'mfa_required' | string;
  retryCount?: number;
  retryReason?: string;
  samplingRate?: number;
  samplingDecision?: 'sampled' | 'dropped';
  [key: string]: any;
}

export interface BusinessLogicContext {
  functionName?: string;
  className?: string;
  module?: string;
  durationMs?: number;
  isAsync?: boolean;
  asyncDurationMs?: number;
  inputSummary?: string;
  outputSummary?: string;
  cacheHit?: boolean;
  cacheMiss?: boolean;
  featureFlag?: string;
  flagValue?: boolean | string;
  flagVariant?: string;
  jobId?: string;
  jobName?: string;
  backgroundJobStatus?: 'started' | 'completed' | 'failed' | 'retrying' | string;
  backgroundJobQueue?: string;
  backgroundJobAttempt?: number;
  circuitBreakerState?: 'open' | 'closed' | 'half-open';
  circuitBreakerService?: string;
  thirdPartyService?: string;
  thirdPartyLatencyMs?: number;
  thirdPartyStatusCode?: number;
  queueName?: string;
  queueAction?: 'publish' | 'consume';
  queueOffset?: number;
  queueLag?: number;
  configKey?: string;
  configValue?: string;
  configPreviousValue?: string;
  configChangedBy?: string;
  fileOperation?: string;
  filePath?: string;
  fileSizeBytes?: number;
  fileReadBytes?: number;
  fileWriteBytes?: number;
  exceptionType?: string;
  stackTrace?: string;
  retryCount?: number;
  retryReason?: string;
  [key: string]: any;
}

export interface DataAccessContext {
  queryType?: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'MERGE' | string;
  table?: string;
  collection?: string;
  database?: string;
  durationMs?: number;
  rowsAffected?: number;
  rowCount?: number;
  slowQuery?: boolean;
  slowQueryThresholdMs?: number;
  deadlock?: boolean;
  lockTimeout?: boolean;
  replicationLagMs?: number;
  indexMiss?: boolean;
  migrationName?: string;
  migrationStatus?: 'started' | 'completed' | 'failed' | string;
  cacheHit?: boolean;
  cacheMiss?: boolean;
  cacheKey?: string;
  cacheTtlMs?: number;
  cacheEviction?: boolean;
  cacheEvictionReason?: string;
  storageUsedBytes?: number;
  storageCapacityBytes?: number;
  storageUsedPercent?: number;
  connectionPoolSize?: number;
  connectionPoolUsed?: number;
  connectionPoolIdle?: number;
  connectionWaitMs?: number;
  backupStatus?: 'started' | 'completed' | 'failed';
  backupSizeBytes?: number;
  backupDurationMs?: number;
  transactionAction?: 'commit' | 'rollback';
  transactionId?: string;
  queryHash?: string;
  exceptionType?: string;
  stackTrace?: string;
  [key: string]: any;
}

export interface DomainContext {
  aggregateType?: string;
  aggregateId?: string;
  eventType?: string;
  eventVersion?: number;
  previousState?: string;
  newState?: string;
  policyName?: string;
  policyResult?: boolean | string;
  invariantName?: string;
  invariantViolated?: boolean;
  riskScore?: number;
  fraudSignal?: string;
  discountCode?: string;
  discountAmount?: number;
  entityType?: string;
  entityId?: string;
  consentType?: string;
  consentGranted?: boolean;
  sagaId?: string;
  sagaStep?: string;
  sagaStatus?: 'started' | 'completed' | 'compensating' | 'failed';
  slaBreach?: boolean;
  slaThresholdMs?: number;
  slaElapsedMs?: number;
  auditUserId?: string;
  auditAction?: string;
  auditTarget?: string;
  auditResult?: string;
  transactionId?: string;
  transactionType?: string;
  transactionAmount?: number;
  transactionCurrency?: string;
  workflowId?: string;
  workflowStep?: string;
  workflowStatus?: 'started' | 'completed' | 'failed' | 'paused' | string;
  [key: string]: any;
}

export interface ObservabilityContext {
  alertName?: string;
  alertStatus?: 'fired' | 'resolved';
  alertSeverity?: 'critical' | 'warning' | 'info' | string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  correlationId?: string;
  requestId?: string;
  sessionId?: string;
  userId?: string;
  metricName?: string;
  metricValue?: number;
  metricUnit?: string;
  metricIngestionLagMs?: number;
  oncallTeam?: string;
  incidentId?: string;
  logVolumeSpike?: boolean;
  samplingDecision?: 'sampled' | 'dropped';
  samplingRate?: number;
  sloBurnRate?: number;
  sloName?: string;
  errorBudgetPercent?: number;
  syntheticCheckName?: string;
  syntheticCheckPassed?: boolean;
  syntheticCheckRegion?: string;
  errorRatePercent?: number;
  errorRateBaseline?: number;
  anomalyType?: string;
  anomalyDeviation?: number;
  runbookUrl?: string;
  dashboardQueryMs?: number;
  [key: string]: any;
}

export interface SecurityContext {
  userId?: string;
  username?: string;
  ipAddress?: string;
  geoCountry?: string;
  userAgent?: string;
  authResult?: 'success' | 'failure' | 'mfa_required';
  failureReason?: string;
  mfaMethod?: string;
  consecutiveFailures?: number;
  lockoutReason?: string;
  sessionInvalidated?: boolean;
  privilegeFrom?: string;
  privilegeTo?: string;
  privilegeEscalationAttempt?: boolean;
  wafRuleId?: string;
  wafRuleName?: string;
  wafAction?: 'allow' | 'block' | string;
  wafAttackClass?: string;
  intrusionSignal?: string;
  intrusionSeverity?: 'low' | 'medium' | 'high' | 'critical' | string;
  vulnerabilityId?: string;
  vulnerabilitySeverity?: 'low' | 'medium' | 'high' | 'critical';
  cveId?: string;
  cvssScore?: number;
  tokenId?: string;
  tokenAction?: 'issued' | 'revoked' | 'expired';
  tokenScope?: string;
  tokenTtlMs?: number;
  complianceFramework?: string;
  complianceCheckPassed?: boolean;
  complianceResource?: string;
  secretName?: string;
  secretAccessedBy?: string;
  secretRotated?: boolean;
  exfiltrationSignal?: string;
  exfiltrationBytes?: number;
  exfiltrationDestination?: string;
  firewallRuleId?: string;
  firewallAction?: 'allow' | 'block';
  firewallRuleChangedBy?: string;
  gdprDataSubject?: string;
  gdprLegalBasis?: string;
  gdprPurpose?: string;
  botScore?: number;
  suspiciousTrafficSignal?: string;
  requestAnomalyType?: string;
  [key: string]: any;
}

export interface InfrastructureContext {
  cpuPercent?: number;
  cpuCoreCount?: number;
  cpuStealPercent?: number;
  memoryUsedBytes?: number;
  memoryTotalBytes?: number;
  memoryAvailableBytes?: number;
  swapUsedBytes?: number;
  networkInBytes?: number;
  networkOutBytes?: number;
  networkLatencyMs?: number;
  networkPacketLossPercent?: number;
  containerId?: string;
  containerName?: string;
  containerImage?: string;
  containerEvent?: 'start' | 'stop' | 'restart' | 'oom' | string;
  nodeId?: string;
  nodeStatus?: 'healthy' | 'degraded' | 'down' | string;
  nodeReadiness?: 'ready' | 'not_ready' | string;
  nodeAllocatableCpu?: number;
  nodeAllocatableMemoryBytes?: number;
  osKernelEvent?: string;
  cloudProvider?: string;
  cloudRegion?: string;
  cloudInstanceId?: string;
  cloudSpendAnomaly?: boolean;
  estimatedCostUsd?: number;
  spotPreemption?: boolean;
  diskReadBytes?: number;
  diskWriteBytes?: number;
  diskReadIops?: number;
  diskWriteIops?: number;
  diskIoWaitMs?: number;
  diskUsedBytes?: number;
  diskTotalBytes?: number;
  diskUsedPercent?: number;
  autoScaleEvent?: 'scale_out' | 'scale_in' | string;
  autoScaleReason?: string;
  autoScaleTriggerMetric?: string;
  certDomain?: string;
  certExpiryDays?: number;
  certIssuer?: string;
  certCipherSuite?: string;
  hardwareFault?: string;
  processUptimeSeconds?: number;
  processExitCode?: number;
  processCrashReason?: string;
  [key: string]: any;
}

/* ── Union type ──────────────────────────────────────────── */

export type LogContext =
  | PresentationContext
  | ApiGatewayContext
  | BusinessLogicContext
  | DataAccessContext
  | DomainContext
  | ObservabilityContext
  | SecurityContext
  | InfrastructureContext
  | { [key: string]: any };

export interface InstrumentedClassMeta {
  className:       string;
  layer:           LogLayer;
  methodNames:     string[];
  detectedDomain?: string;
}

/* ── LogRecord ────────────────────────────────────────────── */

export class LogRecord {
  message:   string;
  level:     LogLevel;
  layer:     LogLayer;
  timestamp: string;
  record_id: string;
  trace_id:  string;
  span_id:   string;
  service:   string;
  env:       string;
  context:   LogContext;

  constructor(data: Partial<LogRecord> & { message: string }) {
    this.message   = data.message;
    this.level     = data.level     || LogLevel.INFO;
    this.layer     = data.layer     || LogLayer.BUSINESS_LOGIC;
    this.timestamp = data.timestamp || new Date().toISOString();
    this.record_id = data.record_id || this._genId();
    this.trace_id  = data.trace_id  || 'untracked';
    this.span_id   = data.span_id   || 'untracked';
    this.service   = data.service   || 'unknown-service';
    this.env       = data.env       || (typeof process !== 'undefined' ? process.env.NODE_ENV || 'development' : 'browser');
    this.context   = data.context   || {};
  }

  private _genId(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }

  enrich(extra: LogContext): this {
    this.context = { ...this.context, ...extra };
    return this;
  }

  to_dict(): Record<string, unknown> {
    return {
      message:   this.message,
      level:     this.level,
      layer:     this.layer,
      timestamp: this.timestamp,
      record_id: this.record_id,
      trace_id:  this.trace_id,
      span_id:   this.span_id,
      service:   this.service,
      env:       this.env,
      context:   this.context,
    };
  }

  toString(): string {
    const colors: Record<LogLevel, string> = {
      [LogLevel.DEBUG]: '\x1b[36m',
      [LogLevel.INFO]:  '\x1b[32m',
      [LogLevel.WARN]:  '\x1b[33m',
      [LogLevel.ERROR]: '\x1b[31m',
      [LogLevel.FATAL]: '\x1b[35m',
    };
    return `${colors[this.level]}[${this.timestamp}] [${this.layer.toUpperCase()}] [${this.level}] ${this.message}\x1b[0m`;
  }
}

/* ── Layer inference ─────────────────────────────────────── */

export function inferLayer(name: string): LogLayer {
  const n = name.toLowerCase();
  if (/auth|jwt|token|oauth|permission|acl|rbac|guard|firewall|waf|encrypt|decrypt|password|credential|session|csrf|cors/.test(n))
    return LogLayer.SECURITY;
  if (/repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|entity|store|persist|storage/.test(n))
    return LogLayer.DATA_ACCESS;
  if (/controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor/.test(n))
    return LogLayer.API_GATEWAY;
  if (/service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk|consent/.test(n))
    return LogLayer.DOMAIN;
  if (/infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk/.test(n))
    return LogLayer.INFRASTRUCTURE;
  if (/trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm/.test(n))
    return LogLayer.OBSERVABILITY;
  if (/component|page|view|ui|render|form|modal|widget|screen|layout|theme/.test(n))
    return LogLayer.PRESENTATION;
  return LogLayer.BUSINESS_LOGIC;
}
