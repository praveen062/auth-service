package logger

import (
	"auth-service/internal/config"
	"auth-service/internal/tracing"
	"context"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.Logger with additional functionality
type Logger struct {
	*zap.Logger
}

// RequestLogger provides request-specific logging
type RequestLogger struct {
	*Logger
	requestID    string
	userID       string
	tenantID     string
	method       string
	path         string
	clientIP     string
	traceID      string
	spanID       string
	parentSpanID string
}

// NewLogger creates a new logger instance based on configuration
func NewLogger(cfg *config.LoggingConfig) (*Logger, error) {
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		level = zapcore.InfoLevel
	}

	// Create encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.MessageKey = "message"
	encoderConfig.LevelKey = "level"
	encoderConfig.CallerKey = "caller"

	// Choose encoder based on format
	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Choose output
	var writeSyncer zapcore.WriteSyncer
	if cfg.Output == "stdout" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else {
		file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.AddSync(file)
	}

	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// Create logger options
	opts := []zap.Option{
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	}

	if cfg.IncludeCaller {
		opts = append(opts, zap.AddCallerSkip(1))
	}

	if cfg.IncludeStacktrace {
		opts = append(opts, zap.AddStacktrace(zapcore.WarnLevel))
	}

	logger := zap.New(core, opts...)
	return &Logger{Logger: logger}, nil
}

// WithRequest creates a request-specific logger
func (l *Logger) WithRequest(r *http.Request) *RequestLogger {
	// Extract tracing information
	traceCtx := tracing.ExtractTracingFromRequest(r)

	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = traceCtx.TraceID // Use trace ID as request ID if not provided
	}

	userID := r.Header.Get("X-User-ID")
	tenantID := r.Header.Get("X-Tenant-ID")
	clientIP := getClientIP(r)

	return &RequestLogger{
		Logger:       l,
		requestID:    requestID,
		userID:       userID,
		tenantID:     tenantID,
		method:       r.Method,
		path:         r.URL.Path,
		clientIP:     clientIP,
		traceID:      traceCtx.TraceID,
		spanID:       traceCtx.SpanID,
		parentSpanID: traceCtx.ParentSpanID,
	}
}

// WithContext creates a logger with context values
func (l *Logger) WithContext(ctx context.Context) *RequestLogger {
	requestID := getFromContext(ctx, "request_id")
	userID := getFromContext(ctx, "user_id")
	tenantID := getFromContext(ctx, "tenant_id")
	method := getFromContext(ctx, "method")
	path := getFromContext(ctx, "path")
	clientIP := getFromContext(ctx, "client_ip")

	// Get tracing context from context
	traceCtx := tracing.GetTracingContextFromContext(ctx)

	return &RequestLogger{
		Logger:       l,
		requestID:    requestID,
		userID:       userID,
		tenantID:     tenantID,
		method:       method,
		path:         path,
		clientIP:     clientIP,
		traceID:      traceCtx.TraceID,
		spanID:       traceCtx.SpanID,
		parentSpanID: traceCtx.ParentSpanID,
	}
}

// RequestStart logs the start of a request
func (rl *RequestLogger) RequestStart() {
	rl.Info("Request started",
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("parent_span_id", rl.parentSpanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
		zap.String("user_id", rl.userID),
		zap.String("tenant_id", rl.tenantID),
	)
}

// RequestEnd logs the end of a request with duration and status
func (rl *RequestLogger) RequestEnd(status int, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("parent_span_id", rl.parentSpanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
		zap.String("user_id", rl.userID),
		zap.String("tenant_id", rl.tenantID),
		zap.Int("status", status),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		rl.Error("Request failed", fields...)
	} else {
		rl.Info("Request completed", fields...)
	}
}

// AuthSuccess logs successful authentication
func (rl *RequestLogger) AuthSuccess(userID, tenantID, authMethod string) {
	rl.Info("Authentication successful",
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("user_id", userID),
		zap.String("tenant_id", tenantID),
		zap.String("auth_method", authMethod),
		zap.String("client_ip", rl.clientIP),
	)
}

// AuthFailure logs failed authentication
func (rl *RequestLogger) AuthFailure(userID, tenantID, authMethod, reason string) {
	rl.Warn("Authentication failed",
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("user_id", userID),
		zap.String("tenant_id", tenantID),
		zap.String("auth_method", authMethod),
		zap.String("reason", reason),
		zap.String("client_ip", rl.clientIP),
	)
}

// OAuthFlow logs OAuth flow events
func (rl *RequestLogger) OAuthFlow(provider, step, tenantID string, err error) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("provider", provider),
		zap.String("step", step),
		zap.String("tenant_id", tenantID),
		zap.String("client_ip", rl.clientIP),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		rl.Error("OAuth flow failed", fields...)
	} else {
		rl.Info("OAuth flow step completed", fields...)
	}
}

// DatabaseOperation logs database operations
func (rl *RequestLogger) DatabaseOperation(operation, table, tenantID string, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("operation", operation),
		zap.String("table", table),
		zap.String("tenant_id", tenantID),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		rl.Error("Database operation failed", fields...)
	} else {
		rl.Debug("Database operation completed", fields...)
	}
}

// CacheOperation logs cache operations
func (rl *RequestLogger) CacheOperation(operation, key, tenantID string, hit bool, duration time.Duration, err error) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("operation", operation),
		zap.String("key", key),
		zap.String("tenant_id", tenantID),
		zap.Bool("cache_hit", hit),
		zap.Duration("duration", duration),
	}

	if err != nil {
		fields = append(fields, zap.Error(err))
		rl.Error("Cache operation failed", fields...)
	} else {
		rl.Debug("Cache operation completed", fields...)
	}
}

// SecurityEvent logs security-related events
func (rl *RequestLogger) SecurityEvent(eventType, userID, tenantID, details string, severity string) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("event_type", eventType),
		zap.String("user_id", userID),
		zap.String("tenant_id", tenantID),
		zap.String("details", details),
		zap.String("severity", severity),
		zap.String("client_ip", rl.clientIP),
	}

	switch severity {
	case "high":
		rl.Logger.Error("Security event", fields...)
	case "medium":
		rl.Logger.Warn("Security event", fields...)
	case "low":
		rl.Logger.Info("Security event", fields...)
	default:
		rl.Logger.Info("Security event", fields...)
	}
}

// BusinessEvent logs business logic events
func (rl *RequestLogger) BusinessEvent(eventType, userID, tenantID string, data map[string]interface{}) {
	fields := []zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("event_type", eventType),
		zap.String("user_id", userID),
		zap.String("tenant_id", tenantID),
		zap.String("client_ip", rl.clientIP),
	}

	for key, value := range data {
		fields = append(fields, zap.Any(key, value))
	}

	rl.Logger.Info("Business event", fields...)
}

// Error logs errors with request context
func (rl *RequestLogger) Error(msg string, fields ...zap.Field) {
	allFields := append([]zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
	}, fields...)
	rl.Logger.Error(msg, allFields...)
}

// Warn logs warnings with request context
func (rl *RequestLogger) Warn(msg string, fields ...zap.Field) {
	allFields := append([]zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
	}, fields...)
	rl.Logger.Warn(msg, allFields...)
}

// Info logs info messages with request context
func (rl *RequestLogger) Info(msg string, fields ...zap.Field) {
	allFields := append([]zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
	}, fields...)
	rl.Logger.Info(msg, allFields...)
}

// Debug logs debug messages with request context
func (rl *RequestLogger) Debug(msg string, fields ...zap.Field) {
	allFields := append([]zap.Field{
		zap.String("request_id", rl.requestID),
		zap.String("trace_id", rl.traceID),
		zap.String("span_id", rl.spanID),
		zap.String("method", rl.method),
		zap.String("path", rl.path),
		zap.String("client_ip", rl.clientIP),
	}, fields...)
	rl.Logger.Debug(msg, allFields...)
}

// GetTraceID returns the trace ID for this request
func (rl *RequestLogger) GetTraceID() string {
	return rl.traceID
}

// GetSpanID returns the span ID for this request
func (rl *RequestLogger) GetSpanID() string {
	return rl.spanID
}

// Helper functions
func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func getClientIP(r *http.Request) string {
	// Check for forwarded headers
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

func getFromContext(ctx context.Context, key string) string {
	if val, ok := ctx.Value(key).(string); ok {
		return val
	}
	return ""
}
