package tracing

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Standard tracing headers
	TraceIDHeader      = "X-Trace-ID"
	SpanIDHeader       = "X-Span-ID"
	ParentSpanIDHeader = "X-Parent-Span-ID"

	// Cloud-native tracing headers (AWS X-Ray, Google Cloud Trace, etc.)
	XRayTraceIDHeader = "X-Amzn-Trace-Id"
	CloudTraceHeader  = "X-Cloud-Trace-Context"

	// Response header for trace ID
	ResponseTraceIDHeader = "X-Req-ID"
)

// TracingContext holds tracing information
type TracingContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	IsSampled    bool
}

// ExtractTracingFromRequest extracts tracing information from HTTP request headers
func ExtractTracingFromRequest(r *http.Request) *TracingContext {
	// First, try to extract from OpenTelemetry context
	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	traceID := ""
	spanID := ""
	parentSpanID := ""
	isSampled := true // Default to true for sampling

	if span.SpanContext().IsValid() {
		traceID = span.SpanContext().TraceID().String()
		spanID = span.SpanContext().SpanID().String()
		isSampled = span.SpanContext().IsSampled()
	}

	// If no OpenTelemetry context, try custom headers
	if traceID == "" {
		traceID = extractTraceIDFromHeaders(r)
	}

	if spanID == "" {
		spanID = extractSpanIDFromHeaders(r)
	}
	if spanID == "" {
		spanID = generateSpanID()
	}

	parentSpanID = r.Header.Get(ParentSpanIDHeader)

	// If still no trace ID, generate one
	if traceID == "" {
		traceID = generateTraceID()
	}

	// If no span ID, generate one
	if spanID == "" {
		spanID = generateSpanID()
	}

	return &TracingContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		IsSampled:    isSampled,
	}
}

// extractTraceIDFromHeaders extracts trace ID from various header formats
func extractTraceIDFromHeaders(r *http.Request) string {
	// Try standard trace ID header
	if traceID := r.Header.Get(TraceIDHeader); traceID != "" {
		return traceID
	}

	// Try AWS X-Ray format
	if xrayTraceID := r.Header.Get(XRayTraceIDHeader); xrayTraceID != "" {
		return extractXRayTraceID(xrayTraceID)
	}

	// Try Google Cloud Trace format
	if cloudTrace := r.Header.Get(CloudTraceHeader); cloudTrace != "" {
		return extractCloudTraceID(cloudTrace)
	}

	// Try request ID as fallback
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		return reqID
	}

	return ""
}

// extractSpanIDFromHeaders extracts span ID from headers
func extractSpanIDFromHeaders(r *http.Request) string {
	if spanID := r.Header.Get(SpanIDHeader); spanID != "" {
		return spanID
	}

	// Try to extract from AWS X-Ray
	if xrayTraceID := r.Header.Get(XRayTraceIDHeader); xrayTraceID != "" {
		return extractXRaySpanID(xrayTraceID)
	}

	return ""
}

// extractXRayTraceID extracts trace ID from AWS X-Ray format
// Format: Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1
func extractXRayTraceID(xrayHeader string) string {
	parts := strings.Split(xrayHeader, ";")
	for _, part := range parts {
		if strings.HasPrefix(part, "Root=") {
			root := strings.TrimPrefix(part, "Root=")
			// X-Ray trace ID format: 1-5759e988-bd862e3fe1be46a994272793
			// We'll use the full root as trace ID
			return root
		}
	}
	return ""
}

// extractXRaySpanID extracts span ID from AWS X-Ray format
func extractXRaySpanID(xrayHeader string) string {
	parts := strings.Split(xrayHeader, ";")
	for _, part := range parts {
		if strings.HasPrefix(part, "Parent=") {
			return strings.TrimPrefix(part, "Parent=")
		}
	}
	return ""
}

// extractCloudTraceID extracts trace ID from Google Cloud Trace format
// Format: 105445aa7843bc8bf206b12000100000/0;o=1
func extractCloudTraceID(cloudTraceHeader string) string {
	parts := strings.Split(cloudTraceHeader, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// generateTraceID generates a new trace ID
func generateTraceID() string {
	// Generate a 32-character hex string (16 bytes)
	// This follows the W3C trace context specification
	return fmt.Sprintf("%032x", generateRandomBytes(16))
}

// generateSpanID generates a new span ID
func generateSpanID() string {
	// Generate a 16-character hex string (8 bytes)
	return fmt.Sprintf("%016x", generateRandomBytes(8))
}

// generateRandomBytes generates random bytes for trace/span IDs
func generateRandomBytes(n int) []byte {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		// Fallback to timestamp-based generation if crypto/rand fails
		timestamp := time.Now().UnixNano()
		for i := range bytes {
			bytes[i] = byte((timestamp >> (i * 8)) & 0xFF)
		}
	}
	return bytes
}

// AddTracingHeaders adds tracing headers to HTTP response
func AddTracingHeaders(w http.ResponseWriter, traceCtx *TracingContext) {
	w.Header().Set(ResponseTraceIDHeader, traceCtx.TraceID)
	w.Header().Set(TraceIDHeader, traceCtx.TraceID)
	w.Header().Set(SpanIDHeader, traceCtx.SpanID)
}

// CreateSpan creates a new span with the given name and context
func CreateSpan(ctx context.Context, name string, traceCtx *TracingContext) (context.Context, trace.Span) {
	tracer := otel.Tracer("auth-service")

	// Create span context from trace ID and span ID
	spanCtx := createSpanContext(traceCtx)

	// Create span with the extracted context
	return tracer.Start(spanCtx, name)
}

// createSpanContext creates a span context from trace and span IDs
func createSpanContext(traceCtx *TracingContext) context.Context {
	// Create a context with the trace ID as a value
	ctx := context.WithValue(context.Background(), "trace_id", traceCtx.TraceID)
	ctx = context.WithValue(ctx, "span_id", traceCtx.SpanID)

	return ctx
}

// PropagateTracing propagates tracing context to outgoing requests
func PropagateTracing(ctx context.Context, req *http.Request) {
	// Use OpenTelemetry propagator to inject tracing context
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))
}

// GetTracingContextFromContext extracts tracing context from Go context
func GetTracingContextFromContext(ctx context.Context) *TracingContext {
	traceID, _ := ctx.Value("trace_id").(string)
	spanID, _ := ctx.Value("span_id").(string)

	if traceID == "" {
		traceID = generateTraceID()
	}
	if spanID == "" {
		spanID = generateSpanID()
	}

	return &TracingContext{
		TraceID:   traceID,
		SpanID:    spanID,
		IsSampled: true,
	}
}
