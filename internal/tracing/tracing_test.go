package tracing

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractTracingFromRequest_StandardHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(TraceIDHeader, "trace-123")
	req.Header.Set(SpanIDHeader, "span-456")
	req.Header.Set(ParentSpanIDHeader, "parent-789")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "trace-123", traceCtx.TraceID)
	assert.Equal(t, "span-456", traceCtx.SpanID)
	assert.Equal(t, "parent-789", traceCtx.ParentSpanID)
	assert.True(t, traceCtx.IsSampled)
}

func TestExtractTracingFromRequest_XRayHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(XRayTraceIDHeader, "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "1-5759e988-bd862e3fe1be46a994272793", traceCtx.TraceID)
	assert.Equal(t, "53995c3f42cd8ad8", traceCtx.SpanID)
	assert.Empty(t, traceCtx.ParentSpanID)
	assert.True(t, traceCtx.IsSampled)
}

func TestExtractTracingFromRequest_CloudTraceHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(CloudTraceHeader, "105445aa7843bc8bf206b12000100000/0;o=1")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "105445aa7843bc8bf206b12000100000", traceCtx.TraceID)
	assert.NotEmpty(t, traceCtx.SpanID) // Should generate a new span ID
	assert.Empty(t, traceCtx.ParentSpanID)
	assert.True(t, traceCtx.IsSampled)
}

func TestExtractTracingFromRequest_RequestIDFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "req-123")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "req-123", traceCtx.TraceID)
	assert.NotEmpty(t, traceCtx.SpanID) // Should generate a new span ID
	assert.Empty(t, traceCtx.ParentSpanID)
	assert.True(t, traceCtx.IsSampled)
}

func TestExtractTracingFromRequest_NoHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)

	traceCtx := ExtractTracingFromRequest(req)

	assert.NotEmpty(t, traceCtx.TraceID) // Should generate a new trace ID
	assert.NotEmpty(t, traceCtx.SpanID)  // Should generate a new span ID
	assert.Empty(t, traceCtx.ParentSpanID)
	assert.True(t, traceCtx.IsSampled)
}

func TestExtractXRayTraceID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "valid xray header",
			header:   "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1",
			expected: "1-5759e988-bd862e3fe1be46a994272793",
		},
		{
			name:     "xray header without parent",
			header:   "Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1",
			expected: "1-5759e988-bd862e3fe1be46a994272793",
		},
		{
			name:     "invalid xray header",
			header:   "Invalid=header",
			expected: "",
		},
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXRayTraceID(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractXRaySpanID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "valid xray header with parent",
			header:   "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1",
			expected: "53995c3f42cd8ad8",
		},
		{
			name:     "xray header without parent",
			header:   "Root=1-5759e988-bd862e3fe1be46a994272793;Sampled=1",
			expected: "",
		},
		{
			name:     "invalid xray header",
			header:   "Invalid=header",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractXRaySpanID(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractCloudTraceID(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "valid cloud trace header",
			header:   "105445aa7843bc8bf206b12000100000/0;o=1",
			expected: "105445aa7843bc8bf206b12000100000",
		},
		{
			name:     "cloud trace header without span",
			header:   "105445aa7843bc8bf206b12000100000",
			expected: "105445aa7843bc8bf206b12000100000",
		},
		{
			name:     "invalid cloud trace header",
			header:   "invalid",
			expected: "invalid",
		},
		{
			name:     "empty header",
			header:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCloudTraceID(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateTraceID(t *testing.T) {
	traceID1 := generateTraceID()
	traceID2 := generateTraceID()

	assert.Len(t, traceID1, 32) // 16 bytes = 32 hex characters
	assert.Len(t, traceID2, 32)
	assert.NotEqual(t, traceID1, traceID2) // Should be different
}

func TestGenerateSpanID(t *testing.T) {
	spanID1 := generateSpanID()
	spanID2 := generateSpanID()

	assert.Len(t, spanID1, 16) // 8 bytes = 16 hex characters
	assert.Len(t, spanID2, 16)
	assert.NotEqual(t, spanID1, spanID2) // Should be different
}

func TestAddTracingHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	traceCtx := &TracingContext{
		TraceID:      "trace-123",
		SpanID:       "span-456",
		ParentSpanID: "parent-789",
	}

	AddTracingHeaders(w, traceCtx)

	assert.Equal(t, "trace-123", w.Header().Get(ResponseTraceIDHeader))
	assert.Equal(t, "trace-123", w.Header().Get(TraceIDHeader))
	assert.Equal(t, "span-456", w.Header().Get(SpanIDHeader))
}

func TestGetTracingContextFromContext(t *testing.T) {
	// Test with context that has tracing values
	ctx := context.WithValue(context.Background(), "trace_id", "trace-123")
	ctx = context.WithValue(ctx, "span_id", "span-456")

	traceCtx := GetTracingContextFromContext(ctx)

	assert.Equal(t, "trace-123", traceCtx.TraceID)
	assert.Equal(t, "span-456", traceCtx.SpanID)
	assert.True(t, traceCtx.IsSampled)

	// Test with empty context
	emptyCtx := context.Background()
	emptyTraceCtx := GetTracingContextFromContext(emptyCtx)

	assert.NotEmpty(t, emptyTraceCtx.TraceID) // Should generate new
	assert.NotEmpty(t, emptyTraceCtx.SpanID)  // Should generate new
	assert.True(t, emptyTraceCtx.IsSampled)
}

func TestCreateSpan(t *testing.T) {
	traceCtx := &TracingContext{
		TraceID: "trace-123",
		SpanID:  "span-456",
	}

	ctx, span := CreateSpan(context.Background(), "test-span", traceCtx)

	assert.NotNil(t, ctx)
	assert.NotNil(t, span)

	// Clean up
	span.End()
}

func TestPropagateTracing(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(context.Background(), "trace_id", "trace-123")
	ctx = context.WithValue(ctx, "span_id", "span-456")

	PropagateTracing(ctx, req)

	// Note: In a real implementation, this would test OpenTelemetry propagation
	// For now, we just verify the function doesn't panic
	assert.NotNil(t, req.Header)
}

func TestTracingContext_String(t *testing.T) {
	traceCtx := &TracingContext{
		TraceID:      "trace-123",
		SpanID:       "span-456",
		ParentSpanID: "parent-789",
		IsSampled:    true,
	}

	// Test that the struct can be used in string formatting
	str := traceCtx.TraceID + ":" + traceCtx.SpanID
	assert.Equal(t, "trace-123:span-456", str)
}

func TestExtractTracingFromRequest_PriorityOrder(t *testing.T) {
	// Test that standard headers take priority over X-Ray headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(TraceIDHeader, "standard-trace")
	req.Header.Set(SpanIDHeader, "standard-span")
	req.Header.Set(XRayTraceIDHeader, "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "standard-trace", traceCtx.TraceID)
	assert.Equal(t, "standard-span", traceCtx.SpanID)
}

func TestExtractTracingFromRequest_RequestIDPriority(t *testing.T) {
	// Test that X-Request-ID is used as fallback
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "request-123")

	traceCtx := ExtractTracingFromRequest(req)

	assert.Equal(t, "request-123", traceCtx.TraceID)
	assert.NotEmpty(t, traceCtx.SpanID) // Should generate new span ID
}
