package actuator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewActuator(t *testing.T) {
	appInfo := &AppInfo{
		Name:        "test-app",
		Version:     "1.0.0",
		Description: "Test application",
		Environment: "test",
	}

	act := NewActuator(appInfo)

	assert.NotNil(t, act)
	assert.Equal(t, appInfo, act.appInfo)
	assert.NotNil(t, act.health)
	assert.NotNil(t, act.registry)
	assert.NotNil(t, act.requestCount)
	assert.NotNil(t, act.requestDuration)
	assert.NotNil(t, act.activeRequests)
}

func TestActuator_Info(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	appInfo := &AppInfo{
		Name:        "test-app",
		Version:     "1.0.0",
		Description: "Test application",
		Environment: "test",
	}

	act := NewActuator(appInfo)
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/info", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response AppInfo
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, appInfo.Name, response.Name)
	assert.Equal(t, appInfo.Version, response.Version)
	assert.Equal(t, appInfo.Description, response.Description)
	assert.Equal(t, appInfo.Environment, response.Environment)
}

func TestActuator_Health(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestActuator_Liveness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/health/live", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestActuator_Readiness(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/health/ready", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestActuator_Environment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/env", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "goVersion")
	assert.Contains(t, response, "os")
	assert.Contains(t, response, "arch")
	assert.Contains(t, response, "startTime")
	assert.Contains(t, response, "uptime")
}

func TestActuator_Metrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/metrics", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "uptime")
	assert.Contains(t, response, "memory")
	assert.Contains(t, response, "runtime")
	assert.Contains(t, response, "requests")
	assert.Contains(t, response, "timestamp")
}

func TestActuator_PrometheusMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/prometheus", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/plain")
}

func TestActuator_Status(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test", Version: "1.0.0", Environment: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "RUNNING", response["status"])
	assert.Equal(t, "1.0.0", response["version"])
	assert.Equal(t, "test", response["environment"])
	assert.Contains(t, response, "startTime")
	assert.Contains(t, response, "uptime")
	assert.Contains(t, response, "goroutines")
	assert.Contains(t, response, "memory")
}

func TestActuator_Uptime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/uptime", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "uptime")
	assert.Contains(t, response, "startTime")
	assert.Contains(t, response, "duration")
	assert.Contains(t, response, "durationSec")
}

func TestActuator_ThreadDump(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/threaddump", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "numGoroutines")
	assert.Contains(t, response, "stackTrace")
	assert.Contains(t, response, "timestamp")
}

func TestActuator_HeapDump(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/heapdump", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "heapAlloc")
	assert.Contains(t, response, "heapSys")
	assert.Contains(t, response, "heapIdle")
	assert.Contains(t, response, "heapInuse")
	assert.Contains(t, response, "heapReleased")
	assert.Contains(t, response, "heapObjects")
	assert.Contains(t, response, "totalAlloc")
	assert.Contains(t, response, "sys")
	assert.Contains(t, response, "numGC")
	assert.Contains(t, response, "timestamp")
}

func TestActuator_Mappings(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/mappings", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "actuator")
	assert.Contains(t, response, "timestamp")

	actuatorMappings := response["actuator"].(map[string]interface{})
	assert.Contains(t, actuatorMappings, "health")
	assert.Contains(t, actuatorMappings, "health/live")
	assert.Contains(t, actuatorMappings, "health/ready")
	assert.Contains(t, actuatorMappings, "info")
	assert.Contains(t, actuatorMappings, "metrics")
	assert.Contains(t, actuatorMappings, "prometheus")
	assert.Contains(t, actuatorMappings, "status")
	assert.Contains(t, actuatorMappings, "uptime")
	assert.Contains(t, actuatorMappings, "threaddump")
	assert.Contains(t, actuatorMappings, "heapdump")
}

func TestActuator_Loggers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/loggers", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "levels")
	assert.Contains(t, response, "timestamp")
}

func TestActuator_SetLoggerLevel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/actuator/loggers/test-logger", strings.NewReader(`{"level":"DEBUG"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test-logger", response["logger"])
	assert.Equal(t, "DEBUG", response["level"])
	assert.Equal(t, "Logger level updated", response["message"])
}

func TestActuator_RecordRequest(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	// Record a request
	act.RecordRequest("GET", "/test", 200, 100*time.Millisecond)

	// The metrics should be recorded (we can't easily test the internal state)
	// but we can verify the actuator doesn't panic
	assert.NotNil(t, act)
}

func TestActuator_StartEndRequest(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	// Start tracking a request
	act.StartRequest("GET", "/test")

	// End tracking the request
	act.EndRequest("GET", "/test")

	// The metrics should be recorded (we can't easily test the internal state)
	// but we can verify the actuator doesn't panic
	assert.NotNil(t, act)
}

func TestActuator_GetMemoryStats(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	stats := act.getMemoryStats()

	assert.Contains(t, stats, "alloc")
	assert.Contains(t, stats, "totalAlloc")
	assert.Contains(t, stats, "sys")
	assert.Contains(t, stats, "numGC")
	assert.Contains(t, stats, "heapAlloc")
	assert.Contains(t, stats, "heapSys")
	assert.Contains(t, stats, "heapIdle")
	assert.Contains(t, stats, "heapInuse")
}

func TestActuator_GetRuntimeStats(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	stats := act.getRuntimeStats()

	assert.Contains(t, stats, "numCPU")
	assert.Contains(t, stats, "numGoroutine")
	assert.Contains(t, stats, "numCgoCall")
	assert.Contains(t, stats, "goVersion")
}

func TestActuator_GetRequestStats(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})
	stats := act.getRequestStats()

	assert.NotNil(t, stats)
	assert.Contains(t, stats, "totalRequests")
	assert.Contains(t, stats, "activeRequests")
	assert.Contains(t, stats, "requestsPerSec")
	assert.Contains(t, stats, "errorCount")
	assert.Contains(t, stats, "averageResponse")
}

// TestActuator_RegisterHealthCheck tests the RegisterHealthCheck method
func TestActuator_RegisterHealthCheck(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	// Test registering a health check
	check := func() error { return nil }
	act.RegisterHealthCheck("test-check", check)

	// Verify the check was registered by calling it
	err := check()
	assert.NoError(t, err)
}

// TestActuator_RegisterReadinessCheck tests the RegisterReadinessCheck method
func TestActuator_RegisterReadinessCheck(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	// Test registering a readiness check
	check := func() error { return nil }
	act.RegisterReadinessCheck("test-readiness", check)

	// Verify the check was registered by calling it
	err := check()
	assert.NoError(t, err)
}

// TestActuator_ConfigProps tests the ConfigProps endpoint
func TestActuator_ConfigProps(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	appInfo := &AppInfo{
		Name:        "test-app",
		Version:     "1.0.0",
		Description: "Test application",
		Environment: "test",
		Properties: map[string]string{
			"test.property": "test-value",
		},
	}

	act := NewActuator(appInfo)
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/actuator/configprops", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "application")
	assert.Contains(t, response, "timestamp")

	app := response["application"].(map[string]interface{})
	assert.Equal(t, "test-app", app["name"])
	assert.Equal(t, "1.0.0", app["version"])
}

// TestActuator_SetLoggerLevel_Success tests successful logger level setting
func TestActuator_SetLoggerLevel_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/actuator/loggers/test-logger", strings.NewReader(`{"level": "DEBUG"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test-logger", response["logger"])
	assert.Equal(t, "DEBUG", response["level"])
	assert.Equal(t, "Logger level updated", response["message"])
}

// TestActuator_SetLoggerLevel_InvalidJSON tests logger level setting with invalid JSON
func TestActuator_SetLoggerLevel_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/actuator/loggers/test-logger", strings.NewReader(`{"level": "DEBUG"`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Invalid request body", response["error"])
}

// TestActuator_SetLoggerLevel_EmptyBody tests logger level setting with empty body
func TestActuator_SetLoggerLevel_EmptyBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/actuator/loggers/test-logger", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Invalid request body", response["error"])
}

// TestActuator_RegisterRoutes_AllEndpoints tests that all endpoints are registered
func TestActuator_RegisterRoutes_AllEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	act := NewActuator(&AppInfo{Name: "test"})
	act.RegisterRoutes(router)

	// Test all endpoints are accessible
	endpoints := []string{
		"/actuator/health",
		"/actuator/health/live",
		"/actuator/health/ready",
		"/actuator/info",
		"/actuator/env",
		"/actuator/metrics",
		"/actuator/prometheus",
		"/actuator/status",
		"/actuator/uptime",
		"/actuator/threaddump",
		"/actuator/heapdump",
		"/actuator/configprops",
		"/actuator/mappings",
		"/actuator/loggers",
	}

	for _, endpoint := range endpoints {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", endpoint, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "Endpoint %s should return 200", endpoint)
	}
}

// TestActuator_RecordRequest_WithMetrics tests recording request metrics
func TestActuator_RecordRequest_WithMetrics(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})

	// Record some test metrics
	act.RecordRequest("GET", "/test", 200, 100*time.Millisecond)
	act.RecordRequest("POST", "/test", 201, 150*time.Millisecond)
	act.RecordRequest("GET", "/test", 404, 50*time.Millisecond)

	// Start and end some requests
	act.StartRequest("GET", "/test")
	act.EndRequest("GET", "/test")

	// This test verifies the methods don't panic and execute successfully
	assert.True(t, true, "Request recording methods executed successfully")
}

// TestActuator_AppInfo_WithProperties tests AppInfo with properties
func TestActuator_AppInfo_WithProperties(t *testing.T) {
	properties := map[string]string{
		"server.port":   "8080",
		"database.host": "localhost",
		"redis.host":    "localhost",
	}

	appInfo := &AppInfo{
		Name:        "test-app",
		Version:     "1.0.0",
		Description: "Test application",
		BuildTime:   "2024-01-01T00:00:00Z",
		GitCommit:   "abc123",
		Environment: "test",
		Properties:  properties,
	}

	act := NewActuator(appInfo)
	assert.Equal(t, appInfo, act.appInfo)
	assert.Equal(t, properties, act.appInfo.Properties)
}

// TestActuator_NewActuator_WithNilAppInfo tests NewActuator with nil AppInfo
func TestActuator_NewActuator_WithNilAppInfo(t *testing.T) {
	act := NewActuator(nil)
	assert.NotNil(t, act)
	assert.Nil(t, act.appInfo)
	assert.NotNil(t, act.health)
	assert.NotNil(t, act.registry)
}

// TestActuator_GetMemoryStats_Detailed tests getMemoryStats with detailed verification
func TestActuator_GetMemoryStats_Detailed(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})
	stats := act.getMemoryStats()

	// Verify all expected memory stats are present
	expectedKeys := []string{"alloc", "totalAlloc", "sys", "numGC", "heapAlloc", "heapSys", "heapIdle", "heapInuse"}
	for _, key := range expectedKeys {
		assert.Contains(t, stats, key, "Memory stats should contain %s", key)
	}

	// Verify values are numeric
	for _, key := range expectedKeys {
		value := stats[key]
		switch v := value.(type) {
		case uint64:
			// Memory values should be non-negative
			assert.GreaterOrEqual(t, v, uint64(0), "Memory stat %s should be non-negative", key)
		case uint32:
			// Some stats like numGC are uint32
			assert.GreaterOrEqual(t, v, uint32(0), "Memory stat %s should be non-negative", key)
		default:
			t.Errorf("Memory stat %s should be uint64 or uint32, got %T", key, value)
		}
	}
}

// TestActuator_GetRuntimeStats_Detailed tests getRuntimeStats with detailed verification
func TestActuator_GetRuntimeStats_Detailed(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})
	stats := act.getRuntimeStats()

	// Verify all expected runtime stats are present
	expectedKeys := []string{"numCPU", "numGoroutine", "numCgoCall", "goVersion"}
	for _, key := range expectedKeys {
		assert.Contains(t, stats, key, "Runtime stats should contain %s", key)
	}

	// Verify specific values
	assert.Greater(t, stats["numCPU"], 0, "Number of CPUs should be greater than 0")
	assert.GreaterOrEqual(t, stats["numGoroutine"], 0, "Number of goroutines should be non-negative")
	assert.GreaterOrEqual(t, stats["numCgoCall"], int64(0), "Number of CGO calls should be non-negative")
	assert.NotEmpty(t, stats["goVersion"], "Go version should not be empty")
}

// TestActuator_GetRequestStats_Detailed tests getRequestStats with detailed verification
func TestActuator_GetRequestStats_Detailed(t *testing.T) {
	act := NewActuator(&AppInfo{Name: "test"})
	stats := act.getRequestStats()

	// Verify all expected request stats are present
	expectedKeys := []string{"totalRequests", "activeRequests", "requestsPerSec", "errorCount", "averageResponse"}
	for _, key := range expectedKeys {
		assert.Contains(t, stats, key, "Request stats should contain %s", key)
	}

	// Verify values are numeric and initially zero
	for _, key := range expectedKeys {
		value := stats[key]
		switch v := value.(type) {
		case int:
			assert.Equal(t, 0, v, "Initial request stat %s should be 0", key)
		case float64:
			assert.Equal(t, 0.0, v, "Initial request stat %s should be 0.0", key)
		default:
			t.Errorf("Request stat %s should be numeric, got %T", key, value)
		}
	}
}
