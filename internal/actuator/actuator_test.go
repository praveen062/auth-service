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

	assert.Contains(t, stats, "totalRequests")
	assert.Contains(t, stats, "activeRequests")
	assert.Contains(t, stats, "requestsPerSec")
	assert.Contains(t, stats, "errorCount")
	assert.Contains(t, stats, "averageResponse")
}
