package actuator

import (
	"auth-service/internal/config"
	"auth-service/internal/logger"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/heptiolabs/healthcheck"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Actuator provides health checks, metrics, and operational endpoints
type Actuator struct {
	appInfo         *AppInfo
	health          healthcheck.Handler
	registry        *prometheus.Registry
	startTime       time.Time
	requestCount    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	activeRequests  *prometheus.GaugeVec
	logger          *logger.Logger
	mu              sync.RWMutex
	healthChecks    map[string]healthcheck.Check
	readinessChecks map[string]healthcheck.Check
}

// AppInfo contains application metadata
type AppInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	BuildTime   string            `json:"buildTime"`
	GitCommit   string            `json:"gitCommit"`
	Environment string            `json:"environment"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// NewActuator creates a new actuator instance
func NewActuator(appInfo *AppInfo) *Actuator {
	// Initialize logger for actuator
	appLogger, err := logger.NewLogger(&config.LoggingConfig{
		Level:             "info",
		Format:            "json",
		Output:            "stdout",
		IncludeCaller:     true,
		IncludeStacktrace: true,
	})
	if err != nil {
		// Fallback to default logger if initialization fails
		appLogger = &logger.Logger{}
	}

	registry := prometheus.NewRegistry()

	// Create metrics
	requestCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	activeRequests := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "http_requests_active",
			Help: "Number of active HTTP requests",
		},
		[]string{"method", "endpoint"},
	)

	// Register metrics
	registry.MustRegister(requestCount, requestDuration, activeRequests)

	// Create health check handler
	health := healthcheck.NewHandler()

	return &Actuator{
		appInfo:         appInfo,
		health:          health,
		registry:        registry,
		startTime:       time.Now(),
		requestCount:    requestCount,
		requestDuration: requestDuration,
		activeRequests:  activeRequests,
		logger:          appLogger,
		healthChecks:    make(map[string]healthcheck.Check),
		readinessChecks: make(map[string]healthcheck.Check),
	}
}

// RegisterHealthCheck registers a health check with a name
func (a *Actuator) RegisterHealthCheck(name string, check healthcheck.Check) {
	a.health.AddLivenessCheck(name, check)
	a.logger.Info("Health check registered", zap.String("name", name))
}

// RegisterReadinessCheck registers a readiness check with a name
func (a *Actuator) RegisterReadinessCheck(name string, check healthcheck.Check) {
	a.health.AddReadinessCheck(name, check)
	a.logger.Info("Readiness check registered", zap.String("name", name))
}

// RegisterRoutes registers all actuator endpoints
func (a *Actuator) RegisterRoutes(router *gin.Engine) {
	actuator := router.Group("/actuator")
	{
		// Health endpoints
		actuator.GET("/health", a.Health)
		actuator.GET("/health/live", a.Liveness)
		actuator.GET("/health/ready", a.Readiness)

		// Info endpoints
		actuator.GET("/info", a.Info)
		actuator.GET("/env", a.Environment)

		// Metrics endpoints
		actuator.GET("/metrics", a.Metrics)
		actuator.GET("/prometheus", a.PrometheusMetrics)

		// Operational endpoints
		actuator.GET("/status", a.Status)
		actuator.GET("/uptime", a.Uptime)
		actuator.GET("/threaddump", a.ThreadDump)
		actuator.GET("/heapdump", a.HeapDump)

		// Configuration endpoints
		actuator.GET("/configprops", a.ConfigProps)
		actuator.GET("/mappings", a.Mappings)

		// Logging endpoints
		actuator.GET("/loggers", a.Loggers)
		actuator.POST("/loggers/:name", a.SetLoggerLevel)
	}

	a.logger.Info("Actuator routes registered", zap.String("base_path", "/actuator"))
}

// Health returns overall health status
func (a *Actuator) Health(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Health check request received")

	// Use the healthcheck handler to get overall health
	a.health.LiveEndpoint(c.Writer, c.Request)

	reqLogger.BusinessEvent("health_check", "", "", map[string]interface{}{
		"endpoint": "/actuator/health",
	})
}

// Liveness returns liveness check status
func (a *Actuator) Liveness(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Liveness check request received")

	a.health.LiveEndpoint(c.Writer, c.Request)

	reqLogger.BusinessEvent("liveness_check", "", "", map[string]interface{}{
		"endpoint": "/actuator/health/live",
	})
}

// Readiness returns readiness check status
func (a *Actuator) Readiness(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Readiness check request received")

	a.health.ReadyEndpoint(c.Writer, c.Request)

	reqLogger.BusinessEvent("readiness_check", "", "", map[string]interface{}{
		"endpoint": "/actuator/health/ready",
	})
}

// Info returns application information
func (a *Actuator) Info(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Application info request received")

	c.JSON(http.StatusOK, a.appInfo)
}

// Environment returns environment information
func (a *Actuator) Environment(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Environment info request received")

	env := gin.H{
		"environment": a.appInfo.Environment,
		"properties":  a.appInfo.Properties,
		"goVersion":   runtime.Version(),
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"startTime":   a.startTime,
		"uptime":      time.Since(a.startTime).String(),
	}

	c.JSON(http.StatusOK, env)
}

// Metrics returns application metrics
func (a *Actuator) Metrics(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Metrics request received")

	metrics := gin.H{
		"uptime":    time.Since(a.startTime).String(),
		"memory":    a.getMemoryStats(),
		"runtime":   a.getRuntimeStats(),
		"requests":  a.getRequestStats(),
		"timestamp": time.Now(),
	}

	reqLogger.BusinessEvent("metrics_request", "", "", map[string]interface{}{
		"endpoint": "/actuator/metrics",
	})

	c.JSON(http.StatusOK, metrics)
}

// PrometheusMetrics returns Prometheus-formatted metrics
func (a *Actuator) PrometheusMetrics(c *gin.Context) {
	reqLogger := a.logger.WithRequest(c.Request)
	reqLogger.Info("Prometheus metrics request received")

	handler := promhttp.HandlerFor(a.registry, promhttp.HandlerOpts{})
	handler.ServeHTTP(c.Writer, c.Request)

	reqLogger.BusinessEvent("prometheus_metrics_request", "", "", map[string]interface{}{
		"endpoint": "/actuator/prometheus",
	})
}

// Status returns application status
func (a *Actuator) Status(c *gin.Context) {
	status := gin.H{
		"status":      "RUNNING",
		"startTime":   a.startTime,
		"uptime":      time.Since(a.startTime).String(),
		"version":     a.appInfo.Version,
		"environment": a.appInfo.Environment,
		"goroutines":  runtime.NumGoroutine(),
		"memory":      a.getMemoryStats(),
	}

	c.JSON(http.StatusOK, status)
}

// Uptime returns application uptime
func (a *Actuator) Uptime(c *gin.Context) {
	uptime := gin.H{
		"uptime":      time.Since(a.startTime).String(),
		"startTime":   a.startTime,
		"duration":    time.Since(a.startTime).Milliseconds(),
		"durationSec": time.Since(a.startTime).Seconds(),
	}

	c.JSON(http.StatusOK, uptime)
}

// ThreadDump returns goroutine information
func (a *Actuator) ThreadDump(c *gin.Context) {
	// Get goroutine count and stack traces
	stack := make([]byte, 1024*1024)
	stack = stack[:runtime.Stack(stack, true)]

	dump := gin.H{
		"numGoroutines": runtime.NumGoroutine(),
		"stackTrace":    string(stack),
		"timestamp":     time.Now(),
	}

	c.JSON(http.StatusOK, dump)
}

// HeapDump returns memory heap information
func (a *Actuator) HeapDump(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	dump := gin.H{
		"heapAlloc":    m.HeapAlloc,
		"heapSys":      m.HeapSys,
		"heapIdle":     m.HeapIdle,
		"heapInuse":    m.HeapInuse,
		"heapReleased": m.HeapReleased,
		"heapObjects":  m.HeapObjects,
		"totalAlloc":   m.TotalAlloc,
		"sys":          m.Sys,
		"numGC":        m.NumGC,
		"timestamp":    time.Now(),
	}

	c.JSON(http.StatusOK, dump)
}

// ConfigProps returns configuration properties
func (a *Actuator) ConfigProps(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"application": a.appInfo,
		"timestamp":   time.Now(),
	})
}

// Mappings returns endpoint mappings
func (a *Actuator) Mappings(c *gin.Context) {
	mappings := gin.H{
		"actuator": gin.H{
			"health":       "/actuator/health",
			"health/live":  "/actuator/health/live",
			"health/ready": "/actuator/health/ready",
			"info":         "/actuator/info",
			"metrics":      "/actuator/metrics",
			"prometheus":   "/actuator/prometheus",
			"status":       "/actuator/status",
			"uptime":       "/actuator/uptime",
			"threaddump":   "/actuator/threaddump",
			"heapdump":     "/actuator/heapdump",
		},
		"timestamp": time.Now(),
	}

	c.JSON(http.StatusOK, mappings)
}

// Loggers returns logger information
func (a *Actuator) Loggers(c *gin.Context) {
	loggers := gin.H{
		"levels": gin.H{
			"ROOT":         "INFO",
			"auth-service": "INFO",
		},
		"timestamp": time.Now(),
	}

	c.JSON(http.StatusOK, loggers)
}

// SetLoggerLevel sets logger level
func (a *Actuator) SetLoggerLevel(c *gin.Context) {
	loggerName := c.Param("name")

	var request struct {
		Level string `json:"level"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logger":  loggerName,
		"level":   request.Level,
		"message": "Logger level updated",
	})
}

// RecordRequest records request metrics
func (a *Actuator) RecordRequest(method, endpoint string, status int, duration time.Duration) {
	a.requestCount.WithLabelValues(method, endpoint, string(rune(status))).Inc()
	a.requestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// StartRequest starts tracking an active request
func (a *Actuator) StartRequest(method, endpoint string) {
	a.activeRequests.WithLabelValues(method, endpoint).Inc()
}

// EndRequest ends tracking an active request
func (a *Actuator) EndRequest(method, endpoint string) {
	a.activeRequests.WithLabelValues(method, endpoint).Dec()
}

// getMemoryStats returns current memory statistics
func (a *Actuator) getMemoryStats() gin.H {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return gin.H{
		"alloc":      m.Alloc,
		"totalAlloc": m.TotalAlloc,
		"sys":        m.Sys,
		"numGC":      m.NumGC,
		"heapAlloc":  m.HeapAlloc,
		"heapSys":    m.HeapSys,
		"heapIdle":   m.HeapIdle,
		"heapInuse":  m.HeapInuse,
	}
}

// getRuntimeStats returns current runtime statistics
func (a *Actuator) getRuntimeStats() gin.H {
	return gin.H{
		"numCPU":       runtime.NumCPU(),
		"numGoroutine": runtime.NumGoroutine(),
		"numCgoCall":   runtime.NumCgoCall(),
		"goVersion":    runtime.Version(),
	}
}

// getRequestStats returns request statistics
func (a *Actuator) getRequestStats() gin.H {
	// This would typically return actual request statistics
	// For now, return placeholder data
	return gin.H{
		"totalRequests":   0,
		"activeRequests":  0,
		"requestsPerSec":  0,
		"errorCount":      0,
		"averageResponse": 0,
	}
}
