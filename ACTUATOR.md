# Actuator System Documentation

This document provides comprehensive information about the actuator system integrated into the auth-service, which provides health checks, metrics, and operational insights similar to Spring Boot Actuator.

## Overview

The actuator system provides production-ready monitoring and management capabilities for the auth-service, including:

- **Health Checks**: Application and component health monitoring
- **Metrics**: Application performance and runtime metrics
- **Operational Endpoints**: Runtime information and debugging tools
- **Prometheus Integration**: Standard metrics format for monitoring systems

## Architecture

The actuator system is built using:

- **heptiolabs/healthcheck**: For health check management
- **Prometheus Client**: For metrics collection and exposure
- **Gin Middleware**: For request tracking and metrics collection
- **Runtime Package**: For Go runtime statistics

## Configuration

### Actuator Configuration

The actuator can be configured through the `configs/config.yaml` file:

```yaml
actuator:
  enabled: true
  base_path: "/actuator"
  health:
    enabled: true
    timeout: "5s"
    memory_threshold_percent: 90
    goroutine_threshold: 1000
    disk_space_threshold_gb: 1
  metrics:
    enabled: true
    prometheus_enabled: true
    request_tracking: true
  endpoints:
    health: true
    info: true
    metrics: true
    prometheus: true
    status: true
    uptime: true
    threaddump: true
    heapdump: true
    configprops: true
    mappings: true
    loggers: true
  security:
    health_public: true
    metrics_public: true
    sensitive_endpoints_restricted: true
    allowed_ips:
      - "127.0.0.1"
      - "::1"
```

### Environment Variables

The actuator can also be configured through environment variables:

```bash
# Enable actuator
export ACTUATOR_ENABLED=true

# Base path
export ACTUATOR_BASE_PATH="/actuator"

# Health check settings
export ACTUATOR_HEALTH_ENABLED=true
export ACTUATOR_HEALTH_TIMEOUT="5s"
export ACTUATOR_HEALTH_MEMORY_THRESHOLD_PERCENT=90
export ACTUATOR_HEALTH_GOROUTINE_THRESHOLD=1000
export ACTUATOR_HEALTH_DISK_SPACE_THRESHOLD_GB=1

# Metrics settings
export ACTUATOR_METRICS_ENABLED=true
export ACTUATOR_METRICS_PROMETHEUS_ENABLED=true
export ACTUATOR_METRICS_REQUEST_TRACKING=true

# Endpoint settings
export ACTUATOR_ENDPOINTS_HEALTH=true
export ACTUATOR_ENDPOINTS_INFO=true
export ACTUATOR_ENDPOINTS_METRICS=true
export ACTUATOR_ENDPOINTS_PROMETHEUS=true
export ACTUATOR_ENDPOINTS_STATUS=true
export ACTUATOR_ENDPOINTS_UPTIME=true
export ACTUATOR_ENDPOINTS_THREAD_DUMP=true
export ACTUATOR_ENDPOINTS_HEAP_DUMP=true
export ACTUATOR_ENDPOINTS_CONFIG_PROPS=true
export ACTUATOR_ENDPOINTS_MAPPINGS=true
export ACTUATOR_ENDPOINTS_LOGGERS=true

# Security settings
export ACTUATOR_SECURITY_HEALTH_PUBLIC=true
export ACTUATOR_SECURITY_METRICS_PUBLIC=true
export ACTUATOR_SECURITY_SENSITIVE_ENDPOINTS_RESTRICTED=true
export ACTUATOR_SECURITY_ALLOWED_IPS="127.0.0.1,::1"
```

## Endpoints

### Health Endpoints

#### Overall Health
```
GET /actuator/health
```

Returns the overall health status of the application and all registered health checks.

**Response:**
```json
{
  "status": "UP",
  "details": {
    "memory": {
      "status": "UP",
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "goroutines": {
      "status": "UP",
      "timestamp": "2024-01-01T00:00:00Z"
    },
    "disk": {
      "status": "UP",
      "timestamp": "2024-01-01T00:00:00Z"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Liveness Check
```
GET /actuator/health/live
```

Returns the liveness status of the application. Used by Kubernetes and other orchestration systems.

#### Readiness Check
```
GET /actuator/health/ready
```

Returns the readiness status of the application. Used to determine if the application is ready to receive traffic.

### Info Endpoints

#### Application Information
```
GET /actuator/info
```

Returns application metadata and build information.

**Response:**
```json
{
  "name": "auth-service",
  "version": "1.0.0",
  "description": "Multi-Tenant OAuth Service",
  "buildTime": "2024-01-01T00:00:00Z",
  "gitCommit": "development",
  "environment": "development",
  "properties": {
    "server.port": "8080",
    "database.host": "localhost",
    "redis.host": "localhost"
  }
}
```

#### Environment Information
```
GET /actuator/env
```

Returns runtime environment information.

**Response:**
```json
{
  "goVersion": "go1.21.0",
  "os": "darwin",
  "arch": "amd64",
  "startTime": "2024-01-01T00:00:00Z",
  "uptime": "1h2m3s",
  "numCPU": 8,
  "numGoroutine": 15
}
```

### Metrics Endpoints

#### Application Metrics
```
GET /actuator/metrics
```

Returns application metrics in JSON format.

**Response:**
```json
{
  "uptime": "1h2m3s",
  "memory": {
    "alloc": 1234567,
    "totalAlloc": 9876543,
    "sys": 2345678,
    "numGC": 5,
    "heapAlloc": 1234567,
    "heapSys": 2345678,
    "heapIdle": 1111111,
    "heapInuse": 1234567
  },
  "runtime": {
    "numCPU": 8,
    "numGoroutine": 15,
    "numCgoCall": 0,
    "goVersion": "go1.21.0"
  },
  "requests": {
    "totalRequests": 1000,
    "activeRequests": 5,
    "requestsPerSec": 10,
    "errorCount": 2,
    "averageResponse": 150
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Prometheus Metrics
```
GET /actuator/prometheus
```

Returns metrics in Prometheus format for integration with monitoring systems.

**Response:**
```
# HELP http_requests_total Total number of HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",endpoint="/api/v1/auth/login",status="200"} 100
http_requests_total{method="POST",endpoint="/api/v1/auth/register",status="201"} 50

# HELP http_request_duration_seconds HTTP request duration in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",endpoint="/api/v1/auth/login",le="0.1"} 80
http_request_duration_seconds_bucket{method="GET",endpoint="/api/v1/auth/login",le="0.5"} 95
http_request_duration_seconds_bucket{method="GET",endpoint="/api/v1/auth/login",le="1"} 100

# HELP http_requests_active Number of active HTTP requests
# TYPE http_requests_active gauge
http_requests_active{method="GET",endpoint="/api/v1/auth/login"} 2
```

### Operational Endpoints

#### Application Status
```
GET /actuator/status
```

Returns the current application status.

**Response:**
```json
{
  "status": "RUNNING",
  "startTime": "2024-01-01T00:00:00Z",
  "uptime": "1h2m3s",
  "version": "1.0.0",
  "environment": "development",
  "goroutines": 15,
  "memory": {
    "alloc": 1234567,
    "totalAlloc": 9876543,
    "sys": 2345678,
    "numGC": 5,
    "heapAlloc": 1234567,
    "heapSys": 2345678,
    "heapIdle": 1111111,
    "heapInuse": 1234567
  }
}
```

#### Uptime Information
```
GET /actuator/uptime
```

Returns detailed uptime information.

**Response:**
```json
{
  "uptime": "1h2m3s",
  "startTime": "2024-01-01T00:00:00Z",
  "duration": 3723000,
  "durationSec": 3723
}
```

#### Thread Dump
```
GET /actuator/threaddump
```

Returns goroutine information and stack traces.

**Response:**
```json
{
  "numGoroutines": 15,
  "stackTrace": "goroutine 1 [running]:\nmain.main()\n\t/...",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Heap Dump
```
GET /actuator/heapdump
```

Returns memory heap information.

**Response:**
```json
{
  "heapAlloc": 1234567,
  "heapSys": 2345678,
  "heapIdle": 1111111,
  "heapInuse": 1234567,
  "heapReleased": 500000,
  "heapObjects": 10000,
  "totalAlloc": 9876543,
  "sys": 2345678,
  "numGC": 5,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Configuration Endpoints

#### Configuration Properties
```
GET /actuator/configprops
```

Returns configuration properties.

#### Endpoint Mappings
```
GET /actuator/mappings
```

Returns all registered endpoint mappings.

### Logging Endpoints

#### Logger Information
```
GET /actuator/loggers
```

Returns logger configurations.

**Response:**
```json
{
  "levels": {
    "ROOT": "INFO",
    "auth-service": "INFO"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Set Logger Level
```
POST /actuator/loggers/{name}
```

Sets the log level for a specific logger.

**Request Body:**
```json
{
  "level": "DEBUG"
}
```

**Response:**
```json
{
  "logger": "auth-service",
  "level": "DEBUG",
  "message": "Logger level updated"
}
```

## Health Checks

### Built-in Health Checks

The actuator includes several built-in health checks:

#### Memory Health Check
Monitors memory usage and fails if it exceeds the configured threshold.

```go
act.RegisterHealthCheck("memory", actuator.MemoryHealthCheck(90))
```

#### Goroutine Health Check
Monitors the number of goroutines and fails if it exceeds the configured threshold.

```go
act.RegisterHealthCheck("goroutines", actuator.GoroutineHealthCheck(1000))
```

#### Disk Space Health Check
Monitors available disk space and fails if it falls below the configured threshold.

```go
act.RegisterHealthCheck("disk", actuator.DiskSpaceHealthCheck(1))
```

### Custom Health Checks

You can create custom health checks for your application:

```go
// Database health check
act.RegisterHealthCheck("database", actuator.DatabaseHealthCheck(db))

// Redis health check
act.RegisterHealthCheck("redis", actuator.RedisHealthCheck(redisClient))

// Custom health check
act.RegisterHealthCheck("custom", actuator.CustomHealthCheck(func() error {
    // Your custom health check logic
    return nil
}))

// Health check with timeout
act.RegisterHealthCheck("timeout", actuator.TimeoutHealthCheck(
    actuator.CustomHealthCheck(func() error {
        // Your health check logic
        return nil
    }),
    5*time.Second,
))
```

## Metrics

### Request Metrics

The actuator automatically tracks HTTP request metrics:

- **Total Requests**: Counter of all HTTP requests
- **Request Duration**: Histogram of request response times
- **Active Requests**: Gauge of currently active requests
- **Error Count**: Counter of failed requests

### Runtime Metrics

The actuator provides Go runtime metrics:

- **Memory Usage**: Heap and system memory statistics
- **Goroutine Count**: Number of active goroutines
- **Garbage Collection**: GC statistics
- **CPU Usage**: CPU and CGO call statistics

### Custom Metrics

You can add custom metrics to the actuator:

```go
// Record custom metrics
act.RecordRequest("GET", "/api/v1/auth/login", 200, 150*time.Millisecond)

// Track active requests
act.StartRequest("GET", "/api/v1/auth/login")
// ... process request ...
act.EndRequest("GET", "/api/v1/auth/login")
```

## Integration

### Kubernetes Integration

The actuator endpoints can be used with Kubernetes health checks:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        livenessProbe:
          httpGet:
            path: /actuator/health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Prometheus Integration

The actuator exposes Prometheus metrics that can be scraped:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/actuator/prometheus'
    scrape_interval: 15s
```

### Grafana Dashboard

You can create Grafana dashboards using the Prometheus metrics:

- **Request Rate**: `rate(http_requests_total[5m])`
- **Error Rate**: `rate(http_requests_total{status=~"5.."}[5m])`
- **Response Time**: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`
- **Memory Usage**: `go_memstats_heap_alloc_bytes`

## Security

### Endpoint Security

The actuator provides configurable security for different endpoint types:

- **Public Endpoints**: Health and metrics endpoints can be made public
- **Restricted Endpoints**: Sensitive endpoints (threaddump, heapdump) are restricted by default
- **IP Restrictions**: Endpoints can be restricted to specific IP addresses

### Authentication

For production environments, consider adding authentication to sensitive actuator endpoints:

```go
// Add authentication middleware to sensitive endpoints
actuator.GET("/threaddump", authMiddleware, a.ThreadDump)
actuator.GET("/heapdump", authMiddleware, a.HeapDump)
```

## Monitoring and Alerting

### Health Check Alerts

Set up alerts for health check failures:

```yaml
# alertmanager.yml
groups:
  - name: auth-service
    rules:
      - alert: AuthServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth service is down"
          description: "Auth service has been down for more than 1 minute"

      - alert: HighMemoryUsage
        expr: go_memstats_heap_alloc_bytes / go_memstats_heap_sys_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90%"
```

### Performance Alerts

Set up alerts for performance issues:

```yaml
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate"
          description: "Error rate is above 10%"

      - alert: SlowResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow response time"
          description: "95th percentile response time is above 1 second"
```

## Best Practices

### Health Check Design

1. **Keep health checks fast**: Health checks should complete quickly (< 1 second)
2. **Use timeouts**: Always use timeouts for external dependencies
3. **Fail fast**: Return errors immediately for critical failures
4. **Be specific**: Include detailed error messages for debugging

### Metrics Design

1. **Use meaningful names**: Choose descriptive metric names
2. **Add labels carefully**: Use labels for dimensions, not cardinality
3. **Monitor cardinality**: Avoid high-cardinality labels
4. **Use appropriate types**: Use counters, gauges, and histograms appropriately

### Security Considerations

1. **Restrict sensitive endpoints**: Limit access to debugging endpoints
2. **Use authentication**: Add authentication for production environments
3. **Monitor access**: Log access to sensitive endpoints
4. **Use HTTPS**: Always use HTTPS in production

### Performance Considerations

1. **Minimize overhead**: Keep actuator overhead minimal
2. **Use caching**: Cache expensive health checks
3. **Batch metrics**: Batch metric updates when possible
4. **Monitor actuator**: Monitor the actuator itself

## Troubleshooting

### Common Issues

1. **Health checks failing**: Check external dependencies and timeouts
2. **High memory usage**: Monitor memory metrics and adjust thresholds
3. **Slow response times**: Check request duration metrics
4. **High error rates**: Monitor error metrics and logs

### Debugging

1. **Use thread dump**: Get goroutine information for debugging
2. **Use heap dump**: Analyze memory usage patterns
3. **Check metrics**: Use metrics to identify performance bottlenecks
4. **Monitor logs**: Check application logs for errors

## Testing

The actuator includes comprehensive tests:

```bash
# Run actuator tests
go test ./internal/actuator/... -v

# Run middleware tests
go test ./internal/middleware/... -v

# Run all tests with coverage
go test ./... -cover
```

## Conclusion

The actuator system provides comprehensive monitoring and management capabilities for the auth-service. It enables:

- **Operational visibility**: Real-time health and performance monitoring
- **Production readiness**: Kubernetes and Prometheus integration
- **Debugging capabilities**: Thread dumps and heap analysis
- **Security**: Configurable access controls and authentication

By following the best practices outlined in this document, you can effectively use the actuator system to monitor and manage your auth-service in production environments. 