# Circuit Breaker Design Guide

A comprehensive guide for implementing circuit breaker patterns in the multi-tenant authentication service. This document covers fault tolerance strategies, implementation patterns, and best practices for building resilient distributed systems.

## Table of Contents

- [Overview](#overview)
- [Circuit Breaker Pattern](#circuit-breaker-pattern)
- [Implementation Strategy](#implementation-strategy)
- [Service Integration](#service-integration)
- [Configuration Management](#configuration-management)
- [Monitoring and Observability](#monitoring-and-observability)
- [Testing Strategies](#testing-strategies)
- [Best Practices](#best-practices)
- [Related Documentation](#related-documentation)

## Overview

In distributed systems, external service failures are inevitable. The circuit breaker pattern provides a way to handle these failures gracefully, preventing cascading failures and improving system resilience. Our implementation uses the `github.com/sony/gobreaker` library to provide robust fault tolerance.

The circuit breaker acts as a proxy between your service and external dependencies. When failures exceed a threshold, the circuit "opens" and immediately returns errors without calling the failing service, allowing it time to recover.

## Circuit Breaker Pattern

### States

A circuit breaker operates in three states:

**Closed State**
- Normal operation mode
- All requests pass through to the external service
- Failure count is tracked and reset after successful requests

**Open State**
- Circuit breaker blocks all requests
- Immediately returns error without calling external service
- Remains open for a configured timeout period

**Half-Open State**
- Limited number of test requests are allowed
- If requests succeed, circuit closes
- If requests fail, circuit opens again

### State Transitions

```
Closed ──[failure threshold exceeded]──> Open
  ↑                                        │
  │                                        │
  └──[test requests succeed]──── Half-Open ←┘
                                    │
                                    └──[test requests fail]──> Open
```

## Implementation Strategy

### Core Configuration

The circuit breaker is configured with these key parameters:

```go
type ServiceConfig struct {
    CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
    MaxRequests    uint32        `yaml:"max_requests"`     // Max requests in half-open state
    Interval       time.Duration `yaml:"interval"`         // Statistical window
    Timeout        time.Duration `yaml:"timeout"`          // Open state duration
    ReadyToTrip    float64       `yaml:"ready_to_trip"`    // Failure ratio threshold
    MaxRetries     int           `yaml:"max_retries"`      // Retry attempts
    RetryDelay     time.Duration `yaml:"retry_delay"`      // Delay between retries
}
```

### Configuration Values

```yaml
services:
  notification:
    base_url: "http://notification-service:8080"
    timeout: "10s"
    circuit_breaker:
      max_requests: 3
      interval: "60s"
      timeout: "30s"
      ready_to_trip: 0.6
      max_retries: 3
      retry_delay: "1s"
  
  subscription:
    base_url: "http://subscription-service:8080"
    timeout: "5s"
    circuit_breaker:
      max_requests: 5
      interval: "30s"
      timeout: "15s"
      ready_to_trip: 0.5
      max_retries: 2
      retry_delay: "500ms"
```

## Service Integration

### Notification Service Client

The notification service client implements circuit breaker protection for message delivery:

```go
type NotificationClient struct {
    httpClient *http.Client
    breaker    *gobreaker.CircuitBreaker
    config     NotificationConfig
    logger     *zap.Logger
}

func NewNotificationClient(config NotificationConfig, logger *zap.Logger) *NotificationClient {
    settings := gobreaker.Settings{
        Name:        "notification-service",
        MaxRequests: config.CircuitBreaker.MaxRequests,
        Interval:    config.CircuitBreaker.Interval,
        Timeout:     config.CircuitBreaker.Timeout,
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
            return counts.Requests >= 3 && failureRatio >= config.CircuitBreaker.ReadyToTrip
        },
        OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
            logger.Info("Circuit breaker state changed",
                zap.String("service", name),
                zap.String("from", from.String()),
                zap.String("to", to.String()),
            )
        },
    }

    return &NotificationClient{
        httpClient: &http.Client{Timeout: config.Timeout},
        breaker:    gobreaker.NewCircuitBreaker(settings),
        config:     config,
        logger:     logger,
    }
}
```

### Making Protected Calls

```go
func (c *NotificationClient) SendNotification(ctx context.Context, req NotificationRequest) (*NotificationResponse, error) {
    result, err := c.breaker.Execute(func() (interface{}, error) {
        return c.sendHTTPRequest(ctx, req)
    })

    if err != nil {
        c.logger.Error("Notification service call failed",
            zap.Error(err),
            zap.String("recipient", req.Recipient),
            zap.String("channel", req.Channel),
        )
        return nil, fmt.Errorf("notification service unavailable: %w", err)
    }

    return result.(*NotificationResponse), nil
}

func (c *NotificationClient) sendHTTPRequest(ctx context.Context, req NotificationRequest) (*NotificationResponse, error) {
    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/notifications/send", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("User-Agent", "auth-service/1.0")

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("HTTP request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 500 {
        return nil, fmt.Errorf("server error: status %d", resp.StatusCode)
    }

    if resp.StatusCode >= 400 {
        return nil, fmt.Errorf("client error: status %d", resp.StatusCode)
    }

    var notificationResp NotificationResponse
    if err := json.NewDecoder(resp.Body).Decode(&notificationResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &notificationResp, nil
}
```

### Subscription Service Client

Similar implementation for subscription validation:

```go
type SubscriptionClient struct {
    httpClient *http.Client
    breaker    *gobreaker.CircuitBreaker
    cache      *cache.Cache
    config     SubscriptionConfig
    logger     *zap.Logger
}

func (c *SubscriptionClient) ValidateFeature(ctx context.Context, clientID, feature string) error {
    cacheKey := fmt.Sprintf("subscription:%s:%s", clientID, feature)
    
    // Try circuit breaker protected call
    result, err := c.breaker.Execute(func() (interface{}, error) {
        return c.validateFeatureHTTP(ctx, clientID, feature)
    })

    if err != nil {
        // Fallback to cache
        if cached, found := c.cache.Get(cacheKey); found {
            if valid, ok := cached.(bool); ok && valid {
                c.logger.Warn("Using cached subscription data due to service failure",
                    zap.String("client_id", clientID),
                    zap.String("feature", feature),
                )
                return nil
            }
        }
        
        return fmt.Errorf("subscription validation failed: %w", err)
    }

    // Cache successful result
    if valid, ok := result.(bool); ok && valid {
        c.cache.Set(cacheKey, true, 5*time.Minute)
    }

    return nil
}
```

## Configuration Management

### Environment-Based Configuration

```go
func LoadServiceConfig() (*ServiceConfig, error) {
    config := &ServiceConfig{}
    
    // Load from file
    if err := viper.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("failed to read config: %w", err)
    }
    
    if err := viper.Unmarshal(config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %w", err)
    }
    
    // Override with environment variables
    viper.AutomaticEnv()
    viper.SetEnvPrefix("AUTH_SERVICE")
    viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    
    return config, nil
}
```

### Validation

```go
func (c *ServiceConfig) Validate() error {
    if c.Services.Notification.BaseURL == "" {
        return errors.New("notification service base URL is required")
    }
    
    if c.Services.Notification.CircuitBreaker.ReadyToTrip <= 0 || c.Services.Notification.CircuitBreaker.ReadyToTrip > 1 {
        return errors.New("ready_to_trip must be between 0 and 1")
    }
    
    if c.Services.Notification.CircuitBreaker.MaxRequests == 0 {
        return errors.New("max_requests must be greater than 0")
    }
    
    return nil
}
```

## Monitoring and Observability

### Metrics Collection

```go
type CircuitBreakerMetrics struct {
    requestsTotal    prometheus.CounterVec
    failuresTotal    prometheus.CounterVec
    stateChanges     prometheus.CounterVec
    stateDuration    prometheus.HistogramVec
}

func NewCircuitBreakerMetrics() *CircuitBreakerMetrics {
    return &CircuitBreakerMetrics{
        requestsTotal: *prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "circuit_breaker_requests_total",
                Help: "Total number of circuit breaker requests",
            },
            []string{"service", "state"},
        ),
        failuresTotal: *prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "circuit_breaker_failures_total",
                Help: "Total number of circuit breaker failures",
            },
            []string{"service"},
        ),
        stateChanges: *prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "circuit_breaker_state_changes_total",
                Help: "Total number of circuit breaker state changes",
            },
            []string{"service", "from_state", "to_state"},
        ),
    }
}
```

### Health Checks

```go
func (c *NotificationClient) HealthCheck() error {
    state := c.breaker.State()
    if state == gobreaker.StateOpen {
        return fmt.Errorf("notification service circuit breaker is open")
    }
    
    // Perform a lightweight health check
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    req, err := http.NewRequestWithContext(ctx, "GET", c.config.BaseURL+"/health", nil)
    if err != nil {
        return err
    }
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
    }
    
    return nil
}
```

## Testing Strategies

### Unit Tests

```go
func TestNotificationClient_CircuitBreaker(t *testing.T) {
    // Setup mock server that fails
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer server.Close()

    config := NotificationConfig{
        BaseURL: server.URL,
        Timeout: time.Second,
        CircuitBreaker: CircuitBreakerConfig{
            MaxRequests:  3,
            Interval:     time.Minute,
            Timeout:      time.Second,
            ReadyToTrip:  0.6,
        },
    }

    client := NewNotificationClient(config, zap.NewNop())

    // Make requests until circuit breaker opens
    var lastErr error
    for i := 0; i < 10; i++ {
        _, lastErr = client.SendNotification(context.Background(), NotificationRequest{
            Recipient: "test@example.com",
            Channel:   "EMAIL",
        })
        
        if lastErr != nil && strings.Contains(lastErr.Error(), "circuit breaker is open") {
            break
        }
    }

    assert.Contains(t, lastErr.Error(), "circuit breaker is open")
}
```

### Integration Tests

```go
func TestCircuitBreakerIntegration(t *testing.T) {
    // Start test services
    notificationServer := startMockNotificationService(t)
    defer notificationServer.Close()

    // Configure client
    config := loadTestConfig()
    config.Services.Notification.BaseURL = notificationServer.URL

    client := NewNotificationClient(config.Services.Notification, zap.NewNop())

    // Test normal operation
    resp, err := client.SendNotification(context.Background(), NotificationRequest{
        Recipient: "test@example.com",
        Channel:   "EMAIL",
    })
    assert.NoError(t, err)
    assert.NotNil(t, resp)

    // Simulate service failure
    notificationServer.SetFailureMode(true)

    // Verify circuit breaker opens
    eventually(t, func() bool {
        _, err := client.SendNotification(context.Background(), NotificationRequest{
            Recipient: "test@example.com",
            Channel:   "EMAIL",
        })
        return err != nil && strings.Contains(err.Error(), "circuit breaker is open")
    }, 5*time.Second)

    // Restore service
    notificationServer.SetFailureMode(false)

    // Verify circuit breaker closes
    eventually(t, func() bool {
        _, err := client.SendNotification(context.Background(), NotificationRequest{
            Recipient: "test@example.com",
            Channel:   "EMAIL",
        })
        return err == nil
    }, 10*time.Second)
}
```

## Best Practices

### Configuration Guidelines

1. **Timeout Values**: Set timeouts shorter than your SLA requirements
2. **Failure Thresholds**: Start with 50-60% failure ratio
3. **Retry Logic**: Implement exponential backoff with jitter
4. **Cache Strategy**: Use cache for fallback data when possible

### Error Handling

```go
func (c *NotificationClient) SendWithFallback(ctx context.Context, req NotificationRequest) error {
    // Try primary notification
    _, err := c.SendNotification(ctx, req)
    if err == nil {
        return nil
    }

    // Log the failure
    c.logger.Warn("Primary notification failed, attempting fallback",
        zap.Error(err),
        zap.String("recipient", req.Recipient),
    )

    // Try fallback method (e.g., email instead of SMS)
    if req.Channel == "SMS" {
        req.Channel = "EMAIL"
        _, fallbackErr := c.SendNotification(ctx, req)
        if fallbackErr == nil {
            return nil
        }
    }

    return fmt.Errorf("all notification methods failed: %w", err)
}
```

### Monitoring Integration

```go
func (c *NotificationClient) instrumentedExecute(ctx context.Context, operation string, fn func() (interface{}, error)) (interface{}, error) {
    start := time.Now()
    
    result, err := c.breaker.Execute(fn)
    
    duration := time.Since(start)
    
    // Record metrics
    c.metrics.requestsTotal.WithLabelValues("notification", c.breaker.State().String()).Inc()
    
    if err != nil {
        c.metrics.failuresTotal.WithLabelValues("notification").Inc()
    }
    
    // Log slow operations
    if duration > time.Second {
        c.logger.Warn("Slow notification operation",
            zap.String("operation", operation),
            zap.Duration("duration", duration),
        )
    }
    
    return result, err
}
```

## Related Documentation

- [Multi-Tenant Auth Service Integration Guide](SAAS_CLIENT_GUIDE.md) - Main integration guide
- [Tenant Authentication Implementation Guide](TENANT_AUTHENTICATION_GUIDE.md) - Tenant authentication details
- [Two-Factor Authentication Guide](TWO_FACTOR_AUTHENTICATION_GUIDE.md) - 2FA implementation
- [Testing Documentation](TESTING.md) - Testing strategies and examples
- [Actuator Documentation](ACTUATOR.md) - Monitoring and health checks

This design guide provides the foundation for building resilient services that can handle external dependencies gracefully. The circuit breaker pattern, when properly implemented, significantly improves system reliability and user experience during service outages. 