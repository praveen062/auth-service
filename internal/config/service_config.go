package config

import (
	"time"

	"github.com/sony/gobreaker"
)

// ServiceConfig holds configuration for external services
type ServiceConfig struct {
	NotificationService NotificationServiceConfig `yaml:"notification_service" json:"notification_service"`
	SubscriptionService SubscriptionServiceConfig `yaml:"subscription_service" json:"subscription_service"`
}

// NotificationServiceConfig holds Notification Service configuration
type NotificationServiceConfig struct {
	BaseURL        string               `yaml:"base_url" json:"base_url"`
	Timeout        time.Duration        `yaml:"timeout" json:"timeout"`
	MaxRetries     int                  `yaml:"max_retries" json:"max_retries"`
	RetryDelay     time.Duration        `yaml:"retry_delay" json:"retry_delay"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// SubscriptionServiceConfig holds Subscription Service configuration
type SubscriptionServiceConfig struct {
	BaseURL        string               `yaml:"base_url" json:"base_url"`
	Timeout        time.Duration        `yaml:"timeout" json:"timeout"`
	MaxRetries     int                  `yaml:"max_retries" json:"max_retries"`
	RetryDelay     time.Duration        `yaml:"retry_delay" json:"retry_delay"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxFailures   uint32        `yaml:"max_failures" json:"max_failures"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	Interval      time.Duration `yaml:"interval" json:"interval"`
	ReadyToTrip   string        `yaml:"ready_to_trip" json:"ready_to_trip"` // "consecutive" or "count"
	OnStateChange bool          `yaml:"on_state_change" json:"on_state_change"`
}

// DefaultServiceConfig returns default service configuration
func DefaultServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		NotificationService: NotificationServiceConfig{
			BaseURL:    "http://notification-service:8080",
			Timeout:    10 * time.Second,
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
			CircuitBreaker: CircuitBreakerConfig{
				MaxFailures:   5,
				Timeout:       30 * time.Second,
				Interval:      60 * time.Second,
				ReadyToTrip:   "consecutive",
				OnStateChange: true,
			},
		},
		SubscriptionService: SubscriptionServiceConfig{
			BaseURL:    "http://subscription-service:8080",
			Timeout:    5 * time.Second,
			MaxRetries: 3,
			RetryDelay: 1 * time.Second,
			CircuitBreaker: CircuitBreakerConfig{
				MaxFailures:   3,
				Timeout:       30 * time.Second,
				Interval:      60 * time.Second,
				ReadyToTrip:   "consecutive",
				OnStateChange: true,
			},
		},
	}
}

// CreateCircuitBreaker creates a gobreaker.CircuitBreaker from config
func (c *CircuitBreakerConfig) CreateCircuitBreaker(name string) *gobreaker.CircuitBreaker {
	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: 0, // Unlimited requests when closed
		Interval:    c.Interval,
		Timeout:     c.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			switch c.ReadyToTrip {
			case "consecutive":
				return counts.ConsecutiveFailures > c.MaxFailures
			case "count":
				return counts.TotalFailures > c.MaxFailures
			default:
				return counts.ConsecutiveFailures > c.MaxFailures
			}
		},
	}

	if c.OnStateChange {
		settings.OnStateChange = func(name string, from gobreaker.State, to gobreaker.State) {
			// Log state changes
			// In production, you might want to use a proper logger here
		}
	}

	return gobreaker.NewCircuitBreaker(settings)
}
