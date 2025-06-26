package service

import (
	"auth-service/internal/config"
	"auth-service/internal/models"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sony/gobreaker"
)

// SubscriptionClient defines the interface for Subscription Service communication
type SubscriptionClient interface {
	ValidateSubscription(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error)
	GetCircuitBreakerState() gobreaker.State
}

// subscriptionClient implements SubscriptionClient
type subscriptionClient struct {
	httpClient     *http.Client
	baseURL        string
	circuitBreaker *gobreaker.CircuitBreaker
	config         config.SubscriptionServiceConfig
}

// NewSubscriptionClient creates a new Subscription Service client
func NewSubscriptionClient(cfg config.SubscriptionServiceConfig) SubscriptionClient {
	circuitBreaker := cfg.CircuitBreaker.CreateCircuitBreaker("subscription-service")

	return &subscriptionClient{
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		baseURL:        cfg.BaseURL,
		circuitBreaker: circuitBreaker,
		config:         cfg,
	}
}

// ValidateSubscription validates client subscription and quota for 2FA features
func (c *subscriptionClient) ValidateSubscription(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
	// Use circuit breaker to protect against service failures
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return c.validateSubscriptionWithRetry(ctx, req)
	})

	if err != nil {
		// Check if it's a circuit breaker error
		if err == gobreaker.ErrOpenState {
			return nil, models.CreateError(models.ErrorCodeServiceUnavailable, "Subscription service circuit breaker is open")
		}
		return nil, fmt.Errorf("subscription service error: %w", err)
	}

	response, ok := result.(*models.SubscriptionValidationResponse)
	if !ok {
		return nil, models.CreateError(models.ErrorCodeInternalError, "Invalid response type from subscription service")
	}

	return response, nil
}

// validateSubscriptionWithRetry validates subscription with retry logic
func (c *subscriptionClient) validateSubscriptionWithRetry(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
	// Convert request to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subscription validation request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/subscriptions/validate", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Service-Name", "auth-service")
	httpReq.Header.Set("X-Request-ID", getRequestID(ctx))

	// Send request with retry logic
	var lastErr error
	for attempt := 1; attempt <= c.config.MaxRetries; attempt++ {
		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed (attempt %d): %w", attempt, err)

			// If this is not the last attempt, wait before retrying
			if attempt < c.config.MaxRetries {
				backoff := time.Duration(attempt) * c.config.RetryDelay
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(backoff):
					continue
				}
			}
			continue
		}

		// If we got a response, process it
		return c.processResponse(resp)
	}

	return nil, fmt.Errorf("all retry attempts failed: %w", lastErr)
}

// processResponse processes the HTTP response
func (c *subscriptionClient) processResponse(resp *http.Response) (*models.SubscriptionValidationResponse, error) {
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var subscriptionResp models.SubscriptionValidationResponse
	if err := json.Unmarshal(body, &subscriptionResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subscription response: %w", err)
	}

	// Check HTTP status code and handle errors
	switch resp.StatusCode {
	case http.StatusOK:
		return &subscriptionResp, nil
	case http.StatusBadRequest:
		return nil, models.CreateError(models.ErrorCodeInvalidRequest, subscriptionResp.Error)
	case http.StatusUnauthorized:
		return nil, models.CreateError(models.ErrorCodeAuthentication, subscriptionResp.Error)
	case http.StatusForbidden:
		return nil, models.CreateError(models.ErrorCodeAuthorization, subscriptionResp.Error)
	case http.StatusPaymentRequired:
		return nil, models.CreateError(models.ErrorCodeInvalidSubscription, subscriptionResp.Error)
	case http.StatusTooManyRequests:
		return nil, models.CreateError(models.ErrorCodeRateLimitExceeded, subscriptionResp.Error)
	case http.StatusInternalServerError:
		return nil, models.CreateError(models.ErrorCodeInternalError, subscriptionResp.Error)
	case http.StatusServiceUnavailable:
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable, subscriptionResp.Error)
	default:
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable,
			fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *subscriptionClient) GetCircuitBreakerState() gobreaker.State {
	return c.circuitBreaker.State()
}

// MockSubscriptionClient for testing
type MockSubscriptionClient struct {
	ValidateSubscriptionFunc func(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error)
	CircuitBreakerState      gobreaker.State
}

func (m *MockSubscriptionClient) ValidateSubscription(ctx context.Context, req *models.SubscriptionValidationRequest) (*models.SubscriptionValidationResponse, error) {
	if m.ValidateSubscriptionFunc != nil {
		return m.ValidateSubscriptionFunc(ctx, req)
	}

	// Default mock response
	return &models.SubscriptionValidationResponse{
		Valid:          true,
		FeatureEnabled: true,
		QuotaAvailable: true,
		DailyQuota:     1000,
		MonthlyQuota:   10000,
		DailyUsage:     100,
		MonthlyUsage:   1000,
	}, nil
}

func (m *MockSubscriptionClient) GetCircuitBreakerState() gobreaker.State {
	return m.CircuitBreakerState
}
