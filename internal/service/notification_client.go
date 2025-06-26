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

// NotificationClient defines the interface for Notification Service communication
type NotificationClient interface {
	SendNotification(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error)
	GetCircuitBreakerState() gobreaker.State
}

// notificationClient implements NotificationClient
type notificationClient struct {
	httpClient     *http.Client
	baseURL        string
	circuitBreaker *gobreaker.CircuitBreaker
	config         config.NotificationServiceConfig
}

// NewNotificationClient creates a new Notification Service client
func NewNotificationClient(cfg config.NotificationServiceConfig) NotificationClient {
	circuitBreaker := cfg.CircuitBreaker.CreateCircuitBreaker("notification-service")

	return &notificationClient{
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		baseURL:        cfg.BaseURL,
		circuitBreaker: circuitBreaker,
		config:         cfg,
	}
}

// SendNotification sends a templated notification to the Notification Service
func (c *notificationClient) SendNotification(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
	// Use circuit breaker to protect against service failures
	result, err := c.circuitBreaker.Execute(func() (interface{}, error) {
		return c.sendNotificationWithRetry(ctx, payload)
	})

	if err != nil {
		// Check if it's a circuit breaker error
		if err == gobreaker.ErrOpenState {
			return nil, models.CreateError(models.ErrorCodeServiceUnavailable, "Notification service circuit breaker is open")
		}
		return nil, fmt.Errorf("notification service error: %w", err)
	}

	response, ok := result.(*models.NotificationResponse)
	if !ok {
		return nil, models.CreateError(models.ErrorCodeInternalError, "Invalid response type from notification service")
	}

	return response, nil
}

// sendNotificationWithRetry sends notification with retry logic
func (c *notificationClient) sendNotificationWithRetry(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
	// Convert payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal notification payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/notifications/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Name", "auth-service")
	req.Header.Set("X-Request-ID", getRequestID(ctx))

	// Send request with retry logic
	var lastErr error
	for attempt := 1; attempt <= c.config.MaxRetries; attempt++ {
		resp, err := c.httpClient.Do(req)
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
func (c *notificationClient) processResponse(resp *http.Response) (*models.NotificationResponse, error) {
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var notificationResp models.NotificationResponse
	if err := json.Unmarshal(body, &notificationResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal notification response: %w", err)
	}

	// Check HTTP status code and handle errors
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		return &notificationResp, nil
	case http.StatusBadRequest:
		return nil, models.CreateError(models.ErrorCodeInvalidRequest, notificationResp.Error)
	case http.StatusUnauthorized:
		return nil, models.CreateError(models.ErrorCodeAuthentication, notificationResp.Error)
	case http.StatusForbidden:
		return nil, models.CreateError(models.ErrorCodeAuthorization, notificationResp.Error)
	case http.StatusTooManyRequests:
		return nil, models.CreateError(models.ErrorCodeRateLimitExceeded, notificationResp.Error)
	case http.StatusInternalServerError:
		return nil, models.CreateError(models.ErrorCodeInternalError, notificationResp.Error)
	case http.StatusServiceUnavailable:
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable, notificationResp.Error)
	default:
		return nil, models.CreateError(models.ErrorCodeServiceUnavailable,
			fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
}

// GetCircuitBreakerState returns the current circuit breaker state
func (c *notificationClient) GetCircuitBreakerState() gobreaker.State {
	return c.circuitBreaker.State()
}

// getRequestID extracts request ID from context
func getRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value("request_id").(string); ok {
		return requestID
	}
	return "unknown"
}

// MockNotificationClient for testing
type MockNotificationClient struct {
	SendNotificationFunc func(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error)
	CircuitBreakerState  gobreaker.State
}

func (m *MockNotificationClient) SendNotification(ctx context.Context, payload *models.NotificationPayload) (*models.NotificationResponse, error) {
	if m.SendNotificationFunc != nil {
		return m.SendNotificationFunc(ctx, payload)
	}
	return &models.NotificationResponse{Success: true, MessageID: "mock-message-id"}, nil
}

func (m *MockNotificationClient) GetCircuitBreakerState() gobreaker.State {
	return m.CircuitBreakerState
}
