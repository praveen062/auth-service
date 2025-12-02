package models

import (
	"fmt"
	"net/http"
)

// ErrorType represents the type of error
type ErrorType string

const (
	// ErrorTypeValidation represents validation errors
	ErrorTypeValidation ErrorType = "VALIDATION_ERROR"
	// ErrorTypeAuthentication represents authentication errors
	ErrorTypeAuthentication ErrorType = "AUTHENTICATION_ERROR"
	// ErrorTypeAuthorization represents authorization errors
	ErrorTypeAuthorization ErrorType = "AUTHORIZATION_ERROR"
	// ErrorTypeQuotaExceeded represents quota exceeded errors
	ErrorTypeQuotaExceeded ErrorType = "QUOTA_EXCEEDED"
	// ErrorTypeFeatureDisabled represents feature disabled errors
	ErrorTypeFeatureDisabled ErrorType = "FEATURE_DISABLED"
	// ErrorTypeSubscription represents subscription errors
	ErrorTypeSubscription ErrorType = "SUBSCRIPTION_ERROR"
	// ErrorTypeServiceUnavailable represents service unavailable errors
	ErrorTypeServiceUnavailable ErrorType = "SERVICE_UNAVAILABLE"
	// ErrorTypeRateLimit represents rate limit errors
	ErrorTypeRateLimit ErrorType = "RATE_LIMIT_EXCEEDED"
	// ErrorTypeInternal represents internal server errors
	ErrorTypeInternal ErrorType = "INTERNAL_ERROR"
	// ErrorTypeNotFound represents not found errors
	ErrorTypeNotFound ErrorType = "NOT_FOUND"
)

// ErrorCode represents specific error codes
type ErrorCode string

const (
	// ErrorCodeInvalidRequest represents invalid request
	ErrorCodeInvalidRequest ErrorCode = "INVALID_REQUEST"
	// ErrorCodeMissingFields represents missing required fields
	ErrorCodeMissingFields ErrorCode = "MISSING_FIELDS"
	// ErrorCodeInvalidChannel represents invalid channel
	ErrorCodeInvalidChannel ErrorCode = "INVALID_CHANNEL"
	// ErrorCodeInvalidOTP represents invalid OTP
	ErrorCodeInvalidOTP ErrorCode = "INVALID_OTP"
	// ErrorCodeOTPExpired represents expired OTP
	ErrorCodeOTPExpired ErrorCode = "OTP_EXPIRED"
	// ErrorCodeOTPAlreadyUsed represents already used OTP
	ErrorCodeOTPAlreadyUsed ErrorCode = "OTP_ALREADY_USED"
	// ErrorCode2FAQuotaExceeded represents 2FA quota exceeded
	ErrorCode2FAQuotaExceeded ErrorCode = "2FA_QUOTA_EXCEEDED"
	// ErrorCodeFeatureDisabled represents feature disabled
	ErrorCodeFeatureDisabled ErrorCode = "FEATURE_DISABLED"
	// ErrorCodeInvalidSubscription represents invalid subscription
	ErrorCodeInvalidSubscription ErrorCode = "INVALID_SUBSCRIPTION"
	// ErrorCodeSubscriptionExpired represents expired subscription
	ErrorCodeSubscriptionExpired ErrorCode = "SUBSCRIPTION_EXPIRED"
	// ErrorCodeRateLimitExceeded represents rate limit exceeded
	ErrorCodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"
	// ErrorCodeServiceUnavailable represents service unavailable
	ErrorCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	// ErrorCodeInternalError represents internal server error
	ErrorCodeInternalError ErrorCode = "INTERNAL_ERROR"
	// ErrorCodeNotFound represents resource not found
	ErrorCodeNotFound ErrorCode = "NOT_FOUND"
	// ErrorCodeAuthentication represents authentication error
	ErrorCodeAuthentication ErrorCode = "AUTHENTICATION_ERROR"
	// ErrorCodeAuthorization represents authorization error
	ErrorCodeAuthorization ErrorCode = "AUTHORIZATION_ERROR"
)

// APIError represents a structured API error response
type APIError struct {
	Type       ErrorType `json:"type"`
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	HTTPStatus int       `json:"-"`
	RequestID  string    `json:"request_id,omitempty"`
	Timestamp  string    `json:"timestamp,omitempty"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Type, e.Message)
}

// NewAPIError creates a new API error
func NewAPIError(errorType ErrorType, code ErrorCode, message string, httpStatus int) *APIError {
	return &APIError{
		Type:       errorType,
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// ErrorMapping maps error codes to HTTP status codes and types
var ErrorMapping = map[ErrorCode]struct {
	HTTPStatus int
	ErrorType  ErrorType
	Message    string
}{
	ErrorCodeInvalidRequest: {
		HTTPStatus: http.StatusBadRequest,
		ErrorType:  ErrorTypeValidation,
		Message:    "Invalid request format",
	},
	ErrorCodeMissingFields: {
		HTTPStatus: http.StatusBadRequest,
		ErrorType:  ErrorTypeValidation,
		Message:    "Missing required fields",
	},
	ErrorCodeInvalidChannel: {
		HTTPStatus: http.StatusBadRequest,
		ErrorType:  ErrorTypeValidation,
		Message:    "Invalid channel specified",
	},
	ErrorCodeInvalidOTP: {
		HTTPStatus: http.StatusUnauthorized,
		ErrorType:  ErrorTypeAuthentication,
		Message:    "Invalid OTP code",
	},
	ErrorCodeOTPExpired: {
		HTTPStatus: http.StatusUnauthorized,
		ErrorType:  ErrorTypeAuthentication,
		Message:    "OTP code has expired",
	},
	ErrorCodeOTPAlreadyUsed: {
		HTTPStatus: http.StatusUnauthorized,
		ErrorType:  ErrorTypeAuthentication,
		Message:    "OTP code has already been used",
	},
	ErrorCode2FAQuotaExceeded: {
		HTTPStatus: http.StatusTooManyRequests,
		ErrorType:  ErrorTypeQuotaExceeded,
		Message:    "2FA quota exceeded",
	},
	ErrorCodeFeatureDisabled: {
		HTTPStatus: http.StatusForbidden,
		ErrorType:  ErrorTypeFeatureDisabled,
		Message:    "Feature is disabled",
	},
	ErrorCodeInvalidSubscription: {
		HTTPStatus: http.StatusPaymentRequired,
		ErrorType:  ErrorTypeSubscription,
		Message:    "Invalid subscription",
	},
	ErrorCodeSubscriptionExpired: {
		HTTPStatus: http.StatusPaymentRequired,
		ErrorType:  ErrorTypeSubscription,
		Message:    "Subscription has expired",
	},
	ErrorCodeRateLimitExceeded: {
		HTTPStatus: http.StatusTooManyRequests,
		ErrorType:  ErrorTypeRateLimit,
		Message:    "Rate limit exceeded",
	},
	ErrorCodeServiceUnavailable: {
		HTTPStatus: http.StatusServiceUnavailable,
		ErrorType:  ErrorTypeServiceUnavailable,
		Message:    "Service temporarily unavailable",
	},
	ErrorCodeInternalError: {
		HTTPStatus: http.StatusInternalServerError,
		ErrorType:  ErrorTypeInternal,
		Message:    "Internal server error",
	},
	ErrorCodeNotFound: {
		HTTPStatus: http.StatusNotFound,
		ErrorType:  ErrorTypeNotFound,
		Message:    "Resource not found",
	},
	ErrorCodeAuthentication: {
		HTTPStatus: http.StatusUnauthorized,
		ErrorType:  ErrorTypeAuthentication,
		Message:    "Authentication failed",
	},
	ErrorCodeAuthorization: {
		HTTPStatus: http.StatusForbidden,
		ErrorType:  ErrorTypeAuthorization,
		Message:    "Authorization failed",
	},
}

// GetErrorInfo returns error information for a given error code
func GetErrorInfo(code ErrorCode) (int, ErrorType, string) {
	if info, exists := ErrorMapping[code]; exists {
		return info.HTTPStatus, info.ErrorType, info.Message
	}
	// Default to internal error if code not found
	return http.StatusInternalServerError, ErrorTypeInternal, "Unknown error"
}

// CreateError creates an API error from an error code
func CreateError(code ErrorCode, details ...string) *APIError {
	httpStatus, errorType, message := GetErrorInfo(code)

	apiError := NewAPIError(errorType, code, message, httpStatus)
	if len(details) > 0 {
		apiError.Details = details[0]
	}

	return apiError
}

// Channel mapping for 2FA channels
var ChannelMapping = map[string]struct {
	Feature     string
	ChannelType string
}{
	"EMAIL": {
		Feature:     "2FA_EMAIL",
		ChannelType: "EMAIL",
	},
	"SMS": {
		Feature:     "2FA_SMS",
		ChannelType: "SMS",
	},
}

// GetChannelInfo returns channel information
func GetChannelInfo(channel string) (string, string, bool) {
	if info, exists := ChannelMapping[channel]; exists {
		return info.Feature, info.ChannelType, true
	}
	return "", "", false
}

// ValidChannels returns list of valid channels
func ValidChannels() []string {
	channels := make([]string, 0, len(ChannelMapping))
	for channel := range ChannelMapping {
		channels = append(channels, channel)
	}
	return channels
}
