package coretypes

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// User represents a generic user object returned by a provider
type User struct {
	ID        string                 `json:"id"`         // Unique identifier from the provider
	Email     string                 `json:"email"`      // User's email address
	Name      string                 `json:"name"`       // User's display name
	Username  string                 `json:"username"`   // Username (may differ from name)
	AvatarURL string                 `json:"avatar_url"` // URL to user's profile picture
	Locale    string                 `json:"locale"`     // User's locale/language preference
	RawData   map[string]interface{} `json:"raw_data"`   // Original data from provider
}

// Token represents the token data from a provider
type Token struct {
	AccessToken  string                 `json:"access_token"`  // OAuth2 access token
	RefreshToken string                 `json:"refresh_token"` // OAuth2 refresh token
	Expiry       time.Time              `json:"expiry"`        // Token expiration time
	IDToken      string                 `json:"id_token"`      // OpenID Connect ID token
	TokenType    string                 `json:"token_type"`    // Token type (usually "Bearer")
	Scope        string                 `json:"scope"`         // Granted scopes
	Extra        map[string]interface{} `json:"extra"`         // Provider-specific token data
}

// Provider defines the interface for an authentication provider.
// This interface accommodates both OAuth2 and OpenID 2.0 flows.
type Provider interface {
	// Name returns the provider's name (e.g., "google", "github")
	Name() string

	// BeginAuth initiates the authentication flow and returns the redirect URL
	BeginAuth(ctx context.Context, state string) (redirectURL string, err error)

	// CompleteAuth completes the authentication flow using the callback request
	CompleteAuth(ctx context.Context, r *http.Request) (user User, tokenData Token, err error)

	// RefreshToken refreshes an access token using a refresh token
	RefreshToken(ctx context.Context, refreshToken string) (newTokenData Token, err error)

	// ValidateToken validates a token and returns user info (for session validation)
	ValidateToken(ctx context.Context, token Token) (user User, valid bool, err error)

	// SupportsRefresh indicates if the provider supports token refresh
	SupportsRefresh() bool
}

// ErrorType represents the category of error that occurred
type ErrorType string

const (
	ErrTypeConfig         ErrorType = "config_error"
	ErrTypeProvider       ErrorType = "provider_error"
	ErrTypeAuthentication ErrorType = "auth_error"
	ErrTypeToken          ErrorType = "token_error"
	ErrTypeSession        ErrorType = "session_error"
	ErrTypeValidation     ErrorType = "validation_error"
)

// GonnectError represents errors from the Gonnect library with structured information
type GonnectError struct {
	Type     ErrorType // The category of error
	Message  string    // Human-readable error message
	Cause    error     // Underlying error that caused this error
	Provider string    // Which provider caused the error (if applicable)
}

// Error implements the error interface
func (e *GonnectError) Error() string {
	if e.Provider != "" {
		return fmt.Sprintf("gonnect[%s:%s]: %s", e.Provider, e.Type, e.Message)
	}
	return fmt.Sprintf("gonnect[%s]: %s", e.Type, e.Message)
}

// Unwrap implements the error unwrapping interface for Go 1.13+ error handling
func (e *GonnectError) Unwrap() error {
	return e.Cause
}

// NewError creates a new GonnectError with the specified type and message
func NewError(errType ErrorType, message string) *GonnectError {
	return &GonnectError{
		Type:    errType,
		Message: message,
	}
}

// NewErrorWithCause creates a new GonnectError with an underlying cause
func NewErrorWithCause(errType ErrorType, message string, cause error) *GonnectError {
	return &GonnectError{
		Type:    errType,
		Message: message,
		Cause:   cause,
	}
}

// NewProviderError creates a new GonnectError specific to a provider
func NewProviderError(provider string, errType ErrorType, message string) *GonnectError {
	return &GonnectError{
		Type:     errType,
		Message:  message,
		Provider: provider,
	}
}

// NewProviderErrorWithCause creates a new GonnectError specific to a provider with an underlying cause
func NewProviderErrorWithCause(provider string, errType ErrorType, message string, cause error) *GonnectError {
	return &GonnectError{
		Type:     errType,
		Message:  message,
		Cause:    cause,
		Provider: provider,
	}
}
