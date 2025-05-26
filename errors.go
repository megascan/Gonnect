package gonnect

import "fmt"

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
