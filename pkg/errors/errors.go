package errors

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// ErrorCode represents different types of errors in the application
type ErrorCode string

const (
	// Validation errors
	ErrCodeValidation      ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput    ErrorCode = "INVALID_INPUT"
	ErrCodeMissingRequired ErrorCode = "MISSING_REQUIRED"

	// Business logic errors
	ErrCodeBusinessLogic ErrorCode = "BUSINESS_LOGIC_ERROR"
	ErrCodeNotFound      ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists ErrorCode = "ALREADY_EXISTS"
	ErrCodeUnauthorized  ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden     ErrorCode = "FORBIDDEN"

	// Infrastructure errors
	ErrCodeInfrastructure ErrorCode = "INFRASTRUCTURE_ERROR"
	ErrCodeDatabase       ErrorCode = "DATABASE_ERROR"
	ErrCodeNetwork        ErrorCode = "NETWORK_ERROR"
	ErrCodeTimeout        ErrorCode = "TIMEOUT_ERROR"
	ErrCodeExternal       ErrorCode = "EXTERNAL_SERVICE_ERROR"

	// Scanner errors
	ErrCodeScannerError     ErrorCode = "SCANNER_ERROR"
	ErrCodeScannerNotFound  ErrorCode = "SCANNER_NOT_FOUND"
	ErrCodeScannerConfig    ErrorCode = "SCANNER_CONFIG_ERROR"
	ErrCodeScannerExecution ErrorCode = "SCANNER_EXECUTION_ERROR"

	// System errors
	ErrCodeSystem        ErrorCode = "SYSTEM_ERROR"
	ErrCodeInternal      ErrorCode = "INTERNAL_ERROR"
	ErrCodeConfig        ErrorCode = "CONFIG_ERROR"
	ErrCodeSerialization ErrorCode = "SERIALIZATION_ERROR"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	StackTrace string                 `json:"stack_trace,omitempty"`
	Component  string                 `json:"component,omitempty"`
}

// Error implements the error interface
func (ae *AppError) Error() string {
	if ae.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", ae.Code, ae.Message, ae.Details)
	}
	return fmt.Sprintf("[%s] %s", ae.Code, ae.Message)
}

// Unwrap returns the underlying cause error
func (ae *AppError) Unwrap() error {
	return ae.Cause
}

// Is checks if the error matches the target error
func (ae *AppError) Is(target error) bool {
	if target == nil {
		return false
	}

	if t, ok := target.(*AppError); ok {
		return ae.Code == t.Code
	}

	return errors.Is(ae.Cause, target)
}

// WithContext adds context information to the error
func (ae *AppError) WithContext(key string, value interface{}) *AppError {
	if ae.Context == nil {
		ae.Context = make(map[string]interface{})
	}
	ae.Context[key] = value
	return ae
}

// WithComponent sets the component that generated the error
func (ae *AppError) WithComponent(component string) *AppError {
	ae.Component = component
	return ae
}

// WithStackTrace captures the current stack trace
func (ae *AppError) WithStackTrace() *AppError {
	ae.StackTrace = captureStackTrace(2) // Skip this function and the caller
	return ae
}

// ToMap converts the error to a map for JSON serialization
func (ae *AppError) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"code":      ae.Code,
		"message":   ae.Message,
		"timestamp": ae.Timestamp.Format(time.RFC3339),
	}

	if ae.Details != "" {
		result["details"] = ae.Details
	}

	if ae.Context != nil && len(ae.Context) > 0 {
		result["context"] = ae.Context
	}

	if ae.Component != "" {
		result["component"] = ae.Component
	}

	if ae.StackTrace != "" {
		result["stack_trace"] = ae.StackTrace
	}

	if ae.Cause != nil {
		result["cause"] = ae.Cause.Error()
	}

	return result
}

// Error creation functions

// New creates a new application error
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
}

// Newf creates a new application error with formatted message
func Newf(code ErrorCode, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Timestamp: time.Now().UTC(),
	}
}

// Wrap wraps an existing error with application error information
func Wrap(code ErrorCode, message string, cause error) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Details:   cause.Error(),
		Timestamp: time.Now().UTC(),
	}
}

// Wrapf wraps an existing error with formatted message
func Wrapf(code ErrorCode, cause error, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Cause:     cause,
		Details:   cause.Error(),
		Timestamp: time.Now().UTC(),
	}
}

// Specific error types

// ValidationError creates a validation error
func NewValidationError(message string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeValidation,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}

	if cause != nil {
		err.Cause = cause
		err.Details = cause.Error()
	}

	return err
}

// BusinessLogicError creates a business logic error
func NewBusinessLogicError(message string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeBusinessLogic,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}

	if cause != nil {
		err.Cause = cause
		err.Details = cause.Error()
	}

	return err
}

// NotFoundError creates a not found error
func NewNotFoundError(resource string, identifier string) *AppError {
	return &AppError{
		Code:      ErrCodeNotFound,
		Message:   fmt.Sprintf("%s not found", resource),
		Details:   fmt.Sprintf("Resource '%s' with identifier '%s' was not found", resource, identifier),
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"resource":   resource,
			"identifier": identifier,
		},
	}
}

// AlreadyExistsError creates an already exists error
func NewAlreadyExistsError(resource string, identifier string) *AppError {
	return &AppError{
		Code:      ErrCodeAlreadyExists,
		Message:   fmt.Sprintf("%s already exists", resource),
		Details:   fmt.Sprintf("Resource '%s' with identifier '%s' already exists", resource, identifier),
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"resource":   resource,
			"identifier": identifier,
		},
	}
}

// UnauthorizedError creates an unauthorized error
func NewUnauthorizedError(action string) *AppError {
	return &AppError{
		Code:      ErrCodeUnauthorized,
		Message:   "Unauthorized access",
		Details:   fmt.Sprintf("Action '%s' requires authentication", action),
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"action": action,
		},
	}
}

// ForbiddenError creates a forbidden error
func NewForbiddenError(action string, reason string) *AppError {
	return &AppError{
		Code:      ErrCodeForbidden,
		Message:   "Forbidden action",
		Details:   fmt.Sprintf("Action '%s' is forbidden: %s", action, reason),
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"action": action,
			"reason": reason,
		},
	}
}

// InfrastructureError creates an infrastructure error
func NewInfrastructureError(component string, operation string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeInfrastructure,
		Message:   fmt.Sprintf("%s infrastructure error", component),
		Details:   fmt.Sprintf("Operation '%s' failed in component '%s'", operation, component),
		Component: component,
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"operation": operation,
		},
	}

	if cause != nil {
		err.Cause = cause
		err.Details += ": " + cause.Error()
	}

	return err
}

// DatabaseError creates a database error
func NewDatabaseError(operation string, cause error) *AppError {
	return &AppError{
		Code:      ErrCodeDatabase,
		Message:   "Database operation failed",
		Details:   fmt.Sprintf("Database operation '%s' failed", operation),
		Cause:     cause,
		Component: "database",
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"operation": operation,
		},
	}
}

// NetworkError creates a network error
func NewNetworkError(operation string, target string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeNetwork,
		Message:   "Network operation failed",
		Details:   fmt.Sprintf("Network operation '%s' to '%s' failed", operation, target),
		Component: "network",
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"operation": operation,
			"target":    target,
		},
	}

	if cause != nil {
		err.Cause = cause
		err.Details += ": " + cause.Error()
	}

	return err
}

// TimeoutError creates a timeout error
func NewTimeoutError(operation string, timeout time.Duration) *AppError {
	return &AppError{
		Code:      ErrCodeTimeout,
		Message:   "Operation timed out",
		Details:   fmt.Sprintf("Operation '%s' timed out after %v", operation, timeout),
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"operation": operation,
			"timeout":   timeout.String(),
		},
	}
}

// ScannerError creates a scanner-specific error
func NewScannerError(scanner string, operation string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeScannerError,
		Message:   fmt.Sprintf("Scanner '%s' error", scanner),
		Details:   fmt.Sprintf("Scanner '%s' failed during operation '%s'", scanner, operation),
		Component: "scanner",
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"scanner":   scanner,
			"operation": operation,
		},
	}

	if cause != nil {
		err.Cause = cause
		err.Details += ": " + cause.Error()
	}

	return err
}

// ConfigError creates a configuration error
func NewConfigError(component string, field string, value interface{}, reason string) *AppError {
	return &AppError{
		Code:      ErrCodeConfig,
		Message:   "Configuration error",
		Details:   fmt.Sprintf("Invalid configuration for %s.%s: %s", component, field, reason),
		Component: component,
		Timestamp: time.Now().UTC(),
		Context: map[string]interface{}{
			"field":  field,
			"value":  value,
			"reason": reason,
		},
	}
}

// InternalError creates an internal system error
func NewInternalError(message string, cause error) *AppError {
	err := &AppError{
		Code:      ErrCodeInternal,
		Message:   "Internal system error",
		Details:   message,
		Timestamp: time.Now().UTC(),
	}

	if cause != nil {
		err.Cause = cause
		err.Details += ": " + cause.Error()
	}

	return err.WithStackTrace()
}

// Utility functions

// IsValidationError checks if error is a validation error
func IsValidationError(err error) bool {
	return HasCode(err, ErrCodeValidation)
}

// IsNotFoundError checks if error is a not found error
func IsNotFoundError(err error) bool {
	return HasCode(err, ErrCodeNotFound)
}

// IsBusinessLogicError checks if error is a business logic error
func IsBusinessLogicError(err error) bool {
	return HasCode(err, ErrCodeBusinessLogic)
}

// IsInfrastructureError checks if error is an infrastructure error
func IsInfrastructureError(err error) bool {
	return HasCode(err, ErrCodeInfrastructure) ||
		HasCode(err, ErrCodeDatabase) ||
		HasCode(err, ErrCodeNetwork)
}

// IsScannerError checks if error is a scanner error
func IsScannerError(err error) bool {
	return HasCode(err, ErrCodeScannerError) ||
		HasCode(err, ErrCodeScannerNotFound) ||
		HasCode(err, ErrCodeScannerConfig) ||
		HasCode(err, ErrCodeScannerExecution)
}

// HasCode checks if error has a specific code
func HasCode(err error, code ErrorCode) bool {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code == code
	}
	return false
}

// GetCode extracts the error code from an error
func GetCode(err error) ErrorCode {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Code
	}
	return ErrCodeInternal
}

// GetContext extracts context from an error
func GetContext(err error) map[string]interface{} {
	if appErr, ok := err.(*AppError); ok {
		return appErr.Context
	}
	return nil
}

// captureStackTrace captures the current stack trace
func captureStackTrace(skip int) string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(skip+1, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var trace strings.Builder
	for {
		frame, more := frames.Next()
		trace.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
		if !more {
			break
		}
	}

	return trace.String()
}

// Error chain utilities

// Chain represents a chain of errors
type Chain struct {
	errors []*AppError
}

// NewChain creates a new error chain
func NewChain() *Chain {
	return &Chain{
		errors: make([]*AppError, 0),
	}
}

// Add adds an error to the chain
func (c *Chain) Add(err *AppError) *Chain {
	c.errors = append(c.errors, err)
	return c
}

// HasErrors returns true if the chain has any errors
func (c *Chain) HasErrors() bool {
	return len(c.errors) > 0
}

// Count returns the number of errors in the chain
func (c *Chain) Count() int {
	return len(c.errors)
}

// Errors returns all errors in the chain
func (c *Chain) Errors() []*AppError {
	return c.errors
}

// Error implements the error interface
func (c *Chain) Error() string {
	if len(c.errors) == 0 {
		return "no errors"
	}

	if len(c.errors) == 1 {
		return c.errors[0].Error()
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("multiple errors (%d):\n", len(c.errors)))
	for i, err := range c.errors {
		builder.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}

	return builder.String()
}

// ToMap converts the error chain to a map
func (c *Chain) ToMap() map[string]interface{} {
	if len(c.errors) == 0 {
		return map[string]interface{}{
			"has_errors": false,
			"count":      0,
		}
	}

	errorMaps := make([]map[string]interface{}, len(c.errors))
	for i, err := range c.errors {
		errorMaps[i] = err.ToMap()
	}

	return map[string]interface{}{
		"has_errors": true,
		"count":      len(c.errors),
		"errors":     errorMaps,
	}
}
