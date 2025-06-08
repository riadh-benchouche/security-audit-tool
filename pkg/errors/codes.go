package errors

import "net/http"

// HTTPStatusCode maps error codes to HTTP status codes
func (code ErrorCode) HTTPStatusCode() int {
	switch code {
	// 400 Bad Request
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired:
		return http.StatusBadRequest

	// 401 Unauthorized
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized

	// 403 Forbidden
	case ErrCodeForbidden:
		return http.StatusForbidden

	// 404 Not Found
	case ErrCodeNotFound, ErrCodeScannerNotFound:
		return http.StatusNotFound

	// 409 Conflict
	case ErrCodeAlreadyExists:
		return http.StatusConflict

	// 408 Request Timeout
	case ErrCodeTimeout:
		return http.StatusRequestTimeout

	// 422 Unprocessable Entity
	case ErrCodeBusinessLogic, ErrCodeScannerConfig:
		return http.StatusUnprocessableEntity

	// 502 Bad Gateway
	case ErrCodeExternal:
		return http.StatusBadGateway

	// 503 Service Unavailable
	case ErrCodeNetwork, ErrCodeDatabase:
		return http.StatusServiceUnavailable

	// 500 Internal Server Error
	case ErrCodeInfrastructure, ErrCodeSystem, ErrCodeInternal, ErrCodeConfig,
		ErrCodeSerialization, ErrCodeScannerError, ErrCodeScannerExecution:
		return http.StatusInternalServerError

	default:
		return http.StatusInternalServerError
	}
}

// IsClientError returns true if the error is a client error (4xx)
func (code ErrorCode) IsClientError() bool {
	status := code.HTTPStatusCode()
	return status >= 400 && status < 500
}

// IsServerError returns true if the error is a server error (5xx)
func (code ErrorCode) IsServerError() bool {
	status := code.HTTPStatusCode()
	return status >= 500
}

// IsRetryable returns true if the error might succeed on retry
func (code ErrorCode) IsRetryable() bool {
	switch code {
	case ErrCodeNetwork, ErrCodeTimeout, ErrCodeExternal, ErrCodeDatabase:
		return true
	default:
		return false
	}
}

// Severity levels for logging and monitoring
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severity returns the severity level of the error code
func (code ErrorCode) Severity() Severity {
	switch code {
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired, ErrCodeNotFound:
		return SeverityLow

	case ErrCodeBusinessLogic, ErrCodeAlreadyExists, ErrCodeUnauthorized, ErrCodeForbidden,
		ErrCodeScannerConfig, ErrCodeConfig:
		return SeverityMedium

	case ErrCodeInfrastructure, ErrCodeDatabase, ErrCodeNetwork, ErrCodeTimeout,
		ErrCodeExternal, ErrCodeScannerError, ErrCodeScannerExecution:
		return SeverityHigh

	case ErrCodeSystem, ErrCodeInternal, ErrCodeSerialization:
		return SeverityCritical

	default:
		return SeverityMedium
	}
}

// Category groups related error codes
type Category string

const (
	CategoryValidation     Category = "validation"
	CategoryAuthentication Category = "authentication"
	CategoryAuthorization  Category = "authorization"
	CategoryBusinessLogic  Category = "business_logic"
	CategoryInfrastructure Category = "infrastructure"
	CategorySystem         Category = "system"
	CategoryScanner        Category = "scanner"
)

// Category returns the category of the error code
func (code ErrorCode) Category() Category {
	switch code {
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired:
		return CategoryValidation

	case ErrCodeUnauthorized:
		return CategoryAuthentication

	case ErrCodeForbidden:
		return CategoryAuthorization

	case ErrCodeBusinessLogic, ErrCodeNotFound, ErrCodeAlreadyExists:
		return CategoryBusinessLogic

	case ErrCodeInfrastructure, ErrCodeDatabase, ErrCodeNetwork, ErrCodeTimeout, ErrCodeExternal:
		return CategoryInfrastructure

	case ErrCodeSystem, ErrCodeInternal, ErrCodeConfig, ErrCodeSerialization:
		return CategorySystem

	case ErrCodeScannerError, ErrCodeScannerNotFound, ErrCodeScannerConfig, ErrCodeScannerExecution:
		return CategoryScanner

	default:
		return CategorySystem
	}
}

// ErrorMetadata provides additional metadata about error codes
type ErrorMetadata struct {
	Code        ErrorCode `json:"code"`
	HTTPStatus  int       `json:"http_status"`
	Severity    Severity  `json:"severity"`
	Category    Category  `json:"category"`
	Retryable   bool      `json:"retryable"`
	Description string    `json:"description"`
}

// GetMetadata returns metadata for an error code
func (code ErrorCode) GetMetadata() ErrorMetadata {
	descriptions := map[ErrorCode]string{
		ErrCodeValidation:       "Input validation failed",
		ErrCodeInvalidInput:     "Invalid input provided",
		ErrCodeMissingRequired:  "Required field is missing",
		ErrCodeBusinessLogic:    "Business rule violation",
		ErrCodeNotFound:         "Requested resource not found",
		ErrCodeAlreadyExists:    "Resource already exists",
		ErrCodeUnauthorized:     "Authentication required",
		ErrCodeForbidden:        "Access forbidden",
		ErrCodeInfrastructure:   "Infrastructure component failure",
		ErrCodeDatabase:         "Database operation failed",
		ErrCodeNetwork:          "Network communication error",
		ErrCodeTimeout:          "Operation timed out",
		ErrCodeExternal:         "External service error",
		ErrCodeScannerError:     "Scanner execution error",
		ErrCodeScannerNotFound:  "Scanner not found",
		ErrCodeScannerConfig:    "Scanner configuration error",
		ErrCodeScannerExecution: "Scanner execution failed",
		ErrCodeSystem:           "System error",
		ErrCodeInternal:         "Internal application error",
		ErrCodeConfig:           "Configuration error",
		ErrCodeSerialization:    "Data serialization error",
	}

	return ErrorMetadata{
		Code:        code,
		HTTPStatus:  code.HTTPStatusCode(),
		Severity:    code.Severity(),
		Category:    code.Category(),
		Retryable:   code.IsRetryable(),
		Description: descriptions[code],
	}
}

// AllErrorCodes returns all defined error codes with their metadata
func AllErrorCodes() []ErrorMetadata {
	codes := []ErrorCode{
		ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingRequired,
		ErrCodeBusinessLogic, ErrCodeNotFound, ErrCodeAlreadyExists,
		ErrCodeUnauthorized, ErrCodeForbidden,
		ErrCodeInfrastructure, ErrCodeDatabase, ErrCodeNetwork,
		ErrCodeTimeout, ErrCodeExternal,
		ErrCodeScannerError, ErrCodeScannerNotFound, ErrCodeScannerConfig, ErrCodeScannerExecution,
		ErrCodeSystem, ErrCodeInternal, ErrCodeConfig, ErrCodeSerialization,
	}

	metadata := make([]ErrorMetadata, len(codes))
	for i, code := range codes {
		metadata[i] = code.GetMetadata()
	}

	return metadata
}
