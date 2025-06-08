package interfaces

import (
	"context"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// Scanner defines the contract that all security scanners must implement
type Scanner interface {
	// Info returns metadata about the scanner
	Info() *ScannerInfo

	// Configure sets up the scanner with the provided configuration
	Configure(config map[string]interface{}) error

	// Validate checks if the scanner can run against the given target
	Validate(target *entities.Target) error

	// Scan executes the security scan against the target
	Scan(ctx context.Context, target *entities.Target) (*entities.ModuleExecution, error)

	// Stop gracefully stops a running scan
	Stop() error

	// Health returns the current health status of the scanner
	Health() *HealthStatus
}

// ScannerInfo contains metadata about a scanner
type ScannerInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Website      string            `json:"website,omitempty"`
	License      string            `json:"license,omitempty"`
	Capabilities []string          `json:"capabilities"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	ConfigSchema map[string]string `json:"config_schema,omitempty"`
}

// HealthStatus represents the health state of a scanner
type HealthStatus struct {
	Status      HealthState `json:"status"`
	Message     string      `json:"message,omitempty"`
	LastChecked int64       `json:"last_checked"`
	Errors      []string    `json:"errors,omitempty"`
}

// HealthState represents possible health states
type HealthState string

const (
	HealthStateHealthy   HealthState = "healthy"
	HealthStateUnhealthy HealthState = "unhealthy"
	HealthStateUnknown   HealthState = "unknown"
)

// ScannerFactory creates scanner instances
type ScannerFactory interface {
	// CreateScanner creates a new scanner instance by name
	CreateScanner(name string) (Scanner, error)

	// ListAvailable returns all available scanner names
	ListAvailable() []string

	// GetInfo returns information about a specific scanner
	GetInfo(name string) (*ScannerInfo, error)

	// Register adds a new scanner to the factory
	Register(name string, creator ScannerCreator) error
}

// ScannerCreator is a function that creates scanner instances
type ScannerCreator func() Scanner

// ResultBuilder helps build scan results in a consistent way
type ResultBuilder interface {
	// SetModule sets the module information
	SetModule(module *entities.Module) ResultBuilder

	// SetTarget sets the target information
	SetTarget(target *entities.Target) ResultBuilder

	// AddFinding adds a finding to the result
	AddFinding(finding *entities.Finding) ResultBuilder

	// AddError adds an error to the result
	AddError(err string) ResultBuilder

	// SetMetadata sets metadata for the result
	SetMetadata(key string, value interface{}) ResultBuilder

	// SetProgress updates the scan progress (0-100)
	SetProgress(progress int) ResultBuilder

	// Build creates the final ModuleExecution result
	Build() (*entities.ModuleExecution, error)
}

// FindingBuilder helps create findings in a structured way
type FindingBuilder interface {
	// Critical creates a critical severity finding
	Critical(id, title, description string) FindingBuilder

	// High creates a high severity finding
	High(id, title, description string) FindingBuilder

	// Medium creates a medium severity finding
	Medium(id, title, description string) FindingBuilder

	// Low creates a low severity finding
	Low(id, title, description string) FindingBuilder

	// Info creates an info severity finding
	Info(id, title, description string) FindingBuilder

	// WithType sets the finding type
	WithType(findingType entities.FindingType) FindingBuilder

	// WithEvidence adds evidence to the finding
	WithEvidence(key string, value interface{}) FindingBuilder

	// WithRemediation sets remediation advice
	WithRemediation(remediation string) FindingBuilder

	// WithReference adds a reference URL or document
	WithReference(reference string) FindingBuilder

	// WithTag adds a tag to the finding
	WithTag(tag string) FindingBuilder

	// WithCVSS sets CVSS score information
	WithCVSS(version float64, vector string, score float64, rating string) FindingBuilder

	// Build creates the final Finding
	Build() (*entities.Finding, error)
}

// ScannerRegistry manages available scanners
type ScannerRegistry interface {
	// Register adds a scanner to the registry
	Register(scanner Scanner) error

	// Unregister removes a scanner from the registry
	Unregister(name string) error

	// Get retrieves a scanner by name
	Get(name string) (Scanner, error)

	// List returns all registered scanners
	List() []Scanner

	// ListByCapability returns scanners with specific capability
	ListByCapability(capability string) []Scanner

	// ListByTarget returns scanners compatible with target type
	ListByTarget(targetType entities.TargetType) []Scanner

	// Health checks the health of all registered scanners
	Health() map[string]*HealthStatus
}

// ScannerConfig provides configuration management for scanners
type ScannerConfig interface {
	// Get retrieves a configuration value
	Get(key string) interface{}

	// GetString retrieves a string configuration value
	GetString(key string, defaultValue string) string

	// GetInt retrieves an integer configuration value
	GetInt(key string, defaultValue int) int

	// GetBool retrieves a boolean configuration value
	GetBool(key string, defaultValue bool) bool

	// GetDuration retrieves a duration configuration value
	GetDuration(key string, defaultValue string) time.Duration

	// Set updates a configuration value
	Set(key string, value interface{}) error

	// Validate checks if the current configuration is valid
	Validate() error

	// ToMap returns the configuration as a map
	ToMap() map[string]interface{}
}

// ScannerMetrics collects performance and usage metrics
type ScannerMetrics interface {
	// IncrementScansTotal increments the total scans counter
	IncrementScansTotal(scanner string)

	// IncrementScansSuccessful increments successful scans counter
	IncrementScansSuccessful(scanner string)

	// IncrementScansFailed increments failed scans counter
	IncrementScansFailed(scanner string)

	// ObserveScanDuration records scan duration
	ObserveScanDuration(scanner string, duration time.Duration)

	// ObserveFindingsCount records number of findings
	ObserveFindingsCount(scanner string, count int)

	// GetMetrics returns current metrics
	GetMetrics() map[string]interface{}
}

// ScannerLogger provides structured logging for scanners
type ScannerLogger interface {
	// Debug logs a debug message
	Debug(msg string, fields map[string]interface{})

	// Info logs an info message
	Info(msg string, fields map[string]interface{})

	// Warn logs a warning message
	Warn(msg string, fields map[string]interface{})

	// Error logs an error message
	Error(msg string, err error, fields map[string]interface{})

	// WithField returns a logger with an additional field
	WithField(key string, value interface{}) ScannerLogger

	// WithFields returns a logger with additional fields
	WithFields(fields map[string]interface{}) ScannerLogger

	// WithScanner returns a logger with scanner context
	WithScanner(name string) ScannerLogger

	// WithTarget returns a logger with target context
	WithTarget(target *entities.Target) ScannerLogger
}
