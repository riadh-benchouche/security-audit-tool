package repositories

import (
	"context"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// ScanRepository defines the contract for scan data persistence
type ScanRepository interface {
	// Create stores a new scan
	Create(ctx context.Context, scan *entities.Scan) error

	// GetByID retrieves a scan by its ID
	GetByID(ctx context.Context, id string) (*entities.Scan, error)

	// GetByTarget retrieves scans for a specific target
	GetByTarget(ctx context.Context, target string) ([]*entities.Scan, error)

	// List retrieves scans with optional filtering and pagination
	List(ctx context.Context, filter *ScanFilter, pagination *Pagination) ([]*entities.Scan, error)

	// Update modifies an existing scan
	Update(ctx context.Context, scan *entities.Scan) error

	// Delete removes a scan by ID
	Delete(ctx context.Context, id string) error

	// Count returns the total number of scans matching the filter
	Count(ctx context.Context, filter *ScanFilter) (int64, error)

	// GetStats returns aggregated statistics
	GetStats(ctx context.Context, timeRange *TimeRange) (*ScanStats, error)
}

// ModuleRepository defines the contract for module data persistence
type ModuleRepository interface {
	// Create stores a new module
	Create(ctx context.Context, module *entities.Module) error

	// GetByName retrieves a module by its name
	GetByName(ctx context.Context, name string) (*entities.Module, error)

	// List retrieves all modules with optional filtering
	List(ctx context.Context, filter *ModuleFilter) ([]*entities.Module, error)

	// Update modifies an existing module
	Update(ctx context.Context, module *entities.Module) error

	// Delete removes a module by name
	Delete(ctx context.Context, name string) error

	// GetEnabled returns only enabled modules
	GetEnabled(ctx context.Context) ([]*entities.Module, error)

	// GetByCapability returns modules with specific capability
	GetByCapability(ctx context.Context, capability string) ([]*entities.Module, error)
}

// FindingRepository defines the contract for finding data persistence
type FindingRepository interface {
	// Create stores a new finding
	Create(ctx context.Context, finding *entities.Finding) error

	// GetByID retrieves a finding by its ID
	GetByID(ctx context.Context, id string) (*entities.Finding, error)

	// GetByScanID retrieves findings for a specific scan
	GetByScanID(ctx context.Context, scanID string) ([]*entities.Finding, error)

	// List retrieves findings with optional filtering and pagination
	List(ctx context.Context, filter *FindingFilter, pagination *Pagination) ([]*entities.Finding, error)

	// Update modifies an existing finding
	Update(ctx context.Context, finding *entities.Finding) error

	// Delete removes a finding by ID
	Delete(ctx context.Context, id string) error

	// GetBySeverity returns findings with specific severity
	GetBySeverity(ctx context.Context, severity entities.Severity) ([]*entities.Finding, error)

	// GetStats returns finding statistics
	GetStats(ctx context.Context, timeRange *TimeRange) (*FindingStats, error)
}

// TargetRepository defines the contract for target data persistence
type TargetRepository interface {
	// Create stores a new target
	Create(ctx context.Context, target *entities.Target) error

	// GetByOriginal retrieves a target by its original string
	GetByOriginal(ctx context.Context, original string) (*entities.Target, error)

	// List retrieves targets with optional filtering
	List(ctx context.Context, filter *TargetFilter) ([]*entities.Target, error)

	// Update modifies an existing target
	Update(ctx context.Context, target *entities.Target) error

	// Delete removes a target
	Delete(ctx context.Context, original string) error

	// GetByType returns targets of specific type
	GetByType(ctx context.Context, targetType entities.TargetType) ([]*entities.Target, error)

	// GetRecent returns recently scanned targets
	GetRecent(ctx context.Context, limit int) ([]*entities.Target, error)
}

// Filter and pagination structures

// ScanFilter defines filtering options for scans
type ScanFilter struct {
	Target      string              `json:"target,omitempty"`
	Status      entities.ScanStatus `json:"status,omitempty"`
	Grade       entities.Grade      `json:"grade,omitempty"`
	CreatedBy   string              `json:"created_by,omitempty"`
	Module      string              `json:"module,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	MinScore    *int                `json:"min_score,omitempty"`
	MaxScore    *int                `json:"max_score,omitempty"`
	StartTime   *time.Time          `json:"start_time,omitempty"`
	EndTime     *time.Time          `json:"end_time,omitempty"`
	HasFindings *bool               `json:"has_findings,omitempty"`
	HasCritical *bool               `json:"has_critical,omitempty"`
}

// ModuleFilter defines filtering options for modules
type ModuleFilter struct {
	Name       string `json:"name,omitempty"`
	Enabled    *bool  `json:"enabled,omitempty"`
	Capability string `json:"capability,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Author     string `json:"author,omitempty"`
	Version    string `json:"version,omitempty"`
}

// FindingFilter defines filtering options for findings
type FindingFilter struct {
	ScanID    string               `json:"scan_id,omitempty"`
	Target    string               `json:"target,omitempty"`
	Severity  entities.Severity    `json:"severity,omitempty"`
	Type      entities.FindingType `json:"type,omitempty"`
	Module    string               `json:"module,omitempty"`
	Tag       string               `json:"tag,omitempty"`
	HasCVSS   *bool                `json:"has_cvss,omitempty"`
	MinCVSS   *float64             `json:"min_cvss,omitempty"`
	MaxCVSS   *float64             `json:"max_cvss,omitempty"`
	StartTime *time.Time           `json:"start_time,omitempty"`
	EndTime   *time.Time           `json:"end_time,omitempty"`
}

// TargetFilter defines filtering options for targets
type TargetFilter struct {
	Type        entities.TargetType `json:"type,omitempty"`
	Host        string              `json:"host,omitempty"`
	Port        *int                `json:"port,omitempty"`
	Scheme      string              `json:"scheme,omitempty"`
	IsValid     *bool               `json:"is_valid,omitempty"`
	HasResolved *bool               `json:"has_resolved,omitempty"`
}

// Pagination defines pagination parameters
type Pagination struct {
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	SortBy string `json:"sort_by,omitempty"`
	Order  string `json:"order,omitempty"` // "asc" or "desc"
}

// TimeRange defines a time range for filtering
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Statistics structures

// ScanStats provides aggregated scan statistics
type ScanStats struct {
	Total              int64                   `json:"total"`
	Completed          int64                   `json:"completed"`
	Failed             int64                   `json:"failed"`
	Running            int64                   `json:"running"`
	ByStatus           map[string]int64        `json:"by_status"`
	ByGrade            map[string]int64        `json:"by_grade"`
	ByModule           map[string]int64        `json:"by_module"`
	AverageScore       float64                 `json:"average_score"`
	AverageDuration    time.Duration           `json:"average_duration"`
	TotalFindings      int64                   `json:"total_findings"`
	FindingsBySeverity map[string]int64        `json:"findings_by_severity"`
	TopTargets         []TargetStat            `json:"top_targets"`
	TimeDistribution   []TimeDistributionPoint `json:"time_distribution"`
}

// FindingStats provides aggregated finding statistics
type FindingStats struct {
	Total            int64                   `json:"total"`
	BySeverity       map[string]int64        `json:"by_severity"`
	ByType           map[string]int64        `json:"by_type"`
	ByModule         map[string]int64        `json:"by_module"`
	WithCVSS         int64                   `json:"with_cvss"`
	AverageCVSS      float64                 `json:"average_cvss"`
	TopFindings      []FindingStat           `json:"top_findings"`
	TimeDistribution []TimeDistributionPoint `json:"time_distribution"`
}

// TargetStat represents target statistics
type TargetStat struct {
	Target     string    `json:"target"`
	ScanCount  int64     `json:"scan_count"`
	LastScan   time.Time `json:"last_scan"`
	AvgScore   float64   `json:"avg_score"`
	BestGrade  string    `json:"best_grade"`
	WorstGrade string    `json:"worst_grade"`
}

// FindingStat represents finding statistics
type FindingStat struct {
	Title    string    `json:"title"`
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	AvgCVSS  float64   `json:"avg_cvss,omitempty"`
}

// TimeDistributionPoint represents a point in time distribution
type TimeDistributionPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
	Value     float64   `json:"value,omitempty"`
}

// Repository transaction support

// Transaction defines database transaction operations
type Transaction interface {
	// Commit commits the transaction
	Commit() error

	// Rollback rolls back the transaction
	Rollback() error

	// ScanRepository returns a scan repository within this transaction
	ScanRepository() ScanRepository

	// ModuleRepository returns a module repository within this transaction
	ModuleRepository() ModuleRepository

	// FindingRepository returns a finding repository within this transaction
	FindingRepository() FindingRepository

	// TargetRepository returns a target repository within this transaction
	TargetRepository() TargetRepository
}

// TransactionManager manages database transactions
type TransactionManager interface {
	// Begin starts a new transaction
	Begin(ctx context.Context) (Transaction, error)

	// WithTransaction executes a function within a transaction
	WithTransaction(ctx context.Context, fn func(tx Transaction) error) error
}

// Repository health and monitoring

// RepositoryHealth represents the health status of repositories
type RepositoryHealth struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
}

// RepositoryMetrics represents repository performance metrics
type RepositoryMetrics struct {
	TotalOperations int64         `json:"total_operations"`
	SuccessfulOps   int64         `json:"successful_operations"`
	FailedOps       int64         `json:"failed_operations"`
	AverageLatency  time.Duration `json:"average_latency"`
	ConnectionPool  PoolMetrics   `json:"connection_pool,omitempty"`
	LastReset       time.Time     `json:"last_reset"`
}

// PoolMetrics represents connection pool metrics
type PoolMetrics struct {
	Active   int `json:"active"`
	Idle     int `json:"idle"`
	Total    int `json:"total"`
	MaxConns int `json:"max_connections"`
}

// HealthChecker provides health checking for repositories
type HealthChecker interface {
	// Check performs a health check
	Check(ctx context.Context) *RepositoryHealth

	// GetMetrics returns current metrics
	GetMetrics() *RepositoryMetrics

	// Reset resets the metrics
	Reset()
}

// Migration support

// Migration represents a database migration
type Migration struct {
	Version     int64     `json:"version"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Up          string    `json:"up"`
	Down        string    `json:"down"`
	CreatedAt   time.Time `json:"created_at"`
}

// MigrationManager handles database migrations
type MigrationManager interface {
	// GetCurrent returns the current migration version
	GetCurrent(ctx context.Context) (int64, error)

	// GetPending returns pending migrations
	GetPending(ctx context.Context) ([]*Migration, error)

	// Apply applies a migration
	Apply(ctx context.Context, migration *Migration) error

	// Rollback rolls back a migration
	Rollback(ctx context.Context, migration *Migration) error

	// GetHistory returns migration history
	GetHistory(ctx context.Context) ([]*Migration, error)
}
