package entities

import (
	"fmt"
	"time"
)

// ModuleStatus represents the status of a scan module
type ModuleStatus int

const (
	ModuleStatusPending ModuleStatus = iota + 1
	ModuleStatusRunning
	ModuleStatusCompleted
	ModuleStatusFailed
	ModuleStatusCanceled
	ModuleStatusSkipped
)

func (ms ModuleStatus) String() string {
	switch ms {
	case ModuleStatusPending:
		return "pending"
	case ModuleStatusRunning:
		return "running"
	case ModuleStatusCompleted:
		return "completed"
	case ModuleStatusFailed:
		return "failed"
	case ModuleStatusCanceled:
		return "canceled"
	case ModuleStatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// IsTerminal checks if the status is terminal (scan finished)
func (ms ModuleStatus) IsTerminal() bool {
	return ms == ModuleStatusCompleted ||
		ms == ModuleStatusFailed ||
		ms == ModuleStatusCanceled ||
		ms == ModuleStatusSkipped
}

// ModuleConfig represents the configuration of a module
type ModuleConfig map[string]interface{}

// Get retrieves a configuration value with a default value
func (mc ModuleConfig) Get(key string, defaultValue interface{}) interface{} {
	if value, exists := mc[key]; exists {
		return value
	}
	return defaultValue
}

// GetString retrieves a string value with a default value
func (mc ModuleConfig) GetString(key string, defaultValue string) string {
	if value, exists := mc[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetInt retrieves an int value with a default value
func (mc ModuleConfig) GetInt(key string, defaultValue int) int {
	if value, exists := mc[key]; exists {
		if i, ok := value.(int); ok {
			return i
		}
		if f, ok := value.(float64); ok {
			return int(f)
		}
	}
	return defaultValue
}

// GetBool retrieves a bool value with a default value
func (mc ModuleConfig) GetBool(key string, defaultValue bool) bool {
	if value, exists := mc[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// Module represents a scan module with its metadata
type Module struct {
	name         string
	version      string
	description  string
	author       string
	enabled      bool
	config       ModuleConfig
	capabilities []string
	dependencies []string
	tags         []string
	createdAt    time.Time
	updatedAt    time.Time
}

// NewModule creates a new module
func NewModule(name, version, description, author string) (*Module, error) {
	if name == "" {
		return nil, fmt.Errorf("module name cannot be empty")
	}
	if version == "" {
		return nil, fmt.Errorf("module version cannot be empty")
	}
	if description == "" {
		return nil, fmt.Errorf("module description cannot be empty")
	}

	now := time.Now().UTC()
	return &Module{
		name:         name,
		version:      version,
		description:  description,
		author:       author,
		enabled:      true,
		config:       make(ModuleConfig),
		capabilities: make([]string, 0),
		dependencies: make([]string, 0),
		tags:         make([]string, 0),
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

// Getters
func (m *Module) Name() string           { return m.name }
func (m *Module) Version() string        { return m.version }
func (m *Module) Description() string    { return m.description }
func (m *Module) Author() string         { return m.author }
func (m *Module) Enabled() bool          { return m.enabled }
func (m *Module) Config() ModuleConfig   { return m.config }
func (m *Module) Capabilities() []string { return m.capabilities }
func (m *Module) Dependencies() []string { return m.dependencies }
func (m *Module) Tags() []string         { return m.tags }
func (m *Module) CreatedAt() time.Time   { return m.createdAt }
func (m *Module) UpdatedAt() time.Time   { return m.updatedAt }

// Setters with validation
func (m *Module) SetEnabled(enabled bool) {
	m.enabled = enabled
	m.updatedAt = time.Now().UTC()
}

func (m *Module) SetConfig(config ModuleConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	m.config = config
	m.updatedAt = time.Now().UTC()
	return nil
}

func (m *Module) UpdateConfig(key string, value interface{}) error {
	if key == "" {
		return fmt.Errorf("config key cannot be empty")
	}
	if m.config == nil {
		m.config = make(ModuleConfig)
	}
	m.config[key] = value
	m.updatedAt = time.Now().UTC()
	return nil
}

func (m *Module) AddCapability(capability string) error {
	if capability == "" {
		return fmt.Errorf("capability cannot be empty")
	}
	// Avoid duplicates
	for _, existing := range m.capabilities {
		if existing == capability {
			return nil
		}
	}
	m.capabilities = append(m.capabilities, capability)
	m.updatedAt = time.Now().UTC()
	return nil
}

func (m *Module) AddDependency(dependency string) error {
	if dependency == "" {
		return fmt.Errorf("dependency cannot be empty")
	}
	// Avoid duplicates
	for _, existing := range m.dependencies {
		if existing == dependency {
			return nil
		}
	}
	m.dependencies = append(m.dependencies, dependency)
	m.updatedAt = time.Now().UTC()
	return nil
}

func (m *Module) AddTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	// Avoid duplicates
	for _, existing := range m.tags {
		if existing == tag {
			return nil
		}
	}
	m.tags = append(m.tags, tag)
	m.updatedAt = time.Now().UTC()
	return nil
}

// Business methods
func (m *Module) HasCapability(capability string) bool {
	for _, cap := range m.capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

func (m *Module) HasDependency(dependency string) bool {
	for _, dep := range m.dependencies {
		if dep == dependency {
			return true
		}
	}
	return false
}

func (m *Module) HasTag(tag string) bool {
	for _, t := range m.tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (m *Module) IsCompatibleWith(target *Target) bool {
	// Compatibility logic based on capabilities and target type
	switch target.Type() {
	case TargetTypeIP, TargetTypeCIDR:
		return m.HasCapability("network") || m.HasCapability("ip")
	case TargetTypeDomain:
		return m.HasCapability("dns") || m.HasCapability("domain") || m.HasCapability("network")
	case TargetTypeURL:
		return m.HasCapability("http") || m.HasCapability("web") || m.HasCapability("ssl")
	default:
		return false
	}
}

func (m *Module) FullName() string {
	return fmt.Sprintf("%s@%s", m.name, m.version)
}

// String implements the Stringer interface
func (m *Module) String() string {
	status := "enabled"
	if !m.enabled {
		status = "disabled"
	}
	return fmt.Sprintf("Module{name=%s, version=%s, status=%s}",
		m.name, m.version, status)
}

// ToMap converts the module to a map for serialization
func (m *Module) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"name":         m.name,
		"version":      m.version,
		"description":  m.description,
		"author":       m.author,
		"enabled":      m.enabled,
		"config":       m.config,
		"capabilities": m.capabilities,
		"dependencies": m.dependencies,
		"tags":         m.tags,
		"created_at":   m.createdAt.Format(time.RFC3339),
		"updated_at":   m.updatedAt.Format(time.RFC3339),
	}
}

// ModuleExecution represents the execution of a module on a target
type ModuleExecution struct {
	id           string
	module       *Module
	target       *Target
	status       ModuleStatus
	startTime    time.Time
	endTime      time.Time
	duration     time.Duration
	findings     []*Finding
	errors       []string
	metadata     map[string]interface{}
	progress     int // 0-100
	lastActivity time.Time
}

// NewModuleExecution creates a new module execution
func NewModuleExecution(id string, module *Module, target *Target) (*ModuleExecution, error) {
	if id == "" {
		return nil, fmt.Errorf("execution ID cannot be empty")
	}
	if module == nil {
		return nil, fmt.Errorf("module cannot be nil")
	}
	if target == nil {
		return nil, fmt.Errorf("target cannot be nil")
	}

	return &ModuleExecution{
		id:           id,
		module:       module,
		target:       target,
		status:       ModuleStatusPending,
		findings:     make([]*Finding, 0),
		errors:       make([]string, 0),
		metadata:     make(map[string]interface{}),
		progress:     0,
		lastActivity: time.Now().UTC(),
	}, nil
}

// Getters
func (me *ModuleExecution) ID() string                       { return me.id }
func (me *ModuleExecution) Module() *Module                  { return me.module }
func (me *ModuleExecution) Target() *Target                  { return me.target }
func (me *ModuleExecution) Status() ModuleStatus             { return me.status }
func (me *ModuleExecution) StartTime() time.Time             { return me.startTime }
func (me *ModuleExecution) EndTime() time.Time               { return me.endTime }
func (me *ModuleExecution) Duration() time.Duration          { return me.duration }
func (me *ModuleExecution) Findings() []*Finding             { return me.findings }
func (me *ModuleExecution) Errors() []string                 { return me.errors }
func (me *ModuleExecution) Metadata() map[string]interface{} { return me.metadata }
func (me *ModuleExecution) Progress() int                    { return me.progress }
func (me *ModuleExecution) LastActivity() time.Time          { return me.lastActivity }

// Lifecycle methods
func (me *ModuleExecution) Start() error {
	if me.status != ModuleStatusPending {
		return fmt.Errorf("cannot start execution in %s status", me.status.String())
	}
	me.status = ModuleStatusRunning
	me.startTime = time.Now().UTC()
	me.lastActivity = me.startTime
	me.progress = 0
	return nil
}

func (me *ModuleExecution) Complete() error {
	if me.status != ModuleStatusRunning {
		return fmt.Errorf("cannot complete execution in %s status", me.status.String())
	}
	me.status = ModuleStatusCompleted
	me.endTime = time.Now().UTC()
	me.duration = me.endTime.Sub(me.startTime)
	me.progress = 100
	me.lastActivity = me.endTime
	return nil
}

func (me *ModuleExecution) Fail(reason string) error {
	if me.status.IsTerminal() {
		return fmt.Errorf("cannot fail execution in %s status", me.status.String())
	}
	me.status = ModuleStatusFailed
	me.endTime = time.Now().UTC()
	if !me.startTime.IsZero() {
		me.duration = me.endTime.Sub(me.startTime)
	}
	me.lastActivity = me.endTime
	if reason != "" {
		me.AddError(reason)
	}
	return nil
}

func (me *ModuleExecution) Cancel() error {
	if me.status.IsTerminal() {
		return fmt.Errorf("cannot cancel execution in %s status", me.status.String())
	}
	me.status = ModuleStatusCanceled
	me.endTime = time.Now().UTC()
	if !me.startTime.IsZero() {
		me.duration = me.endTime.Sub(me.startTime)
	}
	me.lastActivity = me.endTime
	return nil
}

func (me *ModuleExecution) Skip(reason string) error {
	if me.status != ModuleStatusPending {
		return fmt.Errorf("cannot skip execution in %s status", me.status.String())
	}
	me.status = ModuleStatusSkipped
	me.endTime = time.Now().UTC()
	me.lastActivity = me.endTime
	if reason != "" {
		me.AddError(reason)
	}
	return nil
}

// Findings and errors management
func (me *ModuleExecution) AddFinding(finding *Finding) error {
	if finding == nil {
		return fmt.Errorf("finding cannot be nil")
	}
	me.findings = append(me.findings, finding)
	me.lastActivity = time.Now().UTC()
	return nil
}

func (me *ModuleExecution) AddError(err string) error {
	if err == "" {
		return fmt.Errorf("error message cannot be empty")
	}
	me.errors = append(me.errors, err)
	me.lastActivity = time.Now().UTC()
	return nil
}

func (me *ModuleExecution) SetProgress(progress int) error {
	if progress < 0 || progress > 100 {
		return fmt.Errorf("progress must be between 0 and 100")
	}
	me.progress = progress
	me.lastActivity = time.Now().UTC()
	return nil
}

func (me *ModuleExecution) SetMetadata(key string, value interface{}) error {
	if key == "" {
		return fmt.Errorf("metadata key cannot be empty")
	}
	me.metadata[key] = value
	me.lastActivity = time.Now().UTC()
	return nil
}

// Utility methods
func (me *ModuleExecution) FindingCount() int {
	return len(me.findings)
}

func (me *ModuleExecution) ErrorCount() int {
	return len(me.errors)
}

func (me *ModuleExecution) HasFindings() bool {
	return len(me.findings) > 0
}

func (me *ModuleExecution) HasErrors() bool {
	return len(me.errors) > 0
}

func (me *ModuleExecution) IsRunning() bool {
	return me.status == ModuleStatusRunning
}

func (me *ModuleExecution) IsCompleted() bool {
	return me.status == ModuleStatusCompleted
}

func (me *ModuleExecution) IsFailed() bool {
	return me.status == ModuleStatusFailed
}

func (me *ModuleExecution) IsTerminal() bool {
	return me.status.IsTerminal()
}

// FindingsBySeverity returns findings grouped by severity
func (me *ModuleExecution) FindingsBySeverity() map[Severity][]*Finding {
	result := make(map[Severity][]*Finding)
	for _, finding := range me.findings {
		severity := finding.Severity()
		if result[severity] == nil {
			result[severity] = make([]*Finding, 0)
		}
		result[severity] = append(result[severity], finding)
	}
	return result
}

// CriticalFindings returns critical findings
func (me *ModuleExecution) CriticalFindings() []*Finding {
	var critical []*Finding
	for _, finding := range me.findings {
		if finding.IsCritical() {
			critical = append(critical, finding)
		}
	}
	return critical
}

// HighRiskFindings returns high risk findings
func (me *ModuleExecution) HighRiskFindings() []*Finding {
	var highRisk []*Finding
	for _, finding := range me.findings {
		if finding.IsHighRisk() {
			highRisk = append(highRisk, finding)
		}
	}
	return highRisk
}

// String implements the Stringer interface
func (me *ModuleExecution) String() string {
	return fmt.Sprintf("ModuleExecution{id=%s, module=%s, target=%s, status=%s, findings=%d}",
		me.id, me.module.Name(), me.target.Host(), me.status.String(), me.FindingCount())
}

// ToMap converts the execution to a map for serialization
func (me *ModuleExecution) ToMap() map[string]interface{} {
	findingMaps := make([]map[string]interface{}, len(me.findings))
	for i, finding := range me.findings {
		findingMaps[i] = finding.ToMap()
	}

	result := map[string]interface{}{
		"id":            me.id,
		"module":        me.module.Name(),
		"target":        me.target.Original(),
		"status":        me.status.String(),
		"start_time":    me.startTime.Format(time.RFC3339),
		"findings":      findingMaps,
		"errors":        me.errors,
		"metadata":      me.metadata,
		"progress":      me.progress,
		"last_activity": me.lastActivity.Format(time.RFC3339),
	}

	if !me.endTime.IsZero() {
		result["end_time"] = me.endTime.Format(time.RFC3339)
		result["duration"] = me.duration.Milliseconds()
	}

	return result
}
