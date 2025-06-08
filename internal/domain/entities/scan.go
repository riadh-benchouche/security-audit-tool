package entities

import (
	"fmt"
	"strings"
	"time"
)

// ScanStatus represents the overall status of a scan
type ScanStatus int

const (
	ScanStatusPending ScanStatus = iota + 1
	ScanStatusRunning
	ScanStatusCompleted
	ScanStatusFailed
	ScanStatusCanceled
	ScanStatusPartial
)

func (ss ScanStatus) String() string {
	switch ss {
	case ScanStatusPending:
		return "pending"
	case ScanStatusRunning:
		return "running"
	case ScanStatusCompleted:
		return "completed"
	case ScanStatusFailed:
		return "failed"
	case ScanStatusCanceled:
		return "canceled"
	case ScanStatusPartial:
		return "partial"
	default:
		return "unknown"
	}
}

// IsTerminal checks if the status is terminal
func (ss ScanStatus) IsTerminal() bool {
	return ss == ScanStatusCompleted ||
		ss == ScanStatusFailed ||
		ss == ScanStatusCanceled ||
		ss == ScanStatusPartial
}

// Grade represents the overall security grade
type Grade string

const (
	GradeA Grade = "A"
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F"
)

// Score returns the numeric score associated with the grade
func (g Grade) Score() int {
	switch g {
	case GradeA:
		return 90
	case GradeB:
		return 80
	case GradeC:
		return 70
	case GradeD:
		return 60
	case GradeF:
		return 50
	default:
		return 0
	}
}

// ScanSummary represents the summary of a scan
type ScanSummary struct {
	totalFindings      int
	findingsBySeverity map[Severity]int
	findingsByType     map[FindingType]int
	modulesExecuted    []string
	modulesFailed      []string
	score              int
	grade              Grade
	executionTime      time.Duration
	avgResponseTime    time.Duration
	successRate        float64
}

// NewScanSummary creates a new scan summary
func NewScanSummary() *ScanSummary {
	return &ScanSummary{
		findingsBySeverity: make(map[Severity]int),
		findingsByType:     make(map[FindingType]int),
		modulesExecuted:    make([]string, 0),
		modulesFailed:      make([]string, 0),
	}
}

// Getters for ScanSummary
func (ss *ScanSummary) TotalFindings() int                   { return ss.totalFindings }
func (ss *ScanSummary) FindingsBySeverity() map[Severity]int { return ss.findingsBySeverity }
func (ss *ScanSummary) FindingsByType() map[FindingType]int  { return ss.findingsByType }
func (ss *ScanSummary) ModulesExecuted() []string            { return ss.modulesExecuted }
func (ss *ScanSummary) ModulesFailed() []string              { return ss.modulesFailed }
func (ss *ScanSummary) Score() int                           { return ss.score }
func (ss *ScanSummary) Grade() Grade                         { return ss.grade }
func (ss *ScanSummary) ExecutionTime() time.Duration         { return ss.executionTime }
func (ss *ScanSummary) AvgResponseTime() time.Duration       { return ss.avgResponseTime }
func (ss *ScanSummary) SuccessRate() float64                 { return ss.successRate }

// Scan represents a complete security scan
type Scan struct {
	id               string
	target           *Target
	requestedModules []string
	executions       map[string]*ModuleExecution
	status           ScanStatus
	startTime        time.Time
	endTime          time.Time
	duration         time.Duration
	summary          *ScanSummary
	options          map[string]interface{}
	createdBy        string
	tags             []string
	lastActivity     time.Time
}

// NewScan creates a new scan
func NewScan(id string, target *Target, modules []string, createdBy string) (*Scan, error) {
	if id == "" {
		return nil, fmt.Errorf("scan ID cannot be empty")
	}
	if target == nil {
		return nil, fmt.Errorf("target cannot be nil")
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("at least one module must be specified")
	}

	return &Scan{
		id:               id,
		target:           target,
		requestedModules: modules,
		executions:       make(map[string]*ModuleExecution),
		status:           ScanStatusPending,
		summary:          NewScanSummary(),
		options:          make(map[string]interface{}),
		createdBy:        createdBy,
		tags:             make([]string, 0),
		lastActivity:     time.Now().UTC(),
	}, nil
}

// Getters
func (s *Scan) ID() string                              { return s.id }
func (s *Scan) Target() *Target                         { return s.target }
func (s *Scan) RequestedModules() []string              { return s.requestedModules }
func (s *Scan) Executions() map[string]*ModuleExecution { return s.executions }
func (s *Scan) Status() ScanStatus                      { return s.status }
func (s *Scan) StartTime() time.Time                    { return s.startTime }
func (s *Scan) EndTime() time.Time                      { return s.endTime }
func (s *Scan) Duration() time.Duration                 { return s.duration }
func (s *Scan) Summary() *ScanSummary                   { return s.summary }
func (s *Scan) Options() map[string]interface{}         { return s.options }
func (s *Scan) CreatedBy() string                       { return s.createdBy }
func (s *Scan) Tags() []string                          { return s.tags }
func (s *Scan) LastActivity() time.Time                 { return s.lastActivity }

// Lifecycle methods
func (s *Scan) Start() error {
	if s.status != ScanStatusPending {
		return fmt.Errorf("cannot start scan in %s status", s.status.String())
	}
	s.status = ScanStatusRunning
	s.startTime = time.Now().UTC()
	s.lastActivity = s.startTime
	return nil
}

func (s *Scan) Complete() error {
	if s.status != ScanStatusRunning {
		return fmt.Errorf("cannot complete scan in %s status", s.status.String())
	}

	// Check if all modules are completed
	allCompleted := true
	hasFailures := false

	for _, execution := range s.executions {
		if !execution.IsTerminal() {
			allCompleted = false
			break
		}
		if execution.IsFailed() {
			hasFailures = true
		}
	}

	if !allCompleted {
		return fmt.Errorf("cannot complete scan: some modules are still running")
	}

	s.endTime = time.Now().UTC()
	s.duration = s.endTime.Sub(s.startTime)
	s.lastActivity = s.endTime

	// Determine the final status
	if hasFailures && len(s.GetCompletedExecutions()) > 0 {
		s.status = ScanStatusPartial
	} else if hasFailures {
		s.status = ScanStatusFailed
	} else {
		s.status = ScanStatusCompleted
	}

	// Generate the summary
	s.generateSummary()

	return nil
}

func (s *Scan) Fail(reason string) error {
	if s.status.IsTerminal() {
		return fmt.Errorf("cannot fail scan in %s status", s.status.String())
	}

	s.status = ScanStatusFailed
	s.endTime = time.Now().UTC()
	if !s.startTime.IsZero() {
		s.duration = s.endTime.Sub(s.startTime)
	}
	s.lastActivity = s.endTime

	// Cancel all running executions
	for _, execution := range s.executions {
		if execution.IsRunning() {
			execution.Cancel()
		}
	}

	s.generateSummary()
	return nil
}

func (s *Scan) Cancel() error {
	if s.status.IsTerminal() {
		return fmt.Errorf("cannot cancel scan in %s status", s.status.String())
	}

	s.status = ScanStatusCanceled
	s.endTime = time.Now().UTC()
	if !s.startTime.IsZero() {
		s.duration = s.endTime.Sub(s.startTime)
	}
	s.lastActivity = s.endTime

	// Cancel all running executions
	for _, execution := range s.executions {
		if execution.IsRunning() {
			execution.Cancel()
		}
	}

	s.generateSummary()
	return nil
}

// Module execution management
func (s *Scan) AddExecution(execution *ModuleExecution) error {
	if execution == nil {
		return fmt.Errorf("execution cannot be nil")
	}

	moduleName := execution.Module().Name()
	s.executions[moduleName] = execution
	s.lastActivity = time.Now().UTC()
	return nil
}

func (s *Scan) GetExecution(moduleName string) *ModuleExecution {
	return s.executions[moduleName]
}

func (s *Scan) HasExecution(moduleName string) bool {
	_, exists := s.executions[moduleName]
	return exists
}

// Utility methods for executions
func (s *Scan) GetRunningExecutions() []*ModuleExecution {
	var running []*ModuleExecution
	for _, execution := range s.executions {
		if execution.IsRunning() {
			running = append(running, execution)
		}
	}
	return running
}

func (s *Scan) GetCompletedExecutions() []*ModuleExecution {
	var completed []*ModuleExecution
	for _, execution := range s.executions {
		if execution.IsCompleted() {
			completed = append(completed, execution)
		}
	}
	return completed
}

func (s *Scan) GetFailedExecutions() []*ModuleExecution {
	var failed []*ModuleExecution
	for _, execution := range s.executions {
		if execution.IsFailed() {
			failed = append(failed, execution)
		}
	}
	return failed
}

// Methods for findings
func (s *Scan) GetAllFindings() []*Finding {
	var allFindings []*Finding
	for _, execution := range s.executions {
		allFindings = append(allFindings, execution.Findings()...)
	}
	return allFindings
}

func (s *Scan) GetFindingsBySeverity(severity Severity) []*Finding {
	var findings []*Finding
	for _, execution := range s.executions {
		for _, finding := range execution.Findings() {
			if finding.Severity() == severity {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func (s *Scan) GetCriticalFindings() []*Finding {
	return s.GetFindingsBySeverity(SeverityCritical)
}

func (s *Scan) GetHighRiskFindings() []*Finding {
	var highRisk []*Finding
	for _, execution := range s.executions {
		highRisk = append(highRisk, execution.HighRiskFindings()...)
	}
	return highRisk
}

func (s *Scan) GetFindingsByModule(moduleName string) []*Finding {
	if execution, exists := s.executions[moduleName]; exists {
		return execution.Findings()
	}
	return []*Finding{}
}

// Options management
func (s *Scan) SetOption(key string, value interface{}) error {
	if key == "" {
		return fmt.Errorf("option key cannot be empty")
	}
	s.options[key] = value
	s.lastActivity = time.Now().UTC()
	return nil
}

func (s *Scan) GetOption(key string, defaultValue interface{}) interface{} {
	if value, exists := s.options[key]; exists {
		return value
	}
	return defaultValue
}

func (s *Scan) GetStringOption(key string, defaultValue string) string {
	if value, exists := s.options[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return defaultValue
}

func (s *Scan) GetIntOption(key string, defaultValue int) int {
	if value, exists := s.options[key]; exists {
		if i, ok := value.(int); ok {
			return i
		}
		if f, ok := value.(float64); ok {
			return int(f)
		}
	}
	return defaultValue
}

func (s *Scan) GetBoolOption(key string, defaultValue bool) bool {
	if value, exists := s.options[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// Tags management
func (s *Scan) AddTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	// Avoid duplicates
	for _, existingTag := range s.tags {
		if existingTag == tag {
			return nil
		}
	}
	s.tags = append(s.tags, tag)
	s.lastActivity = time.Now().UTC()
	return nil
}

func (s *Scan) HasTag(tag string) bool {
	for _, t := range s.tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (s *Scan) RemoveTag(tag string) bool {
	for i, t := range s.tags {
		if t == tag {
			s.tags = append(s.tags[:i], s.tags[i+1:]...)
			s.lastActivity = time.Now().UTC()
			return true
		}
	}
	return false
}

// State methods
func (s *Scan) IsRunning() bool {
	return s.status == ScanStatusRunning
}

func (s *Scan) IsCompleted() bool {
	return s.status == ScanStatusCompleted
}

func (s *Scan) IsFailed() bool {
	return s.status == ScanStatusFailed
}

func (s *Scan) IsCanceled() bool {
	return s.status == ScanStatusCanceled
}

func (s *Scan) IsPartial() bool {
	return s.status == ScanStatusPartial
}

func (s *Scan) IsTerminal() bool {
	return s.status.IsTerminal()
}

func (s *Scan) HasFailures() bool {
	return len(s.GetFailedExecutions()) > 0
}

func (s *Scan) HasFindings() bool {
	return s.summary.totalFindings > 0
}

func (s *Scan) HasCriticalFindings() bool {
	if count, exists := s.summary.findingsBySeverity[SeverityCritical]; exists {
		return count > 0
	}
	return false
}

// Progress calculations
func (s *Scan) GetProgress() int {
	if len(s.executions) == 0 {
		return 0
	}

	totalProgress := 0
	for _, execution := range s.executions {
		totalProgress += execution.Progress()
	}

	return totalProgress / len(s.executions)
}

func (s *Scan) GetEstimatedTimeRemaining() time.Duration {
	if !s.IsRunning() {
		return 0
	}

	progress := s.GetProgress()
	if progress <= 0 {
		return 0
	}

	elapsed := time.Since(s.startTime)
	estimatedTotal := time.Duration(float64(elapsed) * 100.0 / float64(progress))
	remaining := estimatedTotal - elapsed

	if remaining < 0 {
		return 0
	}

	return remaining
}

// generateSummary generates the scan summary
func (s *Scan) generateSummary() {
	s.summary = NewScanSummary()

	// Collect all statistics
	allFindings := s.GetAllFindings()
	s.summary.totalFindings = len(allFindings)

	// Count by severity and type
	for _, finding := range allFindings {
		s.summary.findingsBySeverity[finding.Severity()]++
		s.summary.findingsByType[finding.Type()]++
	}

	// Executed and failed modules
	for moduleName, execution := range s.executions {
		s.summary.modulesExecuted = append(s.summary.modulesExecuted, moduleName)
		if execution.IsFailed() {
			s.summary.modulesFailed = append(s.summary.modulesFailed, moduleName)
		}
	}

	// Execution time
	s.summary.executionTime = s.duration

	// Success rate
	if len(s.summary.modulesExecuted) > 0 {
		successCount := len(s.summary.modulesExecuted) - len(s.summary.modulesFailed)
		s.summary.successRate = float64(successCount) / float64(len(s.summary.modulesExecuted))
	}

	// Calculate score and grade
	s.calculateSecurityScore()
}

// calculateSecurityScore computes the overall security score
func (s *Scan) calculateSecurityScore() {
	baseScore := 100

	// Penalties by severity
	criticalCount := s.summary.findingsBySeverity[SeverityCritical]
	highCount := s.summary.findingsBySeverity[SeverityHigh]
	mediumCount := s.summary.findingsBySeverity[SeverityMedium]
	lowCount := s.summary.findingsBySeverity[SeverityLow]

	// Weighted penalty system
	penalties := criticalCount*25 + highCount*15 + mediumCount*8 + lowCount*3

	// Bonus for scans without errors
	if len(s.summary.modulesFailed) == 0 && s.summary.totalFindings == 0 {
		baseScore += 5 // Bonus for a perfect scan
	}

	// Penalty for failed modules
	failurePenalty := len(s.summary.modulesFailed) * 10

	s.summary.score = baseScore - penalties - failurePenalty

	// Ensure the score stays within bounds
	if s.summary.score < 0 {
		s.summary.score = 0
	}
	if s.summary.score > 100 {
		s.summary.score = 100
	}

	// Assign a grade based on the score
	s.summary.grade = s.calculateGrade(s.summary.score)
}

// calculateGrade computes the grade based on the score
func (s *Scan) calculateGrade(score int) Grade {
	switch {
	case score >= 90:
		return GradeA
	case score >= 80:
		return GradeB
	case score >= 70:
		return GradeC
	case score >= 60:
		return GradeD
	default:
		return GradeF
	}
}

// Comparison and search methods
func (s *Scan) Equals(other *Scan) bool {
	if other == nil {
		return false
	}
	return s.id == other.id
}

func (s *Scan) MatchesFilters(filters map[string]interface{}) bool {
	// Basic filtering implementation
	if targetFilter, exists := filters["target"]; exists {
		if target, ok := targetFilter.(string); ok {
			if target != "" && !strings.Contains(s.target.Original(), target) {
				return false
			}
		}
	}

	if statusFilter, exists := filters["status"]; exists {
		if status, ok := statusFilter.(string); ok {
			if status != "" && s.status.String() != status {
				return false
			}
		}
	}

	if gradeFilter, exists := filters["grade"]; exists {
		if grade, ok := gradeFilter.(string); ok {
			if grade != "" && string(s.summary.grade) != grade {
				return false
			}
		}
	}

	return true
}

// String implements the Stringer interface
func (s *Scan) String() string {
	return fmt.Sprintf("Scan{id=%s, target=%s, status=%s, modules=%d, findings=%d, grade=%s}",
		s.id, s.target.Host(), s.status.String(), len(s.executions),
		s.summary.totalFindings, s.summary.grade)
}

// ToMap converts the scan to a map for serialization
func (s *Scan) ToMap() map[string]interface{} {
	executionMaps := make(map[string]interface{})
	for name, execution := range s.executions {
		executionMaps[name] = execution.ToMap()
	}

	result := map[string]interface{}{
		"id":                s.id,
		"target":            s.target.ToMap(),
		"requested_modules": s.requestedModules,
		"executions":        executionMaps,
		"status":            s.status.String(),
		"start_time":        s.startTime.Format(time.RFC3339),
		"summary":           s.summaryToMap(),
		"options":           s.options,
		"created_by":        s.createdBy,
		"tags":              s.tags,
		"last_activity":     s.lastActivity.Format(time.RFC3339),
	}

	if !s.endTime.IsZero() {
		result["end_time"] = s.endTime.Format(time.RFC3339)
		result["duration"] = s.duration.Milliseconds()
	}

	if s.IsRunning() {
		result["progress"] = s.GetProgress()
		result["estimated_time_remaining"] = s.GetEstimatedTimeRemaining().Seconds()
	}

	return result
}

// summaryToMap converts the summary to a map
func (s *Scan) summaryToMap() map[string]interface{} {
	severityMap := make(map[string]int)
	for severity, count := range s.summary.findingsBySeverity {
		severityMap[severity.String()] = count
	}

	typeMap := make(map[string]int)
	for findingType, count := range s.summary.findingsByType {
		typeMap[findingType.String()] = count
	}

	return map[string]interface{}{
		"total_findings":       s.summary.totalFindings,
		"findings_by_severity": severityMap,
		"findings_by_type":     typeMap,
		"modules_executed":     s.summary.modulesExecuted,
		"modules_failed":       s.summary.modulesFailed,
		"score":                s.summary.score,
		"grade":                string(s.summary.grade),
		"execution_time":       s.summary.executionTime.Milliseconds(),
		"avg_response_time":    s.summary.avgResponseTime.Milliseconds(),
		"success_rate":         s.summary.successRate,
	}
}

// Clone creates a deep copy of the scan (useful for tests)
func (s *Scan) Clone() *Scan {
	clone := &Scan{
		id:               s.id + "_clone",
		target:           s.target.Clone(),
		requestedModules: make([]string, len(s.requestedModules)),
		executions:       make(map[string]*ModuleExecution),
		status:           s.status,
		startTime:        s.startTime,
		endTime:          s.endTime,
		duration:         s.duration,
		summary:          NewScanSummary(),
		options:          make(map[string]interface{}),
		createdBy:        s.createdBy,
		tags:             make([]string, len(s.tags)),
		lastActivity:     s.lastActivity,
	}

	copy(clone.requestedModules, s.requestedModules)
	copy(clone.tags, s.tags)

	// Copy options
	for k, v := range s.options {
		clone.options[k] = v
	}

	// Copy summary
	*clone.summary = *s.summary
	clone.summary.findingsBySeverity = make(map[Severity]int)
	clone.summary.findingsByType = make(map[FindingType]int)

	for k, v := range s.summary.findingsBySeverity {
		clone.summary.findingsBySeverity[k] = v
	}
	for k, v := range s.summary.findingsByType {
		clone.summary.findingsByType[k] = v
	}

	clone.summary.modulesExecuted = make([]string, len(s.summary.modulesExecuted))
	clone.summary.modulesFailed = make([]string, len(s.summary.modulesFailed))
	copy(clone.summary.modulesExecuted, s.summary.modulesExecuted)
	copy(clone.summary.modulesFailed, s.summary.modulesFailed)

	return clone
}
