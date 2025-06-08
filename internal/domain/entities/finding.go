package entities

import (
	"fmt"
	"time"
)

// Severity represents the severity of a security finding
type Severity int

const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Score returns a numeric score for the severity
func (s Severity) Score() int {
	return int(s)
}

// FindingType represents the type of finding
type FindingType int

const (
	FindingTypeVulnerability FindingType = iota + 1
	FindingTypeMisconfiguration
	FindingTypeInformation
	FindingTypeCompliance
	FindingTypeBestPractice
)

func (ft FindingType) String() string {
	switch ft {
	case FindingTypeVulnerability:
		return "vulnerability"
	case FindingTypeMisconfiguration:
		return "misconfiguration"
	case FindingTypeInformation:
		return "information"
	case FindingTypeCompliance:
		return "compliance"
	case FindingTypeBestPractice:
		return "best_practice"
	default:
		return "unknown"
	}
}

// Evidence represents the evidence of a finding
type Evidence map[string]interface{}

// CVSSScore represents a CVSS score
type CVSSScore struct {
	Version float64 `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Rating  string  `json:"rating"`
}

// Finding represents a security finding
type Finding struct {
	id           string
	findingType  FindingType
	severity     Severity
	title        string
	description  string
	target       string
	evidence     Evidence
	remediation  string
	references   []string
	cvss         *CVSSScore
	tags         []string
	timestamp    time.Time
	moduleSource string
}

// NewFinding creates a new security finding
func NewFinding(
	id string,
	findingType FindingType,
	severity Severity,
	title string,
	description string,
	target string,
	moduleSource string,
) (*Finding, error) {
	if id == "" {
		return nil, fmt.Errorf("finding ID cannot be empty")
	}
	if title == "" {
		return nil, fmt.Errorf("finding title cannot be empty")
	}
	if target == "" {
		return nil, fmt.Errorf("finding target cannot be empty")
	}
	if moduleSource == "" {
		return nil, fmt.Errorf("finding module source cannot be empty")
	}

	return &Finding{
		id:           id,
		findingType:  findingType,
		severity:     severity,
		title:        title,
		description:  description,
		target:       target,
		evidence:     make(Evidence),
		references:   make([]string, 0),
		tags:         make([]string, 0),
		timestamp:    time.Now().UTC(),
		moduleSource: moduleSource,
	}, nil
}

func (f *Finding) ID() string           { return f.id }
func (f *Finding) Type() FindingType    { return f.findingType }
func (f *Finding) Severity() Severity   { return f.severity }
func (f *Finding) Title() string        { return f.title }
func (f *Finding) Description() string  { return f.description }
func (f *Finding) Target() string       { return f.target }
func (f *Finding) Evidence() Evidence   { return f.evidence }
func (f *Finding) Remediation() string  { return f.remediation }
func (f *Finding) References() []string { return f.references }
func (f *Finding) CVSS() *CVSSScore     { return f.cvss }
func (f *Finding) Tags() []string       { return f.tags }
func (f *Finding) Timestamp() time.Time { return f.timestamp }
func (f *Finding) ModuleSource() string { return f.moduleSource }

// SetRemediation Setters with validation
func (f *Finding) SetRemediation(remediation string) {
	f.remediation = remediation
}

func (f *Finding) AddEvidence(key string, value interface{}) error {
	if key == "" {
		return fmt.Errorf("evidence key cannot be empty")
	}
	if f.evidence == nil {
		f.evidence = make(Evidence)
	}
	f.evidence[key] = value
	return nil
}

func (f *Finding) AddReference(reference string) error {
	if reference == "" {
		return fmt.Errorf("reference cannot be empty")
	}
	f.references = append(f.references, reference)
	return nil
}

func (f *Finding) AddTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	// Avoid duplicates
	for _, existingTag := range f.tags {
		if existingTag == tag {
			return nil // Already present
		}
	}
	f.tags = append(f.tags, tag)
	return nil
}

func (f *Finding) SetCVSS(cvss *CVSSScore) error {
	if cvss != nil {
		if cvss.Version <= 0 {
			return fmt.Errorf("CVSS version must be positive")
		}
		if cvss.Score < 0 || cvss.Score > 10 {
			return fmt.Errorf("CVSS score must be between 0 and 10")
		}
	}
	f.cvss = cvss
	return nil
}

// Business methods
func (f *Finding) IsHighRisk() bool {
	return f.severity >= SeverityHigh
}

func (f *Finding) IsCritical() bool {
	return f.severity == SeverityCritical
}

func (f *Finding) HasEvidence() bool {
	return len(f.evidence) > 0
}

func (f *Finding) HasRemediation() bool {
	return f.remediation != ""
}

// String implements the Stringer interface
func (f *Finding) String() string {
	return fmt.Sprintf("[%s] %s - %s (Target: %s)",
		f.severity.String(),
		f.findingType.String(),
		f.title,
		f.target)
}

// ToMap converts the finding to a map for serialization
func (f *Finding) ToMap() map[string]interface{} {
	result := map[string]interface{}{
		"id":            f.id,
		"type":          f.findingType.String(),
		"severity":      f.severity.String(),
		"title":         f.title,
		"description":   f.description,
		"target":        f.target,
		"evidence":      f.evidence,
		"remediation":   f.remediation,
		"references":    f.references,
		"tags":          f.tags,
		"timestamp":     f.timestamp.Format(time.RFC3339),
		"module_source": f.moduleSource,
	}

	if f.cvss != nil {
		result["cvss"] = map[string]interface{}{
			"version": f.cvss.Version,
			"vector":  f.cvss.Vector,
			"score":   f.cvss.Score,
			"rating":  f.cvss.Rating,
		}
	}

	return result
}

// FindingBuilder allows building findings in a fluent way
type FindingBuilder struct {
	finding *Finding
	err     error
}

// NewFindingBuilder creates a new builder
func NewFindingBuilder() *FindingBuilder {
	return &FindingBuilder{}
}

func (fb *FindingBuilder) WithID(id string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if id == "" {
		fb.err = fmt.Errorf("finding ID cannot be empty")
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.id = id
	return fb
}

func (fb *FindingBuilder) WithType(findingType FindingType) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.findingType = findingType
	return fb
}

func (fb *FindingBuilder) WithSeverity(severity Severity) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.severity = severity
	return fb
}

func (fb *FindingBuilder) WithTitle(title string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if title == "" {
		fb.err = fmt.Errorf("finding title cannot be empty")
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.title = title
	return fb
}

func (fb *FindingBuilder) WithDescription(description string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.description = description
	return fb
}

func (fb *FindingBuilder) WithTarget(target string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if target == "" {
		fb.err = fmt.Errorf("finding target cannot be empty")
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.target = target
	return fb
}

func (fb *FindingBuilder) WithModuleSource(moduleSource string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if moduleSource == "" {
		fb.err = fmt.Errorf("finding module source cannot be empty")
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.moduleSource = moduleSource
	return fb
}

func (fb *FindingBuilder) WithRemediation(remediation string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	fb.finding.remediation = remediation
	return fb
}

func (fb *FindingBuilder) WithEvidence(evidence Evidence) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	if fb.finding.evidence == nil {
		fb.finding.evidence = make(Evidence)
	}
	for k, v := range evidence {
		fb.finding.evidence[k] = v
	}
	return fb
}

func (fb *FindingBuilder) WithTags(tags ...string) *FindingBuilder {
	if fb.err != nil {
		return fb
	}
	if fb.finding == nil {
		fb.finding = &Finding{}
	}
	if fb.finding.tags == nil {
		fb.finding.tags = make([]string, 0)
	}
	fb.finding.tags = append(fb.finding.tags, tags...)
	return fb
}

func (fb *FindingBuilder) Build() (*Finding, error) {
	if fb.err != nil {
		return nil, fb.err
	}
	if fb.finding == nil {
		return nil, fmt.Errorf("no finding data provided")
	}

	// Final validation
	if fb.finding.id == "" {
		return nil, fmt.Errorf("finding ID is required")
	}
	if fb.finding.title == "" {
		return nil, fmt.Errorf("finding title is required")
	}
	if fb.finding.target == "" {
		return nil, fmt.Errorf("finding target is required")
	}
	if fb.finding.moduleSource == "" {
		return nil, fmt.Errorf("finding module source is required")
	}

	// Initialize missing fields
	if fb.finding.evidence == nil {
		fb.finding.evidence = make(Evidence)
	}
	if fb.finding.references == nil {
		fb.finding.references = make([]string, 0)
	}
	if fb.finding.tags == nil {
		fb.finding.tags = make([]string, 0)
	}
	if fb.finding.timestamp.IsZero() {
		fb.finding.timestamp = time.Now().UTC()
	}

	return fb.finding, nil
}
