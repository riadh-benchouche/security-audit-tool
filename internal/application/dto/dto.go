package dto

import (
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// ScanRequest represents a scan request
type ScanRequest struct {
	Target  string                 `json:"target" validate:"required"`
	Modules []string               `json:"modules" validate:"required,min=1"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ScanID    string                    `json:"scan_id"`
	Target    string                    `json:"target"`
	Status    string                    `json:"status"`
	StartTime time.Time                 `json:"start_time"`
	EndTime   *time.Time                `json:"end_time,omitempty"`
	Duration  *string                   `json:"duration,omitempty"`
	Summary   *ScanSummaryResponse      `json:"summary,omitempty"`
	Modules   []ModuleExecutionResponse `json:"modules"`
	Message   string                    `json:"message,omitempty"`
}

// ScanSummaryResponse represents scan summary
type ScanSummaryResponse struct {
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	Score              int            `json:"score"`
	Grade              string         `json:"grade"`
	ExecutionTime      int64          `json:"execution_time_ms"`
	SuccessRate        float64        `json:"success_rate"`
}

// ModuleExecutionResponse represents module execution
type ModuleExecutionResponse struct {
	Module   string                 `json:"module"`
	Status   string                 `json:"status"`
	Duration string                 `json:"duration"`
	Findings []FindingResponse      `json:"findings"`
	Errors   []string               `json:"errors,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// FindingResponse represents a finding
type FindingResponse struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Target      string                 `json:"target"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ModuleInfoResponse represents module information
type ModuleInfoResponse struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Capabilities []string          `json:"capabilities"`
	Tags         []string          `json:"tags"`
	ConfigSchema map[string]string `json:"config_schema"`
}

// HealthResponse represents health status
type HealthResponse struct {
	Status  string            `json:"status"`
	Message string            `json:"message"`
	Modules map[string]string `json:"modules"`
}

// ToScanResponse converts entities.Scan to ScanResponse
func ToScanResponse(scan *entities.Scan) *ScanResponse {
	response := &ScanResponse{
		ScanID:    scan.ID(),
		Target:    scan.Target().Original(),
		Status:    scan.Status().String(),
		StartTime: scan.StartTime(),
		Modules:   make([]ModuleExecutionResponse, 0),
	}

	// Fix: Créer une variable temporaire pour l'EndTime
	if !scan.EndTime().IsZero() {
		endTime := scan.EndTime()
		response.EndTime = &endTime
		duration := scan.Duration().String()
		response.Duration = &duration
	}

	// Convert summary
	if scan.Summary() != nil {
		summary := scan.Summary()
		severityMap := make(map[string]int)
		for severity, count := range summary.FindingsBySeverity() {
			severityMap[severity.String()] = count
		}

		response.Summary = &ScanSummaryResponse{
			TotalFindings:      summary.TotalFindings(),
			FindingsBySeverity: severityMap,
			Score:              summary.Score(),
			Grade:              string(summary.Grade()),
			ExecutionTime:      summary.ExecutionTime().Milliseconds(),
			SuccessRate:        summary.SuccessRate(),
		}
	}

	// Convert module executions
	for _, execution := range scan.Executions() {
		moduleResponse := ModuleExecutionResponse{
			Module:   execution.Module().Name(),
			Status:   execution.Status().String(),
			Duration: execution.Duration().String(),
			Findings: make([]FindingResponse, 0),
			Errors:   execution.Errors(),
			Metadata: execution.Metadata(),
		}

		// Convert findings
		for _, finding := range execution.Findings() {
			findingResponse := FindingResponse{
				ID:          finding.ID(),
				Type:        finding.Type().String(),
				Severity:    finding.Severity().String(),
				Title:       finding.Title(),
				Description: finding.Description(),
				Target:      finding.Target(),
				Evidence:    finding.Evidence(),
				Remediation: finding.Remediation(),
				Tags:        finding.Tags(),
				Timestamp:   finding.Timestamp(),
			}
			moduleResponse.Findings = append(moduleResponse.Findings, findingResponse)
		}

		response.Modules = append(response.Modules, moduleResponse)
	}

	return response
}

// ToModuleInfoResponse converts interfaces.ScannerInfo to ModuleInfoResponse
func ToModuleInfoResponse(info *interfaces.ScannerInfo) *ModuleInfoResponse {
	return &ModuleInfoResponse{
		Name:         info.Name,
		Version:      info.Version,
		Description:  info.Description,
		Author:       info.Author,
		Capabilities: info.Capabilities,
		Tags:         info.Tags,
		ConfigSchema: info.ConfigSchema,
	}
}
