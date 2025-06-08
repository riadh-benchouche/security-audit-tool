package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/application/dto"
)

// OutputFormat represents available output formats
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatHTML OutputFormat = "html"
	FormatXML  OutputFormat = "xml"
	FormatCSV  OutputFormat = "csv"
)

// OutputHandler handles scan result output
type OutputHandler struct {
	format OutputFormat
}

// NewOutputHandler creates a new output handler
func NewOutputHandler() *OutputHandler {
	return &OutputHandler{
		format: FormatText,
	}
}

// SetFormat sets the output format
func (oh *OutputHandler) SetFormat(format OutputFormat) {
	oh.format = format
}

// SaveToFile saves results to a file
func (oh *OutputHandler) SaveToFile(scanResponse *dto.ScanResponse, filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Determine format from filename if not set
	if oh.format == "" {
		oh.format = oh.detectFormatFromFilename(filename)
	}

	var data []byte
	var err error

	switch oh.format {
	case FormatJSON:
		data, err = oh.formatJSON(scanResponse)
	case FormatText:
		data, err = oh.formatText(scanResponse)
	case FormatHTML:
		data, err = oh.formatHTML(scanResponse)
	case FormatXML:
		data, err = oh.formatXML(scanResponse)
	case FormatCSV:
		data, err = oh.formatCSV(scanResponse)
	default:
		return fmt.Errorf("unsupported output format: %s", oh.format)
	}

	if err != nil {
		return fmt.Errorf("formatting error: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// PrintToConsole prints results to console
func (oh *OutputHandler) PrintToConsole(scanResponse *dto.ScanResponse) {
	switch oh.format {
	case FormatJSON:
		data, _ := oh.formatJSON(scanResponse)
		fmt.Println(string(data))
	case FormatText:
		data, _ := oh.formatText(scanResponse)
		fmt.Print(string(data))
	default:
		// Default to text for console
		data, _ := oh.formatText(scanResponse)
		fmt.Print(string(data))
	}
}

// detectFormatFromFilename detects format from file extension
func (oh *OutputHandler) detectFormatFromFilename(filename string) OutputFormat {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return FormatJSON
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"):
		return FormatHTML
	case strings.HasSuffix(lower, ".xml"):
		return FormatXML
	case strings.HasSuffix(lower, ".csv"):
		return FormatCSV
	case strings.HasSuffix(lower, ".txt"):
		return FormatText
	default:
		return FormatJSON
	}
}

// formatJSON formats results as JSON
func (oh *OutputHandler) formatJSON(scanResponse *dto.ScanResponse) ([]byte, error) {
	return json.MarshalIndent(scanResponse, "", "  ")
}

// formatText formats results as text
func (oh *OutputHandler) formatText(scanResponse *dto.ScanResponse) ([]byte, error) {
	var output strings.Builder

	// Header
	output.WriteString("═══════════════════════════════════════════════════════════════\n")
	output.WriteString("               SECURITY AUDIT REPORT\n")
	output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	// General information
	output.WriteString(fmt.Sprintf("Target:        %s\n", scanResponse.Target))
	output.WriteString(fmt.Sprintf("Scan ID:       %s\n", scanResponse.ScanID))
	output.WriteString(fmt.Sprintf("Status:        %s\n", scanResponse.Status))
	output.WriteString(fmt.Sprintf("Start Time:    %s\n", scanResponse.StartTime.Format(time.RFC3339)))

	if scanResponse.EndTime != nil {
		output.WriteString(fmt.Sprintf("End Time:      %s\n", scanResponse.EndTime.Format(time.RFC3339)))
	}

	if scanResponse.Duration != nil {
		output.WriteString(fmt.Sprintf("Duration:      %s\n", *scanResponse.Duration))
	}

	// Summary
	if scanResponse.Summary != nil {
		summary := scanResponse.Summary
		output.WriteString(fmt.Sprintf("Overall Score: %d/100 (Grade: %s)\n\n", summary.Score, summary.Grade))

		output.WriteString("SUMMARY\n")
		output.WriteString("───────────────────────────────────────────────────────────────\n")
		output.WriteString(fmt.Sprintf("Total Findings: %d\n", summary.TotalFindings))
		output.WriteString("Findings by Severity:\n")

		for severity, count := range summary.FindingsBySeverity {
			if count > 0 {
				output.WriteString(fmt.Sprintf("  %s: %d\n", strings.ToUpper(severity), count))
			}
		}
		output.WriteString("\n")
	}

	// Module results
	for _, moduleResult := range scanResponse.Modules {
		output.WriteString(fmt.Sprintf("MODULE: %s\n", strings.ToUpper(moduleResult.Module)))
		output.WriteString("───────────────────────────────────────────────────────────────\n")
		output.WriteString(fmt.Sprintf("Status:   %s\n", moduleResult.Status))
		output.WriteString(fmt.Sprintf("Duration: %s\n", moduleResult.Duration))
		output.WriteString(fmt.Sprintf("Findings: %d\n\n", len(moduleResult.Findings)))

		// Display findings
		for i, finding := range moduleResult.Findings {
			output.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(finding.Severity), finding.Title))
			output.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))

			if finding.Remediation != "" {
				output.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
			}

			if len(finding.Tags) > 0 {
				output.WriteString(fmt.Sprintf("   Tags: %s\n", strings.Join(finding.Tags, ", ")))
			}

			output.WriteString("\n")
		}

		// Display errors if any
		if len(moduleResult.Errors) > 0 {
			output.WriteString("Errors:\n")
			for _, err := range moduleResult.Errors {
				output.WriteString(fmt.Sprintf("  - %s\n", err))
			}
			output.WriteString("\n")
		}
	}

	output.WriteString("═══════════════════════════════════════════════════════════════\n")
	output.WriteString(fmt.Sprintf("Report generated at: %s\n", time.Now().Format(time.RFC3339)))

	return []byte(output.String()), nil
}

// formatHTML formats results as HTML (basic implementation)
func (oh *OutputHandler) formatHTML(scanResponse *dto.ScanResponse) ([]byte, error) {
	// Simplified HTML implementation
	// You can enhance this with proper HTML templating
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .finding { margin: 10px 0; padding: 10px; border-radius: 5px; }
        .critical { background: #f8d7da; }
        .high { background: #fff3cd; }
        .medium { background: #d1ecf1; }
        .low { background: #d4edda; }
        .info { background: #e2e3e5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p><strong>Target:</strong> %s</p>
        <p><strong>Status:</strong> %s</p>
    </div>
`, scanResponse.Target, scanResponse.Target, scanResponse.Status)

	// Add findings
	for _, module := range scanResponse.Modules {
		html += fmt.Sprintf(`<h2>%s Module</h2>`, strings.Title(module.Module))
		for _, finding := range module.Findings {
			html += fmt.Sprintf(`<div class="finding %s">
                <h3>%s</h3>
                <p>%s</p>
            </div>`, finding.Severity, finding.Title, finding.Description)
		}
	}

	html += `</body></html>`
	return []byte(html), nil
}

// formatXML formats results as XML (basic implementation)
func (oh *OutputHandler) formatXML(scanResponse *dto.ScanResponse) ([]byte, error) {
	// Basic XML implementation
	xml := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	xml += `<scan_result>` + "\n"
	xml += fmt.Sprintf(`  <target>%s</target>`, scanResponse.Target) + "\n"
	xml += fmt.Sprintf(`  <status>%s</status>`, scanResponse.Status) + "\n"
	xml += `</scan_result>`
	return []byte(xml), nil
}

// formatCSV formats results as CSV (basic implementation)
func (oh *OutputHandler) formatCSV(scanResponse *dto.ScanResponse) ([]byte, error) {
	var output strings.Builder

	// CSV header
	output.WriteString("Module,Severity,Type,Title,Description,Target,Timestamp\n")

	// CSV data
	for _, module := range scanResponse.Modules {
		for _, finding := range module.Findings {
			output.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","%s","%s","%s"`+"\n",
				module.Module,
				finding.Severity,
				finding.Type,
				finding.Title,
				strings.ReplaceAll(finding.Description, `"`, `""`),
				finding.Target,
				finding.Timestamp.Format(time.RFC3339),
			))
		}
	}

	return []byte(output.String()), nil
}
