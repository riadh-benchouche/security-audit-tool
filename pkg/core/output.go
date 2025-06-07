package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/pkg/models"
)

// OutputFormat représente les formats de sortie disponibles
type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatText OutputFormat = "text"
	FormatHTML OutputFormat = "html"
	FormatXML  OutputFormat = "xml"
	FormatCSV  OutputFormat = "csv"
)

// Output gère la sortie des résultats de scan
type Output struct {
	format OutputFormat
	logger *StructuredLogger
}

// NewOutput crée une nouvelle instance d'Output
func NewOutput() *Output {
	return &Output{
		format: FormatJSON,
		logger: NewStructuredLogger("output"),
	}
}

// SetFormat définit le format de sortie
func (o *Output) SetFormat(format OutputFormat) {
	o.format = format
}

// SaveToFile sauvegarde les résultats dans un fichier
func (o *Output) SaveToFile(results *models.ScanResult, filename string) error {
	o.logger.Infof("Sauvegarde des résultats dans: %s", filename)

	// Créer le dossier parent s'il n'existe pas
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("impossible de créer le dossier %s: %w", dir, err)
	}

	// Déterminer le format basé sur l'extension si pas défini
	if o.format == "" {
		o.format = o.detectFormatFromFilename(filename)
	}

	var data []byte
	var err error

	switch o.format {
	case FormatJSON:
		data, err = o.formatJSON(results)
	case FormatText:
		data, err = o.formatText(results)
	case FormatHTML:
		data, err = o.formatHTML(results)
	case FormatXML:
		data, err = o.formatXML(results)
	case FormatCSV:
		data, err = o.formatCSV(results)
	default:
		return fmt.Errorf("format de sortie non supporté: %s", o.format)
	}

	if err != nil {
		return fmt.Errorf("erreur lors du formatage: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("erreur lors de l'écriture du fichier: %w", err)
	}

	o.logger.Infof("Résultats sauvegardés avec succès (%d bytes)", len(data))
	return nil
}

// PrintToConsole affiche les résultats dans la console
func (o *Output) PrintToConsole(results *models.ScanResult) {
	switch o.format {
	case FormatJSON:
		data, _ := o.formatJSON(results)
		fmt.Println(string(data))
	case FormatText:
		data, _ := o.formatText(results)
		fmt.Print(string(data))
	default:
		// Format texte par défaut pour la console
		data, _ := o.formatText(results)
		fmt.Print(string(data))
	}
}

// detectFormatFromFilename détecte le format basé sur l'extension du fichier
func (o *Output) detectFormatFromFilename(filename string) OutputFormat {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return FormatJSON
	case strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm"):
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

// formatJSON formate les résultats en JSON
func (o *Output) formatJSON(results *models.ScanResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// formatText formate les résultats en texte
func (o *Output) formatText(results *models.ScanResult) ([]byte, error) {
	var output strings.Builder

	// En-tête
	output.WriteString("═══════════════════════════════════════════════════════════════\n")
	output.WriteString("               SECURITY AUDIT REPORT\n")
	output.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	// Informations générales
	output.WriteString(fmt.Sprintf("Target:        %s\n", results.Target))
	output.WriteString(fmt.Sprintf("Start Time:    %s\n", results.StartTime.Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("End Time:      %s\n", results.EndTime.Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("Duration:      %s\n", results.Duration))
	output.WriteString(fmt.Sprintf("Overall Score: %d/100 (Grade: %s)\n\n", results.Summary.Score, results.Summary.Grade))

	// Résumé
	output.WriteString("SUMMARY\n")
	output.WriteString("───────────────────────────────────────────────────────────────\n")
	output.WriteString(fmt.Sprintf("Total Findings: %d\n", results.Summary.TotalFindings))
	output.WriteString("Findings by Severity:\n")
	for severity, count := range results.Summary.FindingsBySeverity {
		if count > 0 {
			output.WriteString(fmt.Sprintf("  %s: %d\n", strings.ToUpper(string(severity)), count))
		}
	}
	output.WriteString("\n")

	// Résultats par module
	for _, moduleResult := range results.Results {
		output.WriteString(fmt.Sprintf("MODULE: %s\n", strings.ToUpper(moduleResult.Module)))
		output.WriteString("───────────────────────────────────────────────────────────────\n")
		output.WriteString(fmt.Sprintf("Status:   %s\n", moduleResult.Status))
		output.WriteString(fmt.Sprintf("Duration: %s\n", moduleResult.Duration))
		output.WriteString(fmt.Sprintf("Findings: %d\n\n", len(moduleResult.Findings)))

		// Afficher les findings
		for i, finding := range moduleResult.Findings {
			output.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, strings.ToUpper(string(finding.Severity)), finding.Title))
			output.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))
			if finding.Remediation != "" {
				output.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
			}
			output.WriteString("\n")
		}

		// Afficher les erreurs s'il y en a
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

// formatHTML formate les résultats en HTML
func (o *Output) formatHTML(results *models.ScanResult) ([]byte, error) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
        .module { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; }
        .module-header { background: #007bff; color: white; padding: 15px; font-weight: bold; }
        .module-content { padding: 20px; }
        .finding { margin-bottom: 15px; padding: 10px; border-radius: 5px; }
        .severity-critical { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .severity-high { background-color: #fff3cd; border-left: 4px solid #ffc107; }
        .severity-medium { background-color: #d1ecf1; border-left: 4px solid #17a2b8; }
        .severity-low { background-color: #d4edda; border-left: 4px solid #28a745; }
        .severity-info { background-color: #e2e3e5; border-left: 4px solid #6c757d; }
        .badge { padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .badge-critical { background-color: #dc3545; color: white; }
        .badge-high { background-color: #ffc107; color: black; }
        .badge-medium { background-color: #17a2b8; color: white; }
        .badge-low { background-color: #28a745; color: white; }
        .badge-info { background-color: #6c757d; color: white; }
        .grade { font-size: 48px; font-weight: bold; color: #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Report</h1>
            <p><strong>Target:</strong> ` + results.Target + `</p>
            <p><strong>Generated:</strong> ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Overall Grade</h3>
                <div class="grade">` + results.Summary.Grade + `</div>
                <p>Score: ` + fmt.Sprintf("%d", results.Summary.Score) + `/100</p>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <h2>` + fmt.Sprintf("%d", results.Summary.TotalFindings) + `</h2>
            </div>
            <div class="summary-card">
                <h3>Duration</h3>
                <h2>` + results.Duration.String() + `</h2>
            </div>
        </div>`

	// Ajouter les modules
	for _, moduleResult := range results.Results {
		html += `
        <div class="module">
            <div class="module-header">` + strings.ToUpper(moduleResult.Module) + ` Module</div>
            <div class="module-content">
                <p><strong>Status:</strong> ` + string(moduleResult.Status) + `</p>
                <p><strong>Findings:</strong> ` + fmt.Sprintf("%d", len(moduleResult.Findings)) + `</p>`

		for _, finding := range moduleResult.Findings {
			severityClass := "severity-" + string(finding.Severity)
			badgeClass := "badge-" + string(finding.Severity)
			html += `
                <div class="finding ` + severityClass + `">
                    <h4>` + finding.Title + ` <span class="badge ` + badgeClass + `">` + string(finding.Severity) + `</span></h4>
                    <p>` + finding.Description + `</p>`
			if finding.Remediation != "" {
				html += `<p><strong>Remediation:</strong> ` + finding.Remediation + `</p>`
			}
			html += `</div>`
		}

		html += `
            </div>
        </div>`
	}

	html += `
    </div>
</body>
</html>`

	return []byte(html), nil
}

// formatXML formate les résultats en XML
func (o *Output) formatXML(results *models.ScanResult) ([]byte, error) {
	var output strings.Builder
	output.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	output.WriteString(`<scan_result>` + "\n")
	output.WriteString(fmt.Sprintf(`  <target>%s</target>`, results.Target) + "\n")
	output.WriteString(fmt.Sprintf(`  <start_time>%s</start_time>`, results.StartTime.Format(time.RFC3339)) + "\n")
	output.WriteString(fmt.Sprintf(`  <end_time>%s</end_time>`, results.EndTime.Format(time.RFC3339)) + "\n")
	output.WriteString(fmt.Sprintf(`  <duration>%s</duration>`, results.Duration) + "\n")

	output.WriteString(`  <summary>` + "\n")
	output.WriteString(fmt.Sprintf(`    <total_findings>%d</total_findings>`, results.Summary.TotalFindings) + "\n")
	output.WriteString(fmt.Sprintf(`    <score>%d</score>`, results.Summary.Score) + "\n")
	output.WriteString(fmt.Sprintf(`    <grade>%s</grade>`, results.Summary.Grade) + "\n")
	output.WriteString(`  </summary>` + "\n")

	output.WriteString(`</scan_result>`)
	return []byte(output.String()), nil
}

// formatCSV formate les résultats en CSV
func (o *Output) formatCSV(results *models.ScanResult) ([]byte, error) {
	var output strings.Builder

	// En-tête CSV
	output.WriteString("Module,Severity,Type,Title,Description,Target,Timestamp\n")

	// Données
	for _, moduleResult := range results.Results {
		for _, finding := range moduleResult.Findings {
			output.WriteString(fmt.Sprintf(`"%s","%s","%s","%s","%s","%s","%s"`+"\n",
				moduleResult.Module,
				finding.Severity,
				finding.Type,
				finding.Title,
				strings.ReplaceAll(finding.Description, `"`, `""`), // Échapper les guillemets
				finding.Target,
				finding.Timestamp.Format(time.RFC3339),
			))
		}
	}

	return []byte(output.String()), nil
}
