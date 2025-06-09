package http

import (
	"fmt"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"strings"
)

// HTTPAnalyzer handles comprehensive HTTP response analysis
type HTTPAnalyzer struct {
	logger           interfaces.ScannerLogger
	sslAnalyzer      *SSLAnalyzer
	securityAnalyzer *SecurityHeadersAnalyzer
	techDetector     *TechnologyDetector
}

// NewHTTPAnalyzer creates a new HTTP analyzer
func NewHTTPAnalyzer(logger interfaces.ScannerLogger) *HTTPAnalyzer {
	return &HTTPAnalyzer{
		logger:           logger,
		sslAnalyzer:      NewSSLAnalyzer(logger),
		securityAnalyzer: NewSecurityHeadersAnalyzer(logger),
		techDetector:     NewTechnologyDetector(),
	}
}

// AnalyzeResponse performs comprehensive analysis of HTTP response
func (ha *HTTPAnalyzer) AnalyzeResponse(httpResult *HTTPResult, targetURL string, execution *entities.ModuleExecution) {
	// Analyze status code
	ha.analyzeStatusCode(httpResult, targetURL, execution)

	// Analyze technologies
	ha.analyzeTechnologies(httpResult, targetURL, execution)

	// Analyze security headers
	if httpResult.Security.HSTS != nil || httpResult.Security.CSP != nil {
		ha.securityAnalyzer.CreateHeaderFindings(execution, httpResult.Security, targetURL)
	}

	// Analyze SSL if available
	if httpResult.SSL != nil {
		ha.sslAnalyzer.CreateSSLFindings(execution, httpResult.SSL, targetURL)
	}
}

// analyzeStatusCode creates findings for HTTP status codes
func (ha *HTTPAnalyzer) analyzeStatusCode(httpResult *HTTPResult, targetURL string, execution *entities.ModuleExecution) {
	if httpResult.StatusCode >= 400 {
		severity := GetStatusCodeSeverity(httpResult.StatusCode)
		description := GetStatusCodeDescription(httpResult.StatusCode)

		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("http-status-%d", httpResult.StatusCode)).
			WithType(entities.FindingTypeInformation).
			WithSeverity(severity).
			WithTitle(fmt.Sprintf("HTTP %d Response", httpResult.StatusCode)).
			WithDescription(description).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"status_code":   httpResult.StatusCode,
				"url":           httpResult.URL,
				"response_time": httpResult.GetResponseTimeMs(),
			}).
			WithTags("http", "status-code").
			Build()

		if err == nil {
			execution.AddFinding(finding)
		} else {
			ha.logger.Error("Failed to create status code finding", err, nil)
		}
	}
}

// analyzeTechnologies creates findings for detected technologies
func (ha *HTTPAnalyzer) analyzeTechnologies(httpResult *HTTPResult, targetURL string, execution *entities.ModuleExecution) {
	for _, tech := range httpResult.Technologies {
		severity := entities.SeverityInfo
		title := fmt.Sprintf("Technology detected: %s", tech.Name)
		description := fmt.Sprintf("The website uses %s", tech.GetDisplayName())

		// Adjust severity for outdated or risky technologies
		if ha.isRiskyTechnology(tech.Name) {
			severity = entities.SeverityMedium
			description += " (potentially outdated or risky)"
		}

		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("http-technology-%s", strings.ToLower(tech.Name))).
			WithType(entities.FindingTypeInformation).
			WithSeverity(severity).
			WithTitle(title).
			WithDescription(description).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"technology": tech.Name,
				"categories": tech.Categories,
				"version":    tech.Version,
				"confidence": tech.Confidence,
				"method":     tech.Method,
			}).
			WithTags(append([]string{"http", "technology"}, tech.Categories...)...).
			Build()

		if err == nil {
			// Add remediation for risky technologies
			if ha.isRiskyTechnology(tech.Name) {
				remediation := ha.getTechnologyRemediation(tech.Name)
				if remediation != "" {
					finding.SetRemediation(remediation)
				}
			}
			execution.AddFinding(finding)
		}
	}
}

// isRiskyTechnology checks if a technology is considered risky
func (ha *HTTPAnalyzer) isRiskyTechnology(techName string) bool {
	riskyTech := map[string]bool{
		"jQuery 1.x":        true, // Outdated versions
		"jQuery 2.x":        true,
		"Angular 1.x":       true,
		"PHP 5.x":           true,
		"Apache 2.2":        true,
		"Microsoft IIS 7.x": true,
		"WordPress 4.x":     true,
	}
	return riskyTech[techName]
}

// getTechnologyRemediation returns remediation advice for risky technologies
func (ha *HTTPAnalyzer) getTechnologyRemediation(techName string) string {
	remediations := map[string]string{
		"jQuery 1.x":        "Update to jQuery 3.x for security patches and better performance",
		"jQuery 2.x":        "Update to jQuery 3.x for security patches and better performance",
		"Angular 1.x":       "Migrate to Angular 2+ or consider modern alternatives like React or Vue",
		"PHP 5.x":           "Upgrade to PHP 8.x for security patches and performance improvements",
		"Apache 2.2":        "Upgrade to Apache 2.4+ for security improvements",
		"Microsoft IIS 7.x": "Upgrade to IIS 10+ for better security and performance",
		"WordPress 4.x":     "Update to the latest WordPress version for security patches",
	}
	return remediations[techName]
}
