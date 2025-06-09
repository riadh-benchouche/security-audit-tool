package http

import (
	"fmt"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// SecurityHeadersAnalyzer handles security headers analysis
type SecurityHeadersAnalyzer struct {
	logger interfaces.ScannerLogger
}

// NewSecurityHeadersAnalyzer creates a new security headers analyzer
func NewSecurityHeadersAnalyzer(logger interfaces.ScannerLogger) *SecurityHeadersAnalyzer {
	return &SecurityHeadersAnalyzer{
		logger: logger,
	}
}

// AnalyzeHeaders analyzes security headers
func (sha *SecurityHeadersAnalyzer) AnalyzeHeaders(headers http.Header) SecurityHeaders {
	security := SecurityHeaders{}

	// Analyze each security header
	security.HSTS = sha.analyzeHSTS(headers.Get("Strict-Transport-Security"))
	security.CSP = sha.analyzeCSP(headers.Get("Content-Security-Policy"))
	security.XFrameOptions = sha.analyzeXFrameOptions(headers.Get("X-Frame-Options"))
	security.XContentTypeOptions = sha.analyzeXContentTypeOptions(headers.Get("X-Content-Type-Options"))
	security.XSSProtection = sha.analyzeXSSProtection(headers.Get("X-XSS-Protection"))
	security.ReferrerPolicy = sha.analyzeReferrerPolicy(headers.Get("Referrer-Policy"))

	// Calculate overall score and grade
	security.Score = CalculateSecurityScore(&security)
	security.Grade = GetSecurityGrade(security.Score)

	return security
}

// analyzeHSTS analyzes HSTS header
func (sha *SecurityHeadersAnalyzer) analyzeHSTS(hsts string) *Header {
	header := &Header{
		Present: hsts != "",
		Value:   hsts,
		Issues:  make([]string, 0),
	}

	if header.Present {
		header.Valid = strings.Contains(hsts, "max-age=")
		header.Score = 20

		// Parse max-age value
		if maxAgeMatch := regexp.MustCompile(`max-age=(\d+)`).FindStringSubmatch(hsts); len(maxAgeMatch) > 1 {
			if maxAge, err := strconv.Atoi(maxAgeMatch[1]); err == nil {
				if maxAge < 31536000 { // 1 year
					header.Issues = append(header.Issues, "max-age is less than 1 year")
				}
			}
		}

		// Check for includeSubDomains
		if strings.Contains(hsts, "includeSubDomains") {
			header.Score += 5
		} else {
			header.Issues = append(header.Issues, "includeSubDomains directive missing")
		}

		// Check for preload
		if strings.Contains(hsts, "preload") {
			header.Score += 5
		}
	} else {
		header.Issues = []string{"HSTS header missing"}
	}

	return header
}

// analyzeCSP analyzes CSP header
func (sha *SecurityHeadersAnalyzer) analyzeCSP(csp string) *Header {
	header := &Header{
		Present: csp != "",
		Value:   csp,
		Issues:  make([]string, 0),
	}

	if header.Present {
		header.Valid = true
		header.Score = 25

		// Check for unsafe directives
		if strings.Contains(csp, "unsafe-inline") {
			header.Issues = append(header.Issues, "unsafe-inline directive found")
			header.Score -= 10
		}
		if strings.Contains(csp, "unsafe-eval") {
			header.Issues = append(header.Issues, "unsafe-eval directive found")
			header.Score -= 10
		}
		if strings.Contains(csp, "*") && !strings.Contains(csp, "data:") {
			header.Issues = append(header.Issues, "wildcard (*) directive found")
			header.Score -= 5
		}
	} else {
		header.Issues = []string{"CSP header missing"}
	}

	return header
}

// analyzeXFrameOptions analyzes X-Frame-Options header
func (sha *SecurityHeadersAnalyzer) analyzeXFrameOptions(xfo string) *Header {
	header := &Header{
		Present: xfo != "",
		Value:   xfo,
		Issues:  make([]string, 0),
	}

	if header.Present {
		xfoLower := strings.ToLower(xfo)
		header.Valid = xfoLower == "deny" || xfoLower == "sameorigin" || strings.HasPrefix(xfoLower, "allow-from")
		if header.Valid {
			header.Score = 15
		} else {
			header.Issues = append(header.Issues, "invalid X-Frame-Options value")
		}
	} else {
		header.Issues = []string{"X-Frame-Options header missing"}
	}

	return header
}

// analyzeXContentTypeOptions analyzes X-Content-Type-Options header
func (sha *SecurityHeadersAnalyzer) analyzeXContentTypeOptions(xcto string) *Header {
	header := &Header{
		Present: xcto != "",
		Value:   xcto,
		Issues:  make([]string, 0),
	}

	if header.Present {
		header.Valid = strings.ToLower(xcto) == "nosniff"
		if header.Valid {
			header.Score = 10
		} else {
			header.Issues = append(header.Issues, "invalid X-Content-Type-Options value")
		}
	} else {
		header.Issues = []string{"X-Content-Type-Options header missing"}
	}

	return header
}

// analyzeXSSProtection analyzes X-XSS-Protection header
func (sha *SecurityHeadersAnalyzer) analyzeXSSProtection(xss string) *Header {
	header := &Header{
		Present: xss != "",
		Value:   xss,
		Issues:  make([]string, 0),
	}

	if header.Present {
		header.Valid = strings.Contains(xss, "1") && strings.Contains(xss, "mode=block")
		if header.Valid {
			header.Score = 10
		} else {
			header.Issues = append(header.Issues, "X-XSS-Protection not properly configured")
		}
	} else {
		header.Issues = []string{"X-XSS-Protection header missing"}
	}

	return header
}

// analyzeReferrerPolicy analyzes Referrer-Policy header
func (sha *SecurityHeadersAnalyzer) analyzeReferrerPolicy(rp string) *Header {
	header := &Header{
		Present: rp != "",
		Value:   rp,
		Issues:  make([]string, 0),
	}

	if header.Present {
		validPolicies := []string{
			"no-referrer", "no-referrer-when-downgrade", "origin",
			"origin-when-cross-origin", "same-origin", "strict-origin",
			"strict-origin-when-cross-origin", "unsafe-url",
		}

		header.Valid = false
		for _, policy := range validPolicies {
			if strings.Contains(strings.ToLower(rp), policy) {
				header.Valid = true
				header.Score = 10
				break
			}
		}

		if !header.Valid {
			header.Issues = append(header.Issues, "invalid Referrer-Policy value")
		}
	} else {
		header.Issues = []string{"Referrer-Policy header missing"}
	}

	return header
}

// CreateHeaderFindings creates findings from security headers analysis
func (sha *SecurityHeadersAnalyzer) CreateHeaderFindings(execution *entities.ModuleExecution, security SecurityHeaders, targetURL string) {
	// HSTS missing or misconfigured
	if security.HSTS != nil && (!security.HSTS.Present || len(security.HSTS.Issues) > 0) {
		severity := entities.SeverityMedium
		title := "Missing or Misconfigured HSTS Header"
		description := "The Strict-Transport-Security header is missing or misconfigured"

		if security.HSTS.Present {
			title = "Misconfigured HSTS Header"
			description = fmt.Sprintf("HSTS header issues: %s", strings.Join(security.HSTS.Issues, ", "))
		}

		finding, err := entities.NewFindingBuilder().
			WithID("http-hsts-issues").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(severity).
			WithTitle(title).
			WithDescription(description).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"header":  "Strict-Transport-Security",
				"present": security.HSTS.Present,
				"issues":  security.HSTS.Issues,
			}).
			WithTags("http", "security-headers", "hsts").
			Build()

		if err == nil {
			finding.SetRemediation("Configure HSTS with max-age=31536000; includeSubDomains; preload")
			execution.AddFinding(finding)
		}
	}

	// CSP missing or misconfigured
	if security.CSP != nil && (!security.CSP.Present || len(security.CSP.Issues) > 0) {
		severity := entities.SeverityMedium
		title := "Missing or Misconfigured Content Security Policy"
		description := "The Content-Security-Policy header is missing or has security issues"

		if security.CSP.Present {
			title = "Content Security Policy Issues"
			description = fmt.Sprintf("CSP issues: %s", strings.Join(security.CSP.Issues, ", "))
		}

		finding, err := entities.NewFindingBuilder().
			WithID("http-csp-issues").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(severity).
			WithTitle(title).
			WithDescription(description).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"header":  "Content-Security-Policy",
				"present": security.CSP.Present,
				"issues":  security.CSP.Issues,
			}).
			WithTags("http", "security-headers", "csp", "xss").
			Build()

		if err == nil {
			finding.SetRemediation("Implement a strict Content Security Policy without unsafe-inline or unsafe-eval")
			execution.AddFinding(finding)
		}
	}

	// X-Frame-Options missing
	if security.XFrameOptions != nil && !security.XFrameOptions.Present {
		finding, err := entities.NewFindingBuilder().
			WithID("http-x-frame-options-missing").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(entities.SeverityMedium).
			WithTitle("Missing X-Frame-Options Header").
			WithDescription("The X-Frame-Options header is missing, which could allow clickjacking attacks").
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"header":  "X-Frame-Options",
				"present": false,
			}).
			WithTags("http", "security-headers", "clickjacking").
			Build()

		if err == nil {
			finding.SetRemediation("Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking")
			execution.AddFinding(finding)
		}
	}
}
