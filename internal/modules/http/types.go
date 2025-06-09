package http

import (
	"fmt"
	"time"
)

// HTTPResult holds the results of an HTTP request
type HTTPResult struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	Technologies []Technology      `json:"technologies,omitempty"`
	SSL          *SSLResult        `json:"ssl,omitempty"`
	Security     SecurityHeaders   `json:"security"`
	ResponseTime time.Duration     `json:"response_time"`
	BodySize     int64             `json:"body_size,omitempty"`
}

// IsSuccessful returns true if the HTTP request was successful (2xx status)
func (hr *HTTPResult) IsSuccessful() bool {
	return hr.StatusCode >= 200 && hr.StatusCode < 300
}

// IsRedirect returns true if the response is a redirect (3xx status)
func (hr *HTTPResult) IsRedirect() bool {
	return hr.StatusCode >= 300 && hr.StatusCode < 400
}

// IsClientError returns true if there's a client error (4xx status)
func (hr *HTTPResult) IsClientError() bool {
	return hr.StatusCode >= 400 && hr.StatusCode < 500
}

// IsServerError returns true if there's a server error (5xx status)
func (hr *HTTPResult) IsServerError() bool {
	return hr.StatusCode >= 500 && hr.StatusCode < 600
}

// HasSSL returns true if SSL/TLS information is available
func (hr *HTTPResult) HasSSL() bool {
	return hr.SSL != nil
}

// GetResponseTimeMs returns the response time in milliseconds
func (hr *HTTPResult) GetResponseTimeMs() int64 {
	return hr.ResponseTime.Milliseconds()
}

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories,omitempty"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence,omitempty"`
	Method     string   `json:"detection_method,omitempty"`
}

// IsConfident returns true if the technology detection confidence is high (>= 80%)
func (t *Technology) IsConfident() bool {
	return t.Confidence >= 80
}

// HasVersion returns true if the technology version is detected
func (t *Technology) HasVersion() bool {
	return t.Version != ""
}

// GetDisplayName returns a formatted display name for the technology
func (t *Technology) GetDisplayName() string {
	if t.Version != "" {
		return fmt.Sprintf("%s %s", t.Name, t.Version)
	}
	return t.Name
}

// IsFramework returns true if the technology is a framework
func (t *Technology) IsFramework() bool {
	for _, category := range t.Categories {
		if category == "Framework" || category == "JavaScript Framework" || category == "CSS Framework" {
			return true
		}
	}
	return false
}

// IsCMS returns true if the technology is a CMS
func (t *Technology) IsCMS() bool {
	for _, category := range t.Categories {
		if category == "CMS" || category == "Content Management System" {
			return true
		}
	}
	return false
}

// SSLResult holds SSL/TLS analysis results
type SSLResult struct {
	Enabled         bool         `json:"enabled"`
	Version         string       `json:"version,omitempty"`
	Protocols       []string     `json:"protocols,omitempty"`
	Certificate     *Certificate `json:"certificate,omitempty"`
	Vulnerabilities []string     `json:"vulnerabilities,omitempty"`
	Grade           string       `json:"grade,omitempty"`
	Score           int          `json:"score,omitempty"`
}

// IsSecure returns true if SSL is properly configured
func (ssl *SSLResult) IsSecure() bool {
	return ssl.Enabled && len(ssl.Vulnerabilities) == 0 && ssl.Certificate != nil && !ssl.Certificate.IsExpired
}

// HasVulnerabilities returns true if SSL vulnerabilities are detected
func (ssl *SSLResult) HasVulnerabilities() bool {
	return len(ssl.Vulnerabilities) > 0
}

// GetGradeScore returns a numeric score for the grade
func (ssl *SSLResult) GetGradeScore() int {
	switch ssl.Grade {
	case "A+":
		return 100
	case "A":
		return 90
	case "B":
		return 80
	case "C":
		return 70
	case "D":
		return 60
	default:
		return 50
	}
}

// Certificate holds certificate information
type Certificate struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	IsExpired      bool      `json:"is_expired"`
	IsCA           bool      `json:"is_ca"`
	KeySize        int       `json:"key_size,omitempty"`
	SignatureAlg   string    `json:"signature_algorithm,omitempty"`
	DNSNames       []string  `json:"dns_names,omitempty"`
	EmailAddresses []string  `json:"email_addresses,omitempty"`
}

// IsValid returns true if the certificate is valid (not expired and properly issued)
func (c *Certificate) IsValid() bool {
	now := time.Now()
	return !c.IsExpired && now.After(c.NotBefore) && now.Before(c.NotAfter)
}

// DaysUntilExpiry returns the number of days until the certificate expires
func (c *Certificate) DaysUntilExpiry() int {
	if c.IsExpired {
		return 0
	}
	duration := time.Until(c.NotAfter)
	return int(duration.Hours() / 24)
}

// IsExpiringSoon returns true if the certificate expires within 30 days
func (c *Certificate) IsExpiringSoon() bool {
	return c.DaysUntilExpiry() <= 30 && c.DaysUntilExpiry() > 0
}

// GetKeyStrength returns a string representation of the key strength
func (c *Certificate) GetKeyStrength() string {
	switch {
	case c.KeySize >= 4096:
		return "Strong"
	case c.KeySize >= 2048:
		return "Adequate"
	case c.KeySize >= 1024:
		return "Weak"
	default:
		return "Very Weak"
	}
}

// SecurityHeaders holds security headers analysis
type SecurityHeaders struct {
	HSTS                *Header `json:"hsts,omitempty"`
	CSP                 *Header `json:"csp,omitempty"`
	XFrameOptions       *Header `json:"x_frame_options,omitempty"`
	XContentTypeOptions *Header `json:"x_content_type_options,omitempty"`
	XSSProtection       *Header `json:"x_xss_protection,omitempty"`
	ReferrerPolicy      *Header `json:"referrer_policy,omitempty"`
	Score               int     `json:"score"`
	Grade               string  `json:"grade"`
}

// IsSecure returns true if security headers are properly configured
func (sh *SecurityHeaders) IsSecure() bool {
	return sh.Score >= 80
}

// GetMissingHeaders returns a list of missing critical security headers
func (sh *SecurityHeaders) GetMissingHeaders() []string {
	missing := make([]string, 0)

	if sh.HSTS == nil || !sh.HSTS.Present {
		missing = append(missing, "Strict-Transport-Security")
	}
	if sh.CSP == nil || !sh.CSP.Present {
		missing = append(missing, "Content-Security-Policy")
	}
	if sh.XFrameOptions == nil || !sh.XFrameOptions.Present {
		missing = append(missing, "X-Frame-Options")
	}
	if sh.XContentTypeOptions == nil || !sh.XContentTypeOptions.Present {
		missing = append(missing, "X-Content-Type-Options")
	}

	return missing
}

// GetGradeDescription returns a description of the security grade
func (sh *SecurityHeaders) GetGradeDescription() string {
	switch sh.Grade {
	case "A":
		return "Excellent security header configuration"
	case "B":
		return "Good security header configuration with minor issues"
	case "C":
		return "Average security header configuration with some missing headers"
	case "D":
		return "Poor security header configuration with many missing headers"
	case "F":
		return "Very poor security header configuration"
	default:
		return "Unknown security grade"
	}
}

// Header represents a security header analysis
type Header struct {
	Present bool     `json:"present"`
	Value   string   `json:"value,omitempty"`
	Valid   bool     `json:"valid"`
	Score   int      `json:"score"`
	Issues  []string `json:"issues,omitempty"`
}

// IsProperlyConfigured returns true if the header is present and valid
func (h *Header) IsProperlyConfigured() bool {
	return h.Present && h.Valid && len(h.Issues) == 0
}

// HasIssues returns true if the header has configuration issues
func (h *Header) HasIssues() bool {
	return len(h.Issues) > 0
}

// GetIssueCount returns the number of issues with this header
func (h *Header) GetIssueCount() int {
	return len(h.Issues)
}

// AnalysisResult represents the result of analyzing a specific aspect
type AnalysisResult struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
}

// IsHighSeverity returns true if the analysis result is high severity
func (ar *AnalysisResult) IsHighSeverity() bool {
	return ar.Severity == "high" || ar.Severity == "critical"
}

// IsMediumSeverity returns true if the analysis result is medium severity
func (ar *AnalysisResult) IsMediumSeverity() bool {
	return ar.Severity == "medium"
}

// IsLowSeverity returns true if the analysis result is low severity
func (ar *AnalysisResult) IsLowSeverity() bool {
	return ar.Severity == "low" || ar.Severity == "info"
}

// ScanProgress represents the progress of an HTTP scan
type ScanProgress struct {
	Phase           string `json:"phase"`
	CurrentStep     int    `json:"current_step"`
	TotalSteps      int    `json:"total_steps"`
	ProgressPercent int    `json:"progress_percent"`
	Message         string `json:"message,omitempty"`
}

// IsComplete returns true if the scan is complete
func (sp *ScanProgress) IsComplete() bool {
	return sp.ProgressPercent >= 100
}

// GetProgressRatio returns the progress as a ratio (0.0 to 1.0)
func (sp *ScanProgress) GetProgressRatio() float64 {
	return float64(sp.ProgressPercent) / 100.0
}

// RequestInfo holds information about the HTTP request made
type RequestInfo struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	UserAgent string            `json:"user_agent"`
	Timestamp time.Time         `json:"timestamp"`
}

// GetFormattedTimestamp returns a formatted timestamp string
func (ri *RequestInfo) GetFormattedTimestamp() string {
	return ri.Timestamp.Format("2006-01-02 15:04:05")
}

// ResponseInfo holds information about the HTTP response received
type ResponseInfo struct {
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	ResponseTime  time.Duration     `json:"response_time"`
}

// GetContentTypeCategory returns the category of the content type
func (ri *ResponseInfo) GetContentTypeCategory() string {
	switch {
	case ri.ContentType == "":
		return "Unknown"
	case ri.ContentType == "text/html":
		return "HTML"
	case ri.ContentType == "application/json":
		return "JSON"
	case ri.ContentType == "text/xml" || ri.ContentType == "application/xml":
		return "XML"
	case ri.ContentType == "text/plain":
		return "Text"
	default:
		return "Other"
	}
}
