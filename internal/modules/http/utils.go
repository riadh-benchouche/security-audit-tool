package http

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// URL Normalization Utilities

// NormalizeURL converts target to HTTP URL
func NormalizeURL(target *entities.Target) (string, error) {
	switch target.Type() {
	case entities.TargetTypeURL:
		return target.Original(), nil
	case entities.TargetTypeDomain:
		if target.IsHTTPS() {
			return fmt.Sprintf("https://%s", target.Host()), nil
		}
		return fmt.Sprintf("http://%s", target.Host()), nil
	case entities.TargetTypeIP:
		if target.Port() == 443 {
			return fmt.Sprintf("https://%s", target.Host()), nil
		}
		return fmt.Sprintf("http://%s", target.Host()), nil
	default:
		return "", errors.NewValidationError("unsupported target type for HTTP scanning", nil)
	}
}

// IsHTTPS checks if a URL uses HTTPS
func IsHTTPS(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "https://")
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(url string) string {
	// Simple domain extraction - in production, use proper URL parsing
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		domain := parts[0]
		// Remove port if present
		if colonIndex := strings.LastIndex(domain, ":"); colonIndex > 0 {
			domain = domain[:colonIndex]
		}
		return domain
	}
	return ""
}

// Content Parsing Utilities

// ExtractTitle extracts page title from HTML content
func ExtractTitle(body string) string {
	titleRegex := regexp.MustCompile(`<title[^>]*>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Clean title (remove control characters)
		title = strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 || r > 127 {
				return r
			}
			return -1
		}, title)
		return title
	}
	return ""
}

// LimitResponseBody reads response body with size limit
func LimitResponseBody(body io.Reader, maxSize int64) ([]byte, error) {
	limitedReader := io.LimitReader(body, maxSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return content, nil
}

// CleanHTMLContent removes HTML tags and extracts text content
func CleanHTMLContent(html string) string {
	// Remove script and style content
	scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	html = scriptRegex.ReplaceAllString(html, "")

	styleRegex := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	html = styleRegex.ReplaceAllString(html, "")

	// Remove HTML tags
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	text := tagRegex.ReplaceAllString(html, " ")

	// Clean whitespace
	spaceRegex := regexp.MustCompile(`\s+`)
	text = spaceRegex.ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}

// Header Utilities

// ConvertHeaders converts http.Header to map[string]string
func ConvertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

// GetHeaderValue gets a header value (case-insensitive)
func GetHeaderValue(headers http.Header, name string) string {
	return headers.Get(name)
}

// HasHeader checks if a header exists (case-insensitive)
func HasHeader(headers http.Header, name string) bool {
	return headers.Get(name) != ""
}

// GetSecurityHeaders extracts security-related headers
func GetSecurityHeaders(headers http.Header) map[string]string {
	securityHeaders := map[string]string{
		"Strict-Transport-Security": headers.Get("Strict-Transport-Security"),
		"Content-Security-Policy":   headers.Get("Content-Security-Policy"),
		"X-Frame-Options":           headers.Get("X-Frame-Options"),
		"X-Content-Type-Options":    headers.Get("X-Content-Type-Options"),
		"X-XSS-Protection":          headers.Get("X-XSS-Protection"),
		"Referrer-Policy":           headers.Get("Referrer-Policy"),
		"Permissions-Policy":        headers.Get("Permissions-Policy"),
		"Feature-Policy":            headers.Get("Feature-Policy"),
	}

	// Remove empty headers
	result := make(map[string]string)
	for name, value := range securityHeaders {
		if value != "" {
			result[name] = value
		}
	}

	return result
}

// HTTP Status Utilities

// GetStatusCodeSeverity returns severity based on HTTP status code
func GetStatusCodeSeverity(statusCode int) entities.Severity {
	switch {
	case statusCode >= 500:
		return entities.SeverityHigh
	case statusCode >= 400:
		return entities.SeverityMedium
	case statusCode >= 300:
		return entities.SeverityLow
	default:
		return entities.SeverityInfo
	}
}

// GetStatusCodeDescription returns a description for HTTP status codes
func GetStatusCodeDescription(statusCode int) string {
	descriptions := map[int]string{
		200: "OK - Request successful",
		201: "Created - Resource created successfully",
		301: "Moved Permanently - Resource has been moved",
		302: "Found - Resource temporarily moved",
		400: "Bad Request - Invalid request syntax",
		401: "Unauthorized - Authentication required",
		403: "Forbidden - Access denied",
		404: "Not Found - Resource not found",
		405: "Method Not Allowed - HTTP method not supported",
		500: "Internal Server Error - Server encountered an error",
		502: "Bad Gateway - Invalid response from upstream server",
		503: "Service Unavailable - Server temporarily unavailable",
		504: "Gateway Timeout - Upstream server timeout",
	}

	if desc, exists := descriptions[statusCode]; exists {
		return desc
	}

	switch {
	case statusCode >= 200 && statusCode < 300:
		return "Successful response"
	case statusCode >= 300 && statusCode < 400:
		return "Redirection response"
	case statusCode >= 400 && statusCode < 500:
		return "Client error response"
	case statusCode >= 500 && statusCode < 600:
		return "Server error response"
	default:
		return "Unknown status code"
	}
}

// IsSuccessfulStatusCode checks if status code indicates success
func IsSuccessfulStatusCode(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// IsErrorStatusCode checks if status code indicates an error
func IsErrorStatusCode(statusCode int) bool {
	return statusCode >= 400
}

// Content Type Utilities

// ParseContentType parses Content-Type header
func ParseContentType(contentType string) (mediaType, charset string) {
	parts := strings.Split(contentType, ";")
	mediaType = strings.TrimSpace(parts[0])

	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if strings.HasPrefix(param, "charset=") {
			charset = strings.TrimSpace(param[8:])
			break
		}
	}

	return mediaType, charset
}

// IsHTMLContent checks if content type is HTML
func IsHTMLContent(contentType string) bool {
	mediaType, _ := ParseContentType(contentType)
	return mediaType == "text/html"
}

// IsJSONContent checks if content type is JSON
func IsJSONContent(contentType string) bool {
	mediaType, _ := ParseContentType(contentType)
	return mediaType == "application/json"
}

// IsXMLContent checks if content type is XML
func IsXMLContent(contentType string) bool {
	mediaType, _ := ParseContentType(contentType)
	return mediaType == "text/xml" || mediaType == "application/xml"
}

// Validation Utilities

// ValidateHTTPTarget validates if target is suitable for HTTP scanning
func ValidateHTTPTarget(target *entities.Target) error {
	switch target.Type() {
	case entities.TargetTypeURL, entities.TargetTypeDomain, entities.TargetTypeIP:
		return nil
	default:
		return errors.NewValidationError("unsupported target type for HTTP scanning", nil)
	}
}

// ValidateURL performs basic URL validation
func ValidateURL(url string) error {
	if url == "" {
		return errors.NewValidationError("URL cannot be empty", nil)
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return errors.NewValidationError("URL must start with http:// or https://", nil)
	}

	return nil
}

// Security Utilities

// GetSecurityGrade calculates security grade from score
func GetSecurityGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// CalculateSecurityScore calculates overall security score
func CalculateSecurityScore(security *SecurityHeaders) int {
	score := 0

	if security.HSTS != nil {
		score += security.HSTS.Score
	}
	if security.CSP != nil {
		score += security.CSP.Score
	}
	if security.XFrameOptions != nil {
		score += security.XFrameOptions.Score
	}
	if security.XContentTypeOptions != nil {
		score += security.XContentTypeOptions.Score
	}
	if security.XSSProtection != nil {
		score += security.XSSProtection.Score
	}
	if security.ReferrerPolicy != nil {
		score += security.ReferrerPolicy.Score
	}

	return score
}

// Common Technology Patterns
var (
	// TechnologyPatterns maps patterns to technologies for detection
	TechnologyPatterns = map[string]Technology{
		"wordpress":  {Name: "WordPress", Categories: []string{"CMS"}, Method: "content"},
		"wp-content": {Name: "WordPress", Categories: []string{"CMS"}, Method: "content"},
		"drupal":     {Name: "Drupal", Categories: []string{"CMS"}, Method: "content"},
		"joomla":     {Name: "Joomla", Categories: []string{"CMS"}, Method: "content"},
		"react":      {Name: "React", Categories: []string{"JavaScript Framework"}, Method: "content"},
		"angular":    {Name: "Angular", Categories: []string{"JavaScript Framework"}, Method: "content"},
		"vue.js":     {Name: "Vue.js", Categories: []string{"JavaScript Framework"}, Method: "content"},
		"jquery":     {Name: "jQuery", Categories: []string{"JavaScript Library"}, Method: "content"},
		"bootstrap":  {Name: "Bootstrap", Categories: []string{"CSS Framework"}, Method: "content"},
	}

	// ServerPatterns maps server header patterns to technologies
	ServerPatterns = map[string]Technology{
		"nginx":      {Name: "Nginx", Categories: []string{"Web Server"}, Method: "header"},
		"apache":     {Name: "Apache", Categories: []string{"Web Server"}, Method: "header"},
		"iis":        {Name: "Microsoft IIS", Categories: []string{"Web Server"}, Method: "header"},
		"cloudflare": {Name: "Cloudflare", Categories: []string{"CDN", "Security"}, Method: "header"},
		"aws":        {Name: "Amazon Web Services", Categories: []string{"Cloud", "Hosting"}, Method: "header"},
	}
)

// GetTechnologyByPattern finds technology by pattern
func GetTechnologyByPattern(pattern string) (*Technology, bool) {
	if tech, exists := TechnologyPatterns[strings.ToLower(pattern)]; exists {
		return &tech, true
	}
	return nil, false
}

// GetServerTechnology parses server header to detect technology
func GetServerTechnology(serverHeader string) *Technology {
	serverLower := strings.ToLower(serverHeader)

	for pattern, tech := range ServerPatterns {
		if strings.Contains(serverLower, pattern) {
			tech.Version = extractVersionFromServer(serverHeader, pattern)
			return &tech
		}
	}

	// Default fallback
	return &Technology{
		Name:       serverHeader,
		Categories: []string{"Web Server"},
		Method:     "header",
	}
}

// extractVersionFromServer extracts version from server header
func extractVersionFromServer(serverHeader, pattern string) string {
	// Simple version extraction - can be improved
	versionRegex := regexp.MustCompile(pattern + `/([0-9\.]+)`)
	matches := versionRegex.FindStringSubmatch(strings.ToLower(serverHeader))
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// No-op Implementations for Testing

// noOpLogger provides a no-operation logger implementation
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, fields map[string]interface{})                   {}
func (l *noOpLogger) Info(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Warn(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Error(msg string, err error, fields map[string]interface{})        {}
func (l *noOpLogger) WithField(key string, value interface{}) interfaces.ScannerLogger  { return l }
func (l *noOpLogger) WithFields(fields map[string]interface{}) interfaces.ScannerLogger { return l }
func (l *noOpLogger) WithScanner(name string) interfaces.ScannerLogger                  { return l }
func (l *noOpLogger) WithTarget(target *entities.Target) interfaces.ScannerLogger       { return l }

// noOpMetrics provides a no-operation metrics implementation
type noOpMetrics struct{}

func (m *noOpMetrics) IncrementScansTotal(scanner string)                         {}
func (m *noOpMetrics) IncrementScansSuccessful(scanner string)                    {}
func (m *noOpMetrics) IncrementScansFailed(scanner string)                        {}
func (m *noOpMetrics) ObserveScanDuration(scanner string, duration time.Duration) {}
func (m *noOpMetrics) ObserveFindingsCount(scanner string, count int)             {}
func (m *noOpMetrics) GetMetrics() map[string]interface{}                         { return nil }

// NewNoOpLogger creates a new no-operation logger
func NewNoOpLogger() interfaces.ScannerLogger {
	return &noOpLogger{}
}

// NewNoOpMetrics creates a new no-operation metrics collector
func NewNoOpMetrics() interfaces.ScannerMetrics {
	return &noOpMetrics{}
}
