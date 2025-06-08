package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "crypto/x509"
	"fmt"
	"io"
	"net/http"
	_ "net/url"
	"regexp"
	_ "regexp"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// HTTPScanner implémente le scanner HTTP selon la nouvelle architecture
type HTTPScanner struct {
	timeout      time.Duration
	userAgent    string
	maxRedirects int
	client       *http.Client
	logger       interfaces.ScannerLogger
	metrics      interfaces.ScannerMetrics
}

// NewHTTPScanner crée une nouvelle instance du scanner HTTP
func NewHTTPScanner() *HTTPScanner {
	scanner := &HTTPScanner{
		timeout:      30 * time.Second,
		userAgent:    "SecurityAuditTool/2.0",
		maxRedirects: 5,
		logger:       &noOpLogger{},
		metrics:      &noOpMetrics{},
	}

	// Configuration du client HTTP
	scanner.client = &http.Client{
		Timeout: scanner.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Pour analyser les certificats invalides
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= scanner.maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return scanner
}

// Info returns metadata about the scanner
func (hs *HTTPScanner) Info() *interfaces.ScannerInfo {
	return &interfaces.ScannerInfo{
		Name:        "http",
		Version:     "2.0.0",
		Description: "HTTP security headers and SSL/TLS analysis",
		Author:      "Security Audit Tool Team",
		Website:     "https://github.com/riadh-benchouche/security-audit-tool",
		License:     "MIT",
		Capabilities: []string{
			"http-headers",
			"ssl-analysis",
			"technology-detection",
			"security-headers",
		},
		Tags: []string{
			"http",
			"ssl",
			"web",
			"security-headers",
		},
		ConfigSchema: map[string]string{
			"timeout":          "int:5:300", // seconds
			"user_agent":       "string",    // custom user agent
			"max_redirects":    "int:0:10",  // max redirects to follow
			"follow_redirects": "bool",      // whether to follow redirects
		},
	}
}

// Configure sets up the scanner with provided configuration
func (hs *HTTPScanner) Configure(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok && t > 0 && t <= 300 {
			hs.timeout = time.Duration(t) * time.Second
			hs.client.Timeout = hs.timeout
		} else {
			return errors.NewValidationError("invalid timeout value", nil)
		}
	}

	if userAgent, ok := config["user_agent"]; ok {
		if ua, ok := userAgent.(string); ok && ua != "" {
			hs.userAgent = ua
		}
	}

	if maxRedirects, ok := config["max_redirects"]; ok {
		if mr, ok := maxRedirects.(int); ok && mr >= 0 && mr <= 10 {
			hs.maxRedirects = mr
		}
	}

	return nil
}

// Validate checks if the scanner can run against the given target
func (hs *HTTPScanner) Validate(target *entities.Target) error {
	switch target.Type() {
	case entities.TargetTypeURL:
		// URL targets are directly supported
		return nil
	case entities.TargetTypeDomain:
		// Domain targets can be converted to HTTP URLs
		return nil
	case entities.TargetTypeIP:
		// IP targets can be converted to HTTP URLs
		return nil
	default:
		return errors.NewValidationError("unsupported target type for HTTP scanning", nil)
	}
}

// Scan executes the security scan against the target
func (hs *HTTPScanner) Scan(ctx context.Context, target *entities.Target) (*entities.ModuleExecution, error) {
	// Create module for this scan
	module, err := entities.NewModule("http", "2.0.0", "HTTP security scanner", "Security Team")
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeScannerError, err, "failed to create module")
	}

	// Create execution
	executionID := fmt.Sprintf("http_%d", time.Now().UnixNano())
	execution, err := entities.NewModuleExecution(executionID, module, target)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeScannerError, err, "failed to create execution")
	}

	// Start execution
	if err := execution.Start(); err != nil {
		return nil, errors.Wrapf(errors.ErrCodeScannerError, err, "failed to start execution")
	}

	logger := hs.logger.WithScanner("http").WithTarget(target)
	logger.Info("Starting HTTP scan", map[string]interface{}{
		"target":      target.Original(),
		"target_type": target.Type().String(),
	})

	// Record scan start
	hs.metrics.IncrementScansTotal("http")

	// Execute scan phases
	err = hs.executeScanPhases(ctx, target, execution, logger)

	// Complete execution
	if err != nil {
		execution.Fail(err.Error())
		hs.metrics.IncrementScansFailed("http")
		logger.Error("HTTP scan failed", err, map[string]interface{}{
			"execution_id": executionID,
		})
	} else {
		execution.Complete()
		hs.metrics.IncrementScansSuccessful("http")
		logger.Info("HTTP scan completed successfully", map[string]interface{}{
			"execution_id": executionID,
			"findings":     execution.FindingCount(),
			"duration":     execution.Duration().String(),
		})
	}

	// Record metrics
	hs.metrics.ObserveScanDuration("http", execution.Duration())
	hs.metrics.ObserveFindingsCount("http", execution.FindingCount())

	return execution, err
}

// Stop gracefully stops a running scan
func (hs *HTTPScanner) Stop() error {
	// HTTP scanner doesn't have long-running operations to stop
	return nil
}

// Health returns the current health status of the scanner
func (hs *HTTPScanner) Health() *interfaces.HealthStatus {
	return &interfaces.HealthStatus{
		Status:      "healthy",
		Message:     "HTTP scanner is ready",
		LastChecked: time.Now().Unix(),
		Errors:      make([]string, 0),
	}
}

// SetLogger sets the logger for the scanner
func (hs *HTTPScanner) SetLogger(logger interfaces.ScannerLogger) {
	hs.logger = logger
}

// SetMetrics sets the metrics collector for the scanner
func (hs *HTTPScanner) SetMetrics(metrics interfaces.ScannerMetrics) {
	hs.metrics = metrics
}

// executeScanPhases executes the main scan phases
func (hs *HTTPScanner) executeScanPhases(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) error {
	// Phase 1: Normalize URL (10%)
	execution.SetProgress(10)
	targetURL, err := hs.normalizeURL(target)
	if err != nil {
		return errors.Wrapf(errors.ErrCodeValidation, err, "failed to normalize URL")
	}

	// Phase 2: HTTP Request (40%)
	execution.SetProgress(20)
	httpResult, err := hs.performHTTPRequest(ctx, targetURL)
	if err != nil {
		// Log error but continue analysis if we have partial results
		logger.Warn("HTTP request failed", map[string]interface{}{
			"error": err.Error(),
			"url":   targetURL,
		})
	}
	execution.SetProgress(60)

	// Phase 3: Analysis (30%)
	if httpResult != nil {
		hs.analyzeHTTPResponse(execution, httpResult, targetURL, logger)
	}
	execution.SetProgress(90)

	// Phase 4: Finalization (10%)
	if httpResult != nil {
		execution.SetMetadata("status_code", httpResult.StatusCode)
		execution.SetMetadata("response_time", httpResult.ResponseTime.Milliseconds())
		execution.SetMetadata("url", targetURL)
	}

	execution.SetProgress(100)
	return nil
}

// normalizeURL converts target to HTTP URL
func (hs *HTTPScanner) normalizeURL(target *entities.Target) (string, error) {
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

// HTTPResult holds the results of an HTTP request
type HTTPResult struct {
	URL          string
	StatusCode   int
	Headers      map[string]string
	Title        string
	Server       string
	Technologies []Technology
	SSL          *SSLResult
	Security     SecurityHeaders
	ResponseTime time.Duration
}

// Technology represents a detected technology
type Technology struct {
	Name       string
	Categories []string
}

// SSLResult holds SSL/TLS analysis results
type SSLResult struct {
	Enabled         bool
	Version         string
	Protocols       []string
	Certificate     *Certificate
	Vulnerabilities []string
	Grade           string
}

// Certificate holds certificate information
type Certificate struct {
	Subject        string
	Issuer         string
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
	IsExpired      bool
	IsCA           bool
	KeySize        int
	SignatureAlg   string
	DNSNames       []string
	EmailAddresses []string
}

// SecurityHeaders holds security headers analysis
type SecurityHeaders struct {
	HSTS                *Header
	CSP                 *Header
	XFrameOptions       *Header
	XContentTypeOptions *Header
	XSSProtection       *Header
	ReferrerPolicy      *Header
	Score               int
	Grade               string
}

// Header represents a security header analysis
type Header struct {
	Present bool
	Value   string
	Valid   bool
	Score   int
	Issues  []string
}

// performHTTPRequest performs the actual HTTP request
func (hs *HTTPScanner) performHTTPRequest(ctx context.Context, targetURL string) (*HTTPResult, error) {
	start := time.Now()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeNetwork, err, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("User-Agent", hs.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	// Perform request
	resp, err := hs.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeNetwork, err, "HTTP request failed")
	}
	defer resp.Body.Close()

	responseTime := time.Since(start)

	// Read response body (limited to prevent memory issues)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		hs.logger.Warn("Failed to read response body", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Build result
	result := &HTTPResult{
		URL:          targetURL,
		StatusCode:   resp.StatusCode,
		Headers:      hs.convertHeaders(resp.Header),
		Title:        hs.extractTitle(string(body)),
		Server:       resp.Header.Get("Server"),
		Technologies: hs.detectTechnologies(resp.Header, string(body)),
		ResponseTime: responseTime,
	}

	// Analyze SSL if HTTPS
	if strings.HasPrefix(targetURL, "https://") && resp.TLS != nil {
		result.SSL = hs.analyzeSSL(resp.TLS)
	}

	// Analyze security headers
	result.Security = hs.analyzeSecurityHeaders(resp.Header)

	return result, nil
}

// Reste des méthodes d'analyse (extractTitle, detectTechnologies, etc.)
// [Les méthodes sont similaires à votre ancien code mais adaptées aux nouvelles entités]

// analyzeHTTPResponse creates findings from HTTP analysis
func (hs *HTTPScanner) analyzeHTTPResponse(execution *entities.ModuleExecution, httpResult *HTTPResult, targetURL string, logger interfaces.ScannerLogger) {
	// Status code findings
	if httpResult.StatusCode >= 400 {
		severity := entities.SeverityMedium
		if httpResult.StatusCode >= 500 {
			severity = entities.SeverityHigh
		}

		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("http-status-%d", httpResult.StatusCode)).
			WithType(entities.FindingTypeInformation).
			WithSeverity(severity).
			WithTitle(fmt.Sprintf("HTTP %d Response", httpResult.StatusCode)).
			WithDescription(fmt.Sprintf("Server returned HTTP %d status code", httpResult.StatusCode)).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"status_code": httpResult.StatusCode,
				"url":         httpResult.URL,
			}).
			WithTags("http", "status-code").
			Build()

		if err == nil {
			execution.AddFinding(finding)
		} else {
			logger.Error("Failed to create status code finding", err, nil)
		}
	}

	// Security headers findings
	hs.analyzeSecurityHeadersFindings(execution, httpResult, targetURL, logger)

	// SSL findings
	if httpResult.SSL != nil {
		hs.analyzeSSLFindings(execution, httpResult.SSL, targetURL, logger)
	}

	// Technology findings
	for _, tech := range httpResult.Technologies {
		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("http-technology-%s", strings.ToLower(tech.Name))).
			WithType(entities.FindingTypeInformation).
			WithSeverity(entities.SeverityInfo).
			WithTitle(fmt.Sprintf("Technology detected: %s", tech.Name)).
			WithDescription(fmt.Sprintf("The website uses %s", tech.Name)).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"technology": tech.Name,
				"categories": tech.Categories,
			}).
			WithTags(append([]string{"http", "technology"}, tech.Categories...)...).
			Build()

		if err == nil {
			execution.AddFinding(finding)
		}
	}
}

// Implémentations no-op pour les dépendances
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, fields map[string]interface{})                   {}
func (l *noOpLogger) Info(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Warn(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Error(msg string, err error, fields map[string]interface{})        {}
func (l *noOpLogger) WithField(key string, value interface{}) interfaces.ScannerLogger  { return l }
func (l *noOpLogger) WithFields(fields map[string]interface{}) interfaces.ScannerLogger { return l }
func (l *noOpLogger) WithScanner(name string) interfaces.ScannerLogger                  { return l }
func (l *noOpLogger) WithTarget(target *entities.Target) interfaces.ScannerLogger       { return l }

type noOpMetrics struct{}

func (m *noOpMetrics) IncrementScansTotal(scanner string)                         {}
func (m *noOpMetrics) IncrementScansSuccessful(scanner string)                    {}
func (m *noOpMetrics) IncrementScansFailed(scanner string)                        {}
func (m *noOpMetrics) ObserveScanDuration(scanner string, duration time.Duration) {}
func (m *noOpMetrics) ObserveFindingsCount(scanner string, count int)             {}
func (m *noOpMetrics) GetMetrics() map[string]interface{}                         { return nil }

func (hs *HTTPScanner) convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

// extractTitle extracts page title from HTML content
func (hs *HTTPScanner) extractTitle(body string) string {
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

// detectTechnologies detects web technologies from headers and content
func (hs *HTTPScanner) detectTechnologies(headers http.Header, body string) []Technology {
	technologies := make([]Technology, 0)

	// Detection based on headers
	if server := headers.Get("Server"); server != "" {
		tech := hs.parseServerHeader(server)
		if tech != nil {
			technologies = append(technologies, *tech)
		}
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		technologies = append(technologies, Technology{
			Name:       powered,
			Categories: []string{"Web Server Extension"},
		})
	}

	// Detection based on content
	bodyTech := hs.detectTechnologiesFromBody(body)
	technologies = append(technologies, bodyTech...)

	return technologies
}

// parseServerHeader parses the Server header
func (hs *HTTPScanner) parseServerHeader(server string) *Technology {
	server = strings.ToLower(server)

	switch {
	case strings.Contains(server, "nginx"):
		return &Technology{
			Name:       "Nginx",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "apache"):
		return &Technology{
			Name:       "Apache",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "iis"):
		return &Technology{
			Name:       "Microsoft IIS",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "cloudflare"):
		return &Technology{
			Name:       "Cloudflare",
			Categories: []string{"CDN", "Security"},
		}
	default:
		return &Technology{
			Name:       server,
			Categories: []string{"Web Server"},
		}
	}
}

// detectTechnologiesFromBody detects technologies from HTML content
func (hs *HTTPScanner) detectTechnologiesFromBody(body string) []Technology {
	technologies := make([]Technology, 0)
	bodyLower := strings.ToLower(body)

	// Common detections
	detections := map[string]Technology{
		"wordpress":  {Name: "WordPress", Categories: []string{"CMS"}},
		"wp-content": {Name: "WordPress", Categories: []string{"CMS"}},
		"drupal":     {Name: "Drupal", Categories: []string{"CMS"}},
		"joomla":     {Name: "Joomla", Categories: []string{"CMS"}},
		"react":      {Name: "React", Categories: []string{"JavaScript Framework"}},
		"angular":    {Name: "Angular", Categories: []string{"JavaScript Framework"}},
		"vue.js":     {Name: "Vue.js", Categories: []string{"JavaScript Framework"}},
		"jquery":     {Name: "jQuery", Categories: []string{"JavaScript Library"}},
		"bootstrap":  {Name: "Bootstrap", Categories: []string{"CSS Framework"}},
	}

	for pattern, tech := range detections {
		if strings.Contains(bodyLower, pattern) {
			technologies = append(technologies, tech)
		}
	}

	return technologies
}

// analyzeSSL analyzes SSL/TLS configuration
func (hs *HTTPScanner) analyzeSSL(tlsState *tls.ConnectionState) *SSLResult {
	if tlsState == nil {
		return nil
	}

	sslResult := &SSLResult{
		Enabled:         true,
		Version:         hs.getTLSVersionString(tlsState.Version),
		Protocols:       []string{hs.getTLSVersionString(tlsState.Version)},
		Vulnerabilities: make([]string, 0),
	}

	// Analyze certificate
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		sslResult.Certificate = &Certificate{
			Subject:        cert.Subject.String(),
			Issuer:         cert.Issuer.String(),
			SerialNumber:   cert.SerialNumber.String(),
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			IsExpired:      time.Now().After(cert.NotAfter),
			IsCA:           cert.IsCA,
			KeySize:        hs.getKeySize(cert),
			SignatureAlg:   cert.SignatureAlgorithm.String(),
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
	}

	// Check vulnerabilities
	if tlsState.Version < tls.VersionTLS12 {
		sslResult.Vulnerabilities = append(sslResult.Vulnerabilities, "Outdated TLS version")
	}

	// Calculate grade
	sslResult.Grade = hs.calculateSSLGrade(sslResult)

	return sslResult
}

// getTLSVersionString converts TLS version to string
func (hs *HTTPScanner) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// getKeySize extracts key size from certificate
func (hs *HTTPScanner) getKeySize(cert *x509.Certificate) int {
	// Simplified - in a real scanner, we'd analyze the key type
	return 2048 // Default value
}

// calculateSSLGrade calculates SSL configuration grade
func (hs *HTTPScanner) calculateSSLGrade(ssl *SSLResult) string {
	score := 100

	// Penalties
	if len(ssl.Vulnerabilities) > 0 {
		score -= len(ssl.Vulnerabilities) * 20
	}

	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		score -= 50
	}

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

// analyzeSecurityHeaders analyzes security headers
func (hs *HTTPScanner) analyzeSecurityHeaders(headers http.Header) SecurityHeaders {
	security := SecurityHeaders{
		Score: 0,
	}

	// Analyze each security header
	security.HSTS = hs.analyzeHSTS(headers.Get("Strict-Transport-Security"))
	security.CSP = hs.analyzeCSP(headers.Get("Content-Security-Policy"))
	security.XFrameOptions = hs.analyzeXFrameOptions(headers.Get("X-Frame-Options"))
	security.XContentTypeOptions = hs.analyzeXContentTypeOptions(headers.Get("X-Content-Type-Options"))
	security.XSSProtection = hs.analyzeXSSProtection(headers.Get("X-XSS-Protection"))
	security.ReferrerPolicy = hs.analyzeReferrerPolicy(headers.Get("Referrer-Policy"))

	// Calculate overall score
	security.Score = hs.calculateSecurityScore(&security)
	security.Grade = hs.calculateSecurityGrade(security.Score)

	return security
}

// analyzeHSTS analyzes HSTS header
func (hs *HTTPScanner) analyzeHSTS(hsts string) *Header {
	header := &Header{
		Present: hsts != "",
		Value:   hsts,
	}

	if header.Present {
		header.Valid = strings.Contains(hsts, "max-age=")
		header.Score = 20
		if strings.Contains(hsts, "includeSubDomains") {
			header.Score += 5
		}
		if strings.Contains(hsts, "preload") {
			header.Score += 5
		}
	} else {
		header.Issues = []string{"HSTS header missing"}
	}

	return header
}

// analyzeCSP analyzes CSP header
func (hs *HTTPScanner) analyzeCSP(csp string) *Header {
	header := &Header{
		Present: csp != "",
		Value:   csp,
	}

	if header.Present {
		header.Valid = true
		header.Score = 25
		if strings.Contains(csp, "unsafe-inline") {
			header.Issues = append(header.Issues, "unsafe-inline directive found")
			header.Score -= 10
		}
		if strings.Contains(csp, "unsafe-eval") {
			header.Issues = append(header.Issues, "unsafe-eval directive found")
			header.Score -= 10
		}
	} else {
		header.Issues = []string{"CSP header missing"}
	}

	return header
}

// analyzeXFrameOptions analyzes X-Frame-Options header
func (hs *HTTPScanner) analyzeXFrameOptions(xfo string) *Header {
	header := &Header{
		Present: xfo != "",
		Value:   xfo,
	}

	if header.Present {
		xfoLower := strings.ToLower(xfo)
		header.Valid = xfoLower == "deny" || xfoLower == "sameorigin" || strings.HasPrefix(xfoLower, "allow-from")
		if header.Valid {
			header.Score = 15
		}
	} else {
		header.Issues = []string{"X-Frame-Options header missing"}
	}

	return header
}

// analyzeXContentTypeOptions analyzes X-Content-Type-Options header
func (hs *HTTPScanner) analyzeXContentTypeOptions(xcto string) *Header {
	header := &Header{
		Present: xcto != "",
		Value:   xcto,
	}

	if header.Present {
		header.Valid = strings.ToLower(xcto) == "nosniff"
		if header.Valid {
			header.Score = 10
		}
	} else {
		header.Issues = []string{"X-Content-Type-Options header missing"}
	}

	return header
}

// analyzeXSSProtection analyzes X-XSS-Protection header
func (hs *HTTPScanner) analyzeXSSProtection(xss string) *Header {
	header := &Header{
		Present: xss != "",
		Value:   xss,
	}

	if header.Present {
		header.Valid = strings.Contains(xss, "1") && strings.Contains(xss, "mode=block")
		if header.Valid {
			header.Score = 10
		}
	} else {
		header.Issues = []string{"X-XSS-Protection header missing"}
	}

	return header
}

// analyzeReferrerPolicy analyzes Referrer-Policy header
func (hs *HTTPScanner) analyzeReferrerPolicy(rp string) *Header {
	header := &Header{
		Present: rp != "",
		Value:   rp,
	}

	if header.Present {
		validPolicies := []string{"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
		for _, policy := range validPolicies {
			if strings.Contains(strings.ToLower(rp), policy) {
				header.Valid = true
				header.Score = 10
				break
			}
		}
	} else {
		header.Issues = []string{"Referrer-Policy header missing"}
	}

	return header
}

// calculateSecurityScore calculates overall security score
func (hs *HTTPScanner) calculateSecurityScore(security *SecurityHeaders) int {
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

// calculateSecurityGrade calculates security grade
func (hs *HTTPScanner) calculateSecurityGrade(score int) string {
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

// analyzeSecurityHeadersFindings creates findings from security headers analysis
func (hs *HTTPScanner) analyzeSecurityHeadersFindings(execution *entities.ModuleExecution, httpResult *HTTPResult, targetURL string, logger interfaces.ScannerLogger) {
	security := httpResult.Security

	// HSTS missing
	if security.HSTS != nil && !security.HSTS.Present {
		finding, err := entities.NewFindingBuilder().
			WithID("http-missing-hsts").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(entities.SeverityMedium).
			WithTitle("Missing HSTS Header").
			WithDescription("The Strict-Transport-Security header is missing, which could allow downgrade attacks").
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"header":  "Strict-Transport-Security",
				"present": false,
			}).
			WithTags("http", "security-headers", "hsts").
			Build()

		if err == nil {
			finding.SetRemediation("Add the Strict-Transport-Security header to enforce HTTPS connections")
			execution.AddFinding(finding)
		}
	}

	// CSP missing
	if security.CSP != nil && !security.CSP.Present {
		finding, err := entities.NewFindingBuilder().
			WithID("http-missing-csp").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(entities.SeverityMedium).
			WithTitle("Missing Content Security Policy").
			WithDescription("The Content-Security-Policy header is missing, which could allow XSS attacks").
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"header":  "Content-Security-Policy",
				"present": false,
			}).
			WithTags("http", "security-headers", "csp", "xss").
			Build()

		if err == nil {
			finding.SetRemediation("Implement a Content Security Policy to prevent XSS attacks")
			execution.AddFinding(finding)
		}
	}

	// X-Frame-Options missing
	if security.XFrameOptions != nil && !security.XFrameOptions.Present {
		finding, err := entities.NewFindingBuilder().
			WithID("http-missing-x-frame-options").
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

// analyzeSSLFindings creates findings from SSL analysis
func (hs *HTTPScanner) analyzeSSLFindings(execution *entities.ModuleExecution, ssl *SSLResult, targetURL string, logger interfaces.ScannerLogger) {
	// Expired certificate
	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		finding, err := entities.NewFindingBuilder().
			WithID("ssl-expired-certificate").
			WithType(entities.FindingTypeVulnerability).
			WithSeverity(entities.SeverityHigh).
			WithTitle("Expired SSL Certificate").
			WithDescription(fmt.Sprintf("The SSL certificate expired on %s", ssl.Certificate.NotAfter.Format("2006-01-02"))).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"not_after": ssl.Certificate.NotAfter,
				"subject":   ssl.Certificate.Subject,
			}).
			WithTags("ssl", "certificate", "expired").
			Build()

		if err == nil {
			finding.SetRemediation("Renew the SSL certificate before it expires")
			execution.AddFinding(finding)
		}
	}

	// Outdated TLS version
	for _, vuln := range ssl.Vulnerabilities {
		if strings.Contains(vuln, "Outdated TLS") {
			finding, err := entities.NewFindingBuilder().
				WithID("ssl-outdated-tls").
				WithType(entities.FindingTypeVulnerability).
				WithSeverity(entities.SeverityMedium).
				WithTitle("Outdated TLS Version").
				WithDescription("The server supports outdated TLS versions that may be vulnerable").
				WithTarget(targetURL).
				WithModuleSource("http").
				WithEvidence(entities.Evidence{
					"tls_version": ssl.Version,
				}).
				WithTags("ssl", "tls", "outdated").
				Build()

			if err == nil {
				finding.SetRemediation("Disable TLS 1.0 and 1.1, use TLS 1.2 or higher")
				execution.AddFinding(finding)
			}
		}
	}
}
