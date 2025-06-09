package http

import (
	"context"
	_ "crypto/x509"
	"fmt"
	"io"
	"net/http"
	_ "net/url"
	_ "regexp"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// HTTPScanner implémente le scanner HTTP selon la nouvelle architecture
type HTTPScanner struct {
	config  *Config
	client  *http.Client
	logger  interfaces.ScannerLogger
	metrics interfaces.ScannerMetrics
}

// NewHTTPScanner crée une nouvelle instance du scanner HTTP
func NewHTTPScanner() *HTTPScanner {
	config := NewDefaultConfig()

	scanner := &HTTPScanner{
		config:  config,
		client:  config.CreateHTTPClient(), // 🆕 Utilise la factory method
		logger:  NewNoOpLogger(),
		metrics: NewNoOpMetrics(),
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
	// Update configuration
	if err := hs.config.Update(config); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	// Recreate HTTP client with new config
	hs.client = hs.config.CreateHTTPClient()

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
	targetURL, err := NormalizeURL(target)
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
		analyzer := NewHTTPAnalyzer(logger)
		analyzer.AnalyzeResponse(httpResult, targetURL, execution)
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

// performHTTPRequest performs the actual HTTP request
func (hs *HTTPScanner) performHTTPRequest(ctx context.Context, targetURL string) (*HTTPResult, error) {
	start := time.Now()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeNetwork, err, "failed to create HTTP request")
	}

	// Add headers
	req.Header.Set("User-Agent", hs.config.GetUserAgent())
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, hs.config.GetMaxResponseSize())) // 1MB limit
	if err != nil {
		hs.logger.Warn("Failed to read response body", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Build result
	result := &HTTPResult{
		URL:          targetURL,
		StatusCode:   resp.StatusCode,
		Headers:      ConvertHeaders(resp.Header),
		Title:        ExtractTitle(string(body)),
		Server:       resp.Header.Get("Server"),
		Technologies: make([]Technology, 0),
		ResponseTime: responseTime,
	}

	// Analyze SSL if HTTPS
	if strings.HasPrefix(targetURL, "https://") && resp.TLS != nil {
		sslAnalyzer := NewSSLAnalyzer(hs.logger)
		result.SSL = sslAnalyzer.AnalyzeSSL(resp.TLS)
	}

	// Analyze security headers
	securityAnalyzer := NewSecurityHeadersAnalyzer(hs.logger)
	result.Security = securityAnalyzer.AnalyzeHeaders(resp.Header)

	techDetector := NewTechnologyDetector()
	result.Technologies = techDetector.DetectTechnologies(resp.Header, string(body))

	return result, nil
}
