package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// NetworkScanner implements the Scanner interface for network scanning
type NetworkScanner struct {
	config      *Config
	logger      interfaces.ScannerLogger
	metrics     interfaces.ScannerMetrics
	portScanner PortScanner
	detector    ServiceDetector
	grabber     BannerGrabber
	osDetector  OSDetector

	// Runtime state
	isRunning bool
	stopChan  chan struct{}
	mu        sync.RWMutex
}

// NewNetworkScanner creates a new network scanner instance
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		config:      NewDefaultConfig(),
		stopChan:    make(chan struct{}),
		portScanner: NewPortScanner(),
		detector:    NewServiceDetector(),
		grabber:     NewBannerGrabber(),
		osDetector:  NewOSDetector(),
		logger:      &noOpLogger{},  // Default no-op logger
		metrics:     &noOpMetrics{}, // Default no-op metrics
	}
}

// Info returns metadata about the scanner
func (ns *NetworkScanner) Info() *interfaces.ScannerInfo {
	return &interfaces.ScannerInfo{
		Name:        "network",
		Version:     "1.0.0",
		Description: "Advanced network port scanning with service detection",
		Author:      "Security Audit Tool Team",
		Website:     "https://github.com/riadh-benchouche/security-audit-tool",
		License:     "MIT",
		Capabilities: []string{
			"port-scan",
			"service-detection",
			"banner-grabbing",
			"os-detection",
			"network-discovery",
		},
		Tags: []string{
			"network",
			"ports",
			"services",
			"reconnaissance",
		},
		ConfigSchema: map[string]string{
			"timeout":      "int:5:300",     // seconds, min 5, max 300
			"max_threads":  "int:1:200",     // concurrent threads
			"ports":        "[]int",         // list of ports to scan
			"top_ports":    "int:100:10000", // number of top ports
			"tcp_timeout":  "int:1:30",      // TCP connection timeout
			"udp_timeout":  "int:1:30",      // UDP timeout
			"ping_check":   "bool",          // perform ping check
			"service_scan": "bool",          // enable service detection
			"banner_grab":  "bool",          // enable banner grabbing
			"os_detect":    "bool",          // enable OS detection
		},
	}
}

// Configure sets up the scanner with provided configuration
func (ns *NetworkScanner) Configure(config map[string]interface{}) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.isRunning {
		return errors.NewBusinessLogicError("cannot configure running scanner", nil)
	}

	// Update configuration
	if err := ns.config.Update(config); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	// Configure sub-components
	if err := ns.portScanner.Configure(ns.config); err != nil {
		return fmt.Errorf("failed to configure port scanner: %w", err)
	}

	if err := ns.detector.Configure(ns.config); err != nil {
		return fmt.Errorf("failed to configure service detector: %w", err)
	}

	if err := ns.grabber.Configure(ns.config); err != nil {
		return fmt.Errorf("failed to configure banner grabber: %w", err)
	}

	if err := ns.osDetector.Configure(ns.config); err != nil {
		return fmt.Errorf("failed to configure OS detector: %w", err)
	}

	return nil
}

// Validate checks if the scanner can run against the given target
func (ns *NetworkScanner) Validate(target *entities.Target) error {
	// Check if target type is supported
	switch target.Type() {
	case entities.TargetTypeIP, entities.TargetTypeDomain, entities.TargetTypeCIDR:
		// Supported types
	case entities.TargetTypeURL:
		// Extract host from URL for network scanning
		if target.Host() == "" {
			return errors.NewValidationError("URL target must have a valid host", nil)
		}
	default:
		return errors.NewValidationError("unsupported target type for network scanning", nil)
	}

	// Validate target is reachable (if configured)
	if ns.config.PingCheck {
		if err := ns.validateConnectivity(target); err != nil {
			return fmt.Errorf("target connectivity check failed: %w", err)
		}
	}

	return nil
}

// Scan executes the security scan against the target
func (ns *NetworkScanner) Scan(ctx context.Context, target *entities.Target) (*entities.ModuleExecution, error) {
	ns.mu.Lock()
	if ns.isRunning {
		ns.mu.Unlock()
		return nil, errors.NewBusinessLogicError("scanner is already running", nil)
	}
	ns.isRunning = true
	ns.mu.Unlock()

	defer func() {
		ns.mu.Lock()
		ns.isRunning = false
		ns.mu.Unlock()
	}()

	// Create module for this scan
	module, err := entities.NewModule("network", "1.0.0", "Network security scanner", "Security Team")
	if err != nil {
		return nil, fmt.Errorf("failed to create module: %w", err)
	}

	// Create execution
	executionID := fmt.Sprintf("network_%d", time.Now().UnixNano())
	execution, err := entities.NewModuleExecution(executionID, module, target)
	if err != nil {
		return nil, fmt.Errorf("failed to create execution: %w", err)
	}

	// Start execution
	if err := execution.Start(); err != nil {
		return nil, fmt.Errorf("failed to start execution: %w", err)
	}

	// Set up logging context
	logger := ns.logger.WithScanner("network").WithTarget(target)
	logger.Info("Starting network scan", map[string]interface{}{
		"target":      target.Original(),
		"target_type": target.Type().String(),
	})

	// Record scan start
	ns.metrics.IncrementScansTotal("network")

	// Execute scan phases
	err = ns.executeScanPhases(ctx, target, execution, logger)

	// Complete execution
	if err != nil {
		execution.Fail(err.Error())
		ns.metrics.IncrementScansFailed("network")
		logger.Error("Network scan failed", err, map[string]interface{}{
			"execution_id": executionID,
		})
	} else {
		execution.Complete()
		ns.metrics.IncrementScansSuccessful("network")
		logger.Info("Network scan completed successfully", map[string]interface{}{
			"execution_id": executionID,
			"findings":     execution.FindingCount(),
			"duration":     execution.Duration().String(),
		})
	}

	// Record metrics
	ns.metrics.ObserveScanDuration("network", execution.Duration())
	ns.metrics.ObserveFindingsCount("network", execution.FindingCount())

	return execution, err
}

// Stop gracefully stops a running scan
func (ns *NetworkScanner) Stop() error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if !ns.isRunning {
		return nil // Already stopped
	}

	// Signal stop to all components
	close(ns.stopChan)
	ns.stopChan = make(chan struct{}) // Reset for next use

	// Stop sub-components
	ns.portScanner.Stop()
	ns.detector.Stop()
	ns.grabber.Stop()
	ns.osDetector.Stop()

	return nil
}

// Health returns the current health status of the scanner
func (ns *NetworkScanner) Health() *interfaces.HealthStatus {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	status := &interfaces.HealthStatus{
		Status:      interfaces.HealthStateHealthy,
		LastChecked: time.Now().Unix(),
		Errors:      make([]string, 0),
	}

	// Check if scanner is in a valid state
	if ns.config == nil {
		status.Status = interfaces.HealthStateUnhealthy
		status.Errors = append(status.Errors, "configuration not initialized")
	}

	// Check sub-component health
	if !ns.portScanner.IsHealthy() {
		status.Status = interfaces.HealthStateUnhealthy
		status.Errors = append(status.Errors, "port scanner unhealthy")
	}

	if !ns.detector.IsHealthy() {
		status.Status = interfaces.HealthStateUnhealthy
		status.Errors = append(status.Errors, "service detector unhealthy")
	}

	if len(status.Errors) == 0 {
		status.Message = "Network scanner is healthy and ready"
	} else {
		status.Message = fmt.Sprintf("Network scanner has %d issues", len(status.Errors))
	}

	return status
}

// executeScanPhases executes the main scan phases
func (ns *NetworkScanner) executeScanPhases(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) error {
	// Phase 1: Connectivity Check (5%)
	execution.SetProgress(5)
	if ns.config.PingCheck {
		if err := ns.performConnectivityCheck(ctx, target, execution, logger); err != nil {
			logger.Warn("Connectivity check failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Don't fail the entire scan for connectivity issues
		}
	}

	// Phase 2: Port Scanning (60%)
	err := execution.SetProgress(10)
	if err != nil {
		return err
	}
	portResults, err := ns.performPortScan(ctx, target, execution, logger)
	if err != nil {
		return fmt.Errorf("port scanning failed: %w", err)
	}
	err = execution.SetProgress(70)
	if err != nil {
		return err
	}

	// Phase 3: Service Detection (20%)
	if ns.config.ServiceScan && len(portResults) > 0 {
		if err := ns.performServiceDetection(ctx, target, portResults, execution, logger); err != nil {
			logger.Warn("Service detection failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Don't fail scan for service detection issues
		}
	}
	execution.SetProgress(90)

	// Phase 4: OS Detection (10%)
	if ns.config.OSDetect {
		if err := ns.performOSDetection(ctx, target, execution, logger); err != nil {
			logger.Warn("OS detection failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Don't fail scan for OS detection issues
		}
	}

	execution.SetProgress(100)
	return nil
}

// performConnectivityCheck checks if target is reachable
func (ns *NetworkScanner) performConnectivityCheck(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) error {
	logger.Debug("Starting connectivity check", nil)

	// Simple TCP connectivity test
	address := net.JoinHostPort(target.Host(), "80")
	conn, err := net.DialTimeout("tcp", address, time.Duration(ns.config.TCPTimeout)*time.Second)

	if err != nil {
		// Try HTTPS port
		address = net.JoinHostPort(target.Host(), "443")
		conn, err = net.DialTimeout("tcp", address, time.Duration(ns.config.TCPTimeout)*time.Second)
	}

	if conn != nil {
		conn.Close()

		// Create connectivity finding
		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("network_connectivity_%s", target.Host())).
			WithType(entities.FindingTypeInformation).
			WithSeverity(entities.SeverityInfo).
			WithTitle("Host is reachable").
			WithDescription(fmt.Sprintf("Target %s is reachable via network", target.Host())).
			WithTarget(target.Original()).
			WithModuleSource("network").
			WithEvidence(entities.Evidence{
				"method":      "tcp",
				"target_host": target.Host(),
				"reachable":   true,
			}).
			WithTags("connectivity", "network", "reachable").
			Build()

		if err != nil {
			return fmt.Errorf("failed to create connectivity finding: %w", err)
		}

		execution.AddFinding(finding)
	}

	return err // Return the original error for logging
}

// performPortScan executes the port scanning phase
func (ns *NetworkScanner) performPortScan(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) ([]PortResult, error) {
	logger.Info("Starting port scan", map[string]interface{}{
		"ports_count": len(ns.config.Ports),
		"max_threads": ns.config.MaxThreads,
	})

	// Execute port scan
	results, err := ns.portScanner.ScanPorts(ctx, target, ns.config.Ports, ns.stopChan)
	if err != nil {
		return nil, fmt.Errorf("port scanning failed: %w", err)
	}

	// Create findings for open ports
	for _, result := range results {
		if result.State == PortStateOpen {
			severity := entities.SeverityInfo
			description := fmt.Sprintf("Port %d/%s is open", result.Port, result.Protocol)

			// Adjust severity based on port type
			if ns.isHighRiskPort(result.Port) {
				severity = entities.SeverityMedium
				description += " (potentially high-risk service)"
			}

			finding, err := entities.NewFindingBuilder().
				WithID(fmt.Sprintf("network_port_%s_%d", target.Host(), result.Port)).
				WithType(entities.FindingTypeInformation).
				WithSeverity(severity).
				WithTitle(fmt.Sprintf("Open port %d/%s", result.Port, result.Protocol)).
				WithDescription(description).
				WithTarget(fmt.Sprintf("%s:%d", target.Original(), result.Port)).
				WithModuleSource("network").
				WithEvidence(entities.Evidence{
					"port":     result.Port,
					"protocol": result.Protocol,
					"state":    result.State.String(),
					"banner":   result.Banner,
				}).
				WithTags("network", "port-scan", result.Protocol).
				Build()

			if err != nil {
				logger.Error("Failed to create port finding", err, map[string]interface{}{
					"port": result.Port,
				})
				continue
			}

			execution.AddFinding(finding)
		}
	}

	// Set metadata
	execution.SetMetadata("ports_scanned", len(ns.config.Ports))
	execution.SetMetadata("open_ports", len(results))

	logger.Info("Port scan completed", map[string]interface{}{
		"open_ports":  len(results),
		"total_ports": len(ns.config.Ports),
	})

	return results, nil
}

// performServiceDetection executes service detection on open ports
func (ns *NetworkScanner) performServiceDetection(ctx context.Context, target *entities.Target, portResults []PortResult, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) error {
	logger.Info("Starting service detection", map[string]interface{}{
		"open_ports": len(portResults),
	})

	for _, portResult := range portResults {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ns.stopChan:
			return errors.NewBusinessLogicError("scan stopped", nil)
		default:
		}

		// Detect service
		service, err := ns.detector.DetectService(ctx, target, portResult.Port)
		if err != nil {
			logger.Warn("Service detection failed for port", map[string]interface{}{
				"port":  portResult.Port,
				"error": err.Error(),
			})
			continue
		}

		if service != nil {
			// Create service finding
			severity := entities.SeverityInfo
			description := fmt.Sprintf("Service %s detected on port %d", service.Name, portResult.Port)

			// Check for insecure services
			if ns.isInsecureService(service.Name) {
				severity = entities.SeverityHigh
				description += " (insecure protocol)"
			}

			finding, err := entities.NewFindingBuilder().
				WithID(fmt.Sprintf("network_service_%s_%d_%s", target.Host(), portResult.Port, service.Name)).
				WithType(entities.FindingTypeInformation).
				WithSeverity(severity).
				WithTitle(fmt.Sprintf("Service detected: %s", service.Name)).
				WithDescription(description).
				WithTarget(fmt.Sprintf("%s:%d", target.Original(), portResult.Port)).
				WithModuleSource("network").
				WithEvidence(entities.Evidence{
					"service_name":    service.Name,
					"service_version": service.Version,
					"port":            portResult.Port,
					"confidence":      service.Confidence,
					"method":          service.DetectionMethod,
				}).
				WithTags("network", "service-detection", service.Name).
				Build()

			if err != nil {
				logger.Error("Failed to create service finding", err, map[string]interface{}{
					"service": service.Name,
					"port":    portResult.Port,
				})
				continue
			}

			// Add remediation for insecure services
			if ns.isInsecureService(service.Name) {
				finding.SetRemediation(fmt.Sprintf("Replace %s with a secure alternative. This protocol transmits data in clear text.", service.Name))
			}

			execution.AddFinding(finding)
		}
	}

	return nil
}

// performOSDetection executes OS detection
func (ns *NetworkScanner) performOSDetection(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution, logger interfaces.ScannerLogger) error {
	logger.Debug("Starting OS detection", nil)

	osInfo, err := ns.osDetector.DetectOS(ctx, target)
	if err != nil {
		return fmt.Errorf("OS detection failed: %w", err)
	}

	if osInfo != nil && osInfo.Name != "" {
		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("network_os_%s", target.Host())).
			WithType(entities.FindingTypeInformation).
			WithSeverity(entities.SeverityInfo).
			WithTitle(fmt.Sprintf("Operating System: %s", osInfo.Name)).
			WithDescription(fmt.Sprintf("Detected operating system: %s (confidence: %d%%)", osInfo.Name, osInfo.Confidence)).
			WithTarget(target.Original()).
			WithModuleSource("network").
			WithEvidence(entities.Evidence{
				"os_name":          osInfo.Name,
				"os_family":        osInfo.Family,
				"os_version":       osInfo.Version,
				"confidence":       osInfo.Confidence,
				"fingerprint":      osInfo.Fingerprint,
				"detection_method": osInfo.Method,
			}).
			WithTags("network", "os-detection", osInfo.Family).
			Build()

		if err != nil {
			return fmt.Errorf("failed to create OS finding: %w", err)
		}

		execution.AddFinding(finding)
		execution.SetMetadata("detected_os", osInfo.Name)
	}

	return nil
}

// validateConnectivity validates target connectivity
func (ns *NetworkScanner) validateConnectivity(target *entities.Target) error {
	// Quick connectivity check
	timeout := time.Duration(ns.config.TCPTimeout) * time.Second

	// Try common ports
	ports := []int{80, 443, 22, 21}
	for _, port := range ports {
		address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return nil // At least one port is reachable
		}
	}

	return fmt.Errorf("target appears to be unreachable")
}

// isHighRiskPort checks if a port is considered high-risk
func (ns *NetworkScanner) isHighRiskPort(port int) bool {
	highRiskPorts := map[int]bool{
		21:   true, // FTP
		23:   true, // Telnet
		25:   true, // SMTP
		53:   true, // DNS
		135:  true, // RPC
		139:  true, // NetBIOS
		445:  true, // SMB
		1433: true, // MSSQL
		1521: true, // Oracle
		3306: true, // MySQL
		3389: true, // RDP
		5432: true, // PostgreSQL
		5900: true, // VNC
	}

	return highRiskPorts[port]
}

// isInsecureService checks if a service is considered insecure
func (ns *NetworkScanner) isInsecureService(serviceName string) bool {
	insecureServices := map[string]bool{
		"telnet": true,
		"ftp":    true,
		"rsh":    true,
		"rlogin": true,
		"tftp":   true,
		"snmp":   true,
		"pop3":   true,
		"imap":   true,
		"http":   true, // Depending on context
	}

	return insecureServices[serviceName]
}

// Sub-component interfaces

// PortScanner handles port scanning operations
type PortScanner interface {
	Configure(config *Config) error
	ScanPorts(ctx context.Context, target *entities.Target, ports []int, stopChan <-chan struct{}) ([]PortResult, error)
	Stop()
	IsHealthy() bool
}

// ServiceDetector handles service detection
type ServiceDetector interface {
	Configure(config *Config) error
	DetectService(ctx context.Context, target *entities.Target, port int) (*ServiceInfo, error)
	Stop()
	IsHealthy() bool
}

// BannerGrabber handles banner grabbing
type BannerGrabber interface {
	Configure(config *Config) error
	GrabBanner(ctx context.Context, target *entities.Target, port int) (string, error)
	Stop()
	IsHealthy() bool
}

// OSDetector handles OS detection
type OSDetector interface {
	Configure(config *Config) error
	DetectOS(ctx context.Context, target *entities.Target) (*OSInfo, error)
	Stop()
	IsHealthy() bool
}

// Data structures

// PortResult represents the result of a port scan
type PortResult struct {
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	State    PortState `json:"state"`
	Banner   string    `json:"banner,omitempty"`
}

// PortState represents the state of a port
type PortState int

const (
	PortStateOpen PortState = iota + 1
	PortStateClosed
	PortStateFiltered
)

func (ps PortState) String() string {
	switch ps {
	case PortStateOpen:
		return "open"
	case PortStateClosed:
		return "closed"
	case PortStateFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// ServiceInfo represents detected service information
type ServiceInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Product         string `json:"product,omitempty"`
	Confidence      int    `json:"confidence"`
	DetectionMethod string `json:"detection_method"`
	Fingerprint     string `json:"fingerprint,omitempty"`
}

// OSInfo represents detected OS information
type OSInfo struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	Version     string `json:"version,omitempty"`
	Confidence  int    `json:"confidence"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Method      string `json:"method"`
}

// Config represents network scanner configuration
type Config struct {
	Timeout     int   `json:"timeout"`
	MaxThreads  int   `json:"max_threads"`
	Ports       []int `json:"ports"`
	TopPorts    int   `json:"top_ports"`
	TCPTimeout  int   `json:"tcp_timeout"`
	UDPTimeout  int   `json:"udp_timeout"`
	PingCheck   bool  `json:"ping_check"`
	ServiceScan bool  `json:"service_scan"`
	BannerGrab  bool  `json:"banner_grab"`
	OSDetect    bool  `json:"os_detect"`
}

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *Config {
	return &Config{
		Timeout:    300,
		MaxThreads: 50,
		Ports: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
			1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 9300,
		},
		TopPorts:    1000,
		TCPTimeout:  5,
		UDPTimeout:  5,
		PingCheck:   true,
		ServiceScan: true,
		BannerGrab:  true,
		OSDetect:    false, // Disabled by default as it can be slow
	}
}

// Update updates the configuration with provided values
func (c *Config) Update(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok {
			if t <= 0 {
				c.Timeout = 300
			} else if t <= 3600 {
				c.Timeout = t
			} else {
				return fmt.Errorf("timeout must be between 1 and 3600 seconds, got: %v", timeout)
			}
		} else {
			return fmt.Errorf("invalid timeout type: %T, expected int", timeout)
		}
	}

	if maxThreads, ok := config["max_threads"]; ok {
		if mt, ok := maxThreads.(int); ok {
			if mt <= 0 {
				c.MaxThreads = 10 // Valeur par défaut
			} else if mt <= 200 {
				c.MaxThreads = mt
			} else {
				return fmt.Errorf("max_threads must be between 1 and 200, got: %v", maxThreads)
			}
		} else {
			return fmt.Errorf("invalid max_threads type: %T, expected int", maxThreads)
		}
	}

	if ports, ok := config["ports"]; ok {
		if portList, ok := ports.([]int); ok {
			c.Ports = portList
		} else if portInterface, ok := ports.([]interface{}); ok {
			// Handle JSON unmarshal case
			c.Ports = make([]int, len(portInterface))
			for i, p := range portInterface {
				if port, ok := p.(float64); ok {
					c.Ports[i] = int(port)
				} else {
					return fmt.Errorf("invalid port value: %v", p)
				}
			}
		} else {
			return fmt.Errorf("invalid ports value: %v", ports)
		}
	}

	if tcpTimeout, ok := config["tcp_timeout"]; ok {
		if tt, ok := tcpTimeout.(int); ok {
			if tt <= 0 {
				c.TCPTimeout = 5
			} else if tt <= 30 {
				c.TCPTimeout = tt
			} else {
				return fmt.Errorf("tcp_timeout must be between 1 and 30 seconds, got: %v", tcpTimeout)
			}
		} else {
			return fmt.Errorf("invalid tcp_timeout type: %T, expected int", tcpTimeout)
		}
	}

	if udpTimeout, ok := config["udp_timeout"]; ok {
		if ut, ok := udpTimeout.(int); ok {
			if ut <= 0 {
				c.UDPTimeout = 5
			} else if ut <= 30 {
				c.UDPTimeout = ut
			} else {
				return fmt.Errorf("udp_timeout must be between 1 and 30 seconds, got: %v", udpTimeout)
			}
		} else {
			return fmt.Errorf("invalid udp_timeout type: %T, expected int", udpTimeout)
		}
	}

	if pingCheck, ok := config["ping_check"]; ok {
		if pc, ok := pingCheck.(bool); ok {
			c.PingCheck = pc
		}
	}

	if serviceScan, ok := config["service_scan"]; ok {
		if ss, ok := serviceScan.(bool); ok {
			c.ServiceScan = ss
		}
	}

	if bannerGrab, ok := config["banner_grab"]; ok {
		if bg, ok := bannerGrab.(bool); ok {
			c.BannerGrab = bg
		}
	}

	if osDetect, ok := config["os_detect"]; ok {
		if od, ok := osDetect.(bool); ok {
			c.OSDetect = od
		}
	}

	return nil
}

func (ns *NetworkScanner) SetLogger(logger interfaces.ScannerLogger) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.logger = logger
}

func (ns *NetworkScanner) SetMetrics(metrics interfaces.ScannerMetrics) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.metrics = metrics
}

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

// Factory function for scanner creation
func init() {
	// This would be registered with the scanner factory
	// scannerFactory.Register("network", func() interfaces.Scanner {
	//     return NewNetworkScanner()
	// })
}
