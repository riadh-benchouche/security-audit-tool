package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
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
		logger:      NewNoOpLogger(),
		metrics:     NewNoOpMetrics(),
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
			"timeout":      "int:5:300",
			"max_threads":  "int:1:200",
			"ports":        "[]int",
			"top_ports":    "int:100:10000",
			"tcp_timeout":  "int:1:30",
			"udp_timeout":  "int:1:30",
			"ping_check":   "bool",
			"service_scan": "bool",
			"banner_grab":  "bool",
			"os_detect":    "bool",
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

	ns.logger.Info("Network scanner configured", map[string]interface{}{
		"timeout":      ns.config.Timeout,
		"max_threads":  ns.config.MaxThreads,
		"ports_count":  len(ns.config.Ports),
		"tcp_timeout":  ns.config.TCPTimeout,
		"ping_check":   ns.config.PingCheck,
		"service_scan": ns.config.ServiceScan,
		"banner_grab":  ns.config.BannerGrab,
		"os_detect":    ns.config.OSDetect,
	})

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
	if ns.config.IsPingCheckEnabled() {
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
		return nil, errors.NewBusinessLogicError("scanner already running", nil)
	}
	ns.isRunning = true
	ns.mu.Unlock()

	defer func() {
		ns.mu.Lock()
		ns.isRunning = false
		ns.mu.Unlock()
	}()

	// Création rapide de l'exécution
	executionID := fmt.Sprintf("network_%d", time.Now().UnixNano())
	module, _ := entities.NewModule("network", "1.0.0", "Network scanner", "Security Team")
	execution, err := entities.NewModuleExecution(executionID, module, target)
	if err != nil {
		return nil, err
	}

	execution.Start()

	// Métriques
	ns.metrics.IncrementScansTotal("network")
	startTime := time.Now()

	// Exécution des phases
	phases := NewScanPhases(ns.config, ns.logger, ns.portScanner, ns.detector, ns.grabber, ns.osDetector, ns.stopChan)
	err = phases.ExecuteAllPhases(ctx, target, execution)

	// Finalisation
	duration := time.Since(startTime)
	if err != nil {
		execution.Fail(err.Error())
		ns.metrics.IncrementScansFailed("network")
	} else {
		execution.Complete()
		ns.metrics.IncrementScansSuccessful("network")
	}

	ns.metrics.ObserveScanDuration("network", duration)
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
