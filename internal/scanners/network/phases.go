package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// ScanPhases handles the execution of different scan phases
type ScanPhases struct {
	config      *Config
	logger      interfaces.ScannerLogger
	portScanner PortScanner
	detector    ServiceDetector
	grabber     BannerGrabber
	osDetector  OSDetector
	stopChan    <-chan struct{}
}

// NewScanPhases creates a new scan phases executor
func NewScanPhases(config *Config, logger interfaces.ScannerLogger, portScanner PortScanner, detector ServiceDetector, grabber BannerGrabber, osDetector OSDetector, stopChan <-chan struct{}) *ScanPhases {
	return &ScanPhases{
		config:      config,
		logger:      logger,
		portScanner: portScanner,
		detector:    detector,
		grabber:     grabber,
		osDetector:  osDetector,
		stopChan:    stopChan,
	}
}

// ExecuteAllPhases executes all scan phases in sequence
func (sp *ScanPhases) ExecuteAllPhases(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error {
	// Phase 1: Connectivity Check (5%)
	execution.SetProgress(5)
	if sp.config.IsPingCheckEnabled() {
		if err := sp.ConnectivityCheck(ctx, target, execution); err != nil {
			sp.logger.Warn("Connectivity check failed", map[string]interface{}{
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
	portResults, err := sp.PortScan(ctx, target, execution)
	if err != nil {
		return fmt.Errorf("port scanning failed: %w", err)
	}
	err = execution.SetProgress(70)
	if err != nil {
		return err
	}

	// Phase 3: Service Detection (20%)
	if sp.config.IsServiceScanEnabled() && len(portResults) > 0 {
		if err := sp.ServiceDetection(ctx, target, portResults, execution); err != nil {
			sp.logger.Warn("Service detection failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Don't fail scan for service detection issues
		}
	}
	execution.SetProgress(90)

	// Phase 4: OS Detection (10%)
	if sp.config.IsOSDetectionEnabled() {
		if err := sp.OSDetection(ctx, target, execution); err != nil {
			sp.logger.Warn("OS detection failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Don't fail scan for OS detection issues
		}
	}

	execution.SetProgress(100)
	return nil
}

// ConnectivityCheck performs connectivity checking phase
func (sp *ScanPhases) ConnectivityCheck(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error {
	sp.logger.Debug("Starting connectivity check", nil)

	// Simple TCP connectivity test
	address := net.JoinHostPort(target.Host(), "80")
	conn, err := net.DialTimeout("tcp", address, time.Duration(sp.config.GetTCPTimeoutDuration())*time.Second)

	if err != nil {
		// Try HTTPS port
		address = net.JoinHostPort(target.Host(), "443")
		conn, err = net.DialTimeout("tcp", address, time.Duration(sp.config.GetTCPTimeoutDuration())*time.Second)
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

// PortScan executes the port scanning phase
func (sp *ScanPhases) PortScan(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) ([]PortResult, error) {
	sp.logger.Info("Starting port scan", map[string]interface{}{
		"ports_count": len(sp.config.GetPortList()),
		"max_threads": sp.config.MaxThreads,
	})

	// Execute port scan
	results, err := sp.portScanner.ScanPorts(ctx, target, sp.config.GetPortList(), sp.stopChan)
	if err != nil {
		return nil, fmt.Errorf("port scanning failed: %w", err)
	}

	// Create findings for open ports
	for _, result := range results {
		if result.State == PortStateOpen {
			finding, err := sp.createPortFinding(result, target)
			if err != nil {
				sp.logger.Error("Failed to create port finding", err, map[string]interface{}{
					"port": result.Port,
				})
				continue
			}

			execution.AddFinding(finding)
		}
	}

	// Set metadata
	execution.SetMetadata("ports_scanned", len(sp.config.GetPortList()))
	execution.SetMetadata("open_ports", len(results))

	sp.logger.Info("Port scan completed", map[string]interface{}{
		"open_ports":  len(results),
		"total_ports": len(sp.config.GetPortList()),
	})

	return results, nil
}

// ServiceDetection executes service detection on open ports
func (sp *ScanPhases) ServiceDetection(ctx context.Context, target *entities.Target, portResults []PortResult, execution *entities.ModuleExecution) error {
	sp.logger.Info("Starting service detection", map[string]interface{}{
		"open_ports": len(portResults),
	})

	for _, portResult := range portResults {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sp.stopChan:
			return errors.NewBusinessLogicError("scan stopped", nil)
		default:
		}

		// Detect service
		service, err := sp.detector.DetectService(ctx, target, portResult.Port)
		if err != nil {
			sp.logger.Warn("Service detection failed for port", map[string]interface{}{
				"port":  portResult.Port,
				"error": err.Error(),
			})
			continue
		}

		if service != nil {
			finding, err := sp.createServiceFinding(service, portResult.Port, target)
			if err != nil {
				sp.logger.Error("Failed to create service finding", err, map[string]interface{}{
					"service": service.Name,
					"port":    portResult.Port,
				})
				continue
			}

			execution.AddFinding(finding)
		}
	}

	return nil
}

// OSDetection executes OS detection
func (sp *ScanPhases) OSDetection(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error {
	sp.logger.Debug("Starting OS detection", nil)

	osInfo, err := sp.osDetector.DetectOS(ctx, target)
	if err != nil {
		return fmt.Errorf("OS detection failed: %w", err)
	}

	if osInfo != nil && osInfo.Name != "" {
		finding, err := sp.createOSFinding(osInfo, target)
		if err != nil {
			return fmt.Errorf("failed to create OS finding: %w", err)
		}

		execution.AddFinding(finding)
		execution.SetMetadata("detected_os", osInfo.Name)
	}

	return nil
}

// Helper methods for creating findings

// createPortFinding creates a finding for an open port
func (sp *ScanPhases) createPortFinding(result PortResult, target *entities.Target) (*entities.Finding, error) {
	severity := GetPortSeverity(result.Port)
	description := GetPortDescription(result.Port, result.Protocol)

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

	return finding, err
}

// createServiceFinding creates a finding for a detected service
func (sp *ScanPhases) createServiceFinding(service *ServiceInfo, port int, target *entities.Target) (*entities.Finding, error) {
	severity := GetServiceSeverity(service.Name)
	description := fmt.Sprintf("Service %s detected on port %d", service.Name, port)

	// Check for insecure services
	if IsInsecureService(service.Name) {
		severity = entities.SeverityHigh
		description += " (insecure protocol)"
	}

	finding, err := entities.NewFindingBuilder().
		WithID(fmt.Sprintf("network_service_%s_%d_%s", target.Host(), port, service.Name)).
		WithType(entities.FindingTypeInformation).
		WithSeverity(severity).
		WithTitle(fmt.Sprintf("Service detected: %s", service.Name)).
		WithDescription(description).
		WithTarget(fmt.Sprintf("%s:%d", target.Original(), port)).
		WithModuleSource("network").
		WithEvidence(entities.Evidence{
			"service_name":    service.Name,
			"service_version": service.Version,
			"port":            port,
			"confidence":      service.Confidence,
			"method":          service.DetectionMethod,
		}).
		WithTags("network", "service-detection", service.Name).
		Build()

	if err != nil {
		return nil, err
	}

	// Add remediation for insecure services
	if IsInsecureService(service.Name) {
		remediation := GetServiceRemediation(service.Name)
		if remediation != "" {
			finding.SetRemediation(remediation)
		} else {
			finding.SetRemediation(fmt.Sprintf("Replace %s with a secure alternative. This protocol transmits data in clear text.", service.Name))
		}
	}

	return finding, nil
}

// createOSFinding creates a finding for detected OS information
func (sp *ScanPhases) createOSFinding(osInfo *OSInfo, target *entities.Target) (*entities.Finding, error) {
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

	return finding, err
}

// Progress tracking methods

// GetPhaseProgress returns the progress percentage for a specific phase
func (sp *ScanPhases) GetPhaseProgress(phase string, currentStep, totalSteps int) int {
	phaseWeights := map[string]int{
		"connectivity": 5,
		"port_scan":    60,
		"service":      20,
		"os_detect":    10,
		"finalize":     5,
	}

	weight, exists := phaseWeights[phase]
	if !exists {
		return 0
	}

	if totalSteps == 0 {
		return weight
	}

	phaseProgress := (currentStep * weight) / totalSteps
	return phaseProgress
}

// GetTotalProgress calculates total scan progress
func (sp *ScanPhases) GetTotalProgress(completedPhases []string, currentPhase string, currentPhaseProgress int) int {
	phaseWeights := map[string]int{
		"connectivity": 5,
		"port_scan":    60,
		"service":      20,
		"os_detect":    10,
		"finalize":     5,
	}

	totalProgress := 0

	// Add completed phases
	for _, phase := range completedPhases {
		if weight, exists := phaseWeights[phase]; exists {
			totalProgress += weight
		}
	}

	// Add current phase progress
	if weight, exists := phaseWeights[currentPhase]; exists {
		totalProgress += (currentPhaseProgress * weight) / 100
	}

	return totalProgress
}

// Configuration validation for phases

// ValidatePhaseConfiguration validates configuration for scan phases
func (sp *ScanPhases) ValidatePhaseConfiguration() error {
	if sp.config == nil {
		return fmt.Errorf("configuration is nil")
	}

	if sp.portScanner == nil {
		return fmt.Errorf("port scanner is not initialized")
	}

	if sp.config.IsServiceScanEnabled() && sp.detector == nil {
		return fmt.Errorf("service detector is not initialized but service scan is enabled")
	}

	if sp.config.IsBannerGrabEnabled() && sp.grabber == nil {
		return fmt.Errorf("banner grabber is not initialized but banner grabbing is enabled")
	}

	if sp.config.IsOSDetectionEnabled() && sp.osDetector == nil {
		return fmt.Errorf("OS detector is not initialized but OS detection is enabled")
	}

	return nil
}

// Stop gracefully stops all phase operations
func (sp *ScanPhases) Stop() {
	if sp.portScanner != nil {
		sp.portScanner.Stop()
	}
	if sp.detector != nil {
		sp.detector.Stop()
	}
	if sp.grabber != nil {
		sp.grabber.Stop()
	}
	if sp.osDetector != nil {
		sp.osDetector.Stop()
	}
}
