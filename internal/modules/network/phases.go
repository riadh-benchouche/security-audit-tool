package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
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
	sp.logger.Info("Starting comprehensive network scan", map[string]interface{}{
		"target": target.Original(),
		"phases_enabled": map[string]bool{
			"connectivity_check": sp.config.IsPingCheckEnabled(),
			"service_scan":       sp.config.IsServiceScanEnabled(),
			"banner_grab":        sp.config.IsBannerGrabEnabled(),
			"os_detect":          sp.config.IsOSDetectEnabled(),
		},
	})

	// Phase 1: Connectivity Check (5%)
	execution.SetProgress(5)
	if sp.config.IsPingCheckEnabled() {
		if err := sp.ConnectivityCheck(ctx, target, execution); err != nil {
			sp.logger.Warn("Connectivity check failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Phase 2: Port Scanning (60%)
	execution.SetProgress(10)
	portResults, err := sp.PortScan(ctx, target, execution)
	if err != nil {
		return fmt.Errorf("port scanning failed: %w", err)
	}
	execution.SetProgress(70)

	if len(portResults) == 0 {
		sp.logger.Info("No open ports found, skipping service-dependent phases", nil)
		execution.SetProgress(100)
		return nil
	}

	// Phase 3: Service Detection (15%)
	if sp.config.IsServiceScanEnabled() {
		sp.logger.Info("Starting service detection phase", map[string]interface{}{
			"open_ports": len(portResults),
		})
		if err := sp.ServiceDetection(ctx, target, portResults, execution); err != nil {
			sp.logger.Warn("Service detection failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
	execution.SetProgress(85)

	// Phase 4: Banner Grabbing (10%)
	if sp.config.IsBannerGrabEnabled() {
		sp.logger.Info("Starting banner grabbing phase", map[string]interface{}{
			"open_ports": len(portResults),
		})
		if err := sp.BannerGrabbing(ctx, target, portResults, execution); err != nil {
			sp.logger.Warn("Banner grabbing failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}
	execution.SetProgress(95)

	// Phase 5: OS Detection (5%) - UN SEUL BLOC !
	if sp.config.IsOSDetectEnabled() {
		sp.logger.Info("Starting OS detection phase", map[string]interface{}{
			"target": target.Original(),
			"host":   target.Host(),
		})
		if err := sp.OSDetection(ctx, target, execution); err != nil {
			sp.logger.Warn("OS detection failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	} else {
		sp.logger.Info("OS detection phase skipped", map[string]interface{}{
			"reason": "disabled in configuration",
		})
	}

	execution.SetProgress(100)
	return nil
}

// ConnectivityCheck performs connectivity checking phase
func (sp *ScanPhases) ConnectivityCheck(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error {
	sp.logger.Debug("Starting connectivity check", nil)

	// Try multiple common ports for better connectivity detection
	testPorts := []int{80, 443, 22, 21, 25, 53}
	timeout := time.Duration(sp.config.GetTCPTimeoutDuration()) * time.Second

	var lastErr error
	for _, port := range testPorts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sp.stopChan:
			return errors.NewBusinessLogicError("scan stopped", nil)
		default:
		}

		address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err != nil {
			lastErr = err
			continue
		}

		conn.Close()

		// Create connectivity finding
		finding, err := entities.NewFindingBuilder().
			WithID(fmt.Sprintf("network_connectivity_%s", target.Host())).
			WithType(entities.FindingTypeInformation).
			WithSeverity(entities.SeverityInfo).
			WithTitle("Host is reachable").
			WithDescription(fmt.Sprintf("Target %s is reachable via network (port %d responded)", target.Host(), port)).
			WithTarget(target.Original()).
			WithModuleSource("network").
			WithEvidence(entities.Evidence{
				"method":        "tcp",
				"target_host":   target.Host(),
				"reachable":     true,
				"test_port":     port,
				"response_time": timeout.String(),
			}).
			WithTags("connectivity", "network", "reachable").
			Build()

		if err != nil {
			return fmt.Errorf("failed to create connectivity finding: %w", err)
		}

		execution.AddFinding(finding)
		return nil // Success on first responding port
	}

	// If we get here, no ports responded
	sp.logger.Warn("Target appears unreachable on all test ports", map[string]interface{}{
		"tested_ports": testPorts,
		"last_error":   lastErr.Error(),
	})

	return lastErr
}

// PortScan executes the port scanning phase
func (sp *ScanPhases) PortScan(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) ([]PortResult, error) {
	sp.logger.Info("Starting port scan", map[string]interface{}{
		"ports_count": len(sp.config.GetPortList()),
		"max_threads": sp.config.MaxThreads,
	})

	// Execute port scan
	allResults, err := sp.portScanner.ScanPorts(ctx, target, sp.config.GetPortList(), sp.stopChan)
	if err != nil {
		return nil, fmt.Errorf("port scanning failed: %w", err)
	}

	// Filter and process only open ports
	var openPortResults []PortResult
	for _, result := range allResults {
		if result.State == PortStateOpen {
			openPortResults = append(openPortResults, result)

			// Create finding for each open port
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

	// Set scan metadata
	execution.SetMetadata("ports_scanned", len(sp.config.GetPortList()))
	execution.SetMetadata("open_ports", len(openPortResults))
	execution.SetMetadata("total_ports_tested", len(allResults))

	sp.logger.Info("Port scan completed", map[string]interface{}{
		"open_ports":       len(openPortResults),
		"total_tested":     len(allResults),
		"total_configured": len(sp.config.GetPortList()),
	})

	return openPortResults, nil
}

// ServiceDetection executes service detection on open ports
func (sp *ScanPhases) ServiceDetection(ctx context.Context, target *entities.Target, portResults []PortResult, execution *entities.ModuleExecution) error {
	sp.logger.Info("Starting service detection", map[string]interface{}{
		"open_ports": len(portResults),
	})

	servicesFound := 0
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
			sp.logger.Debug("Service detection failed for port", map[string]interface{}{
				"port":  portResult.Port,
				"error": err.Error(),
			})
			continue
		}

		if service != nil && service.Name != "" {
			servicesFound++
			finding, err := sp.createServiceFinding(service, portResult.Port, target)
			if err != nil {
				sp.logger.Error("Failed to create service finding", err, map[string]interface{}{
					"service": service.Name,
					"port":    portResult.Port,
				})
				continue
			}

			execution.AddFinding(finding)

			sp.logger.Debug("Service detected", map[string]interface{}{
				"port":       portResult.Port,
				"service":    service.Name,
				"version":    service.Version,
				"confidence": service.Confidence,
			})
		}
	}

	execution.SetMetadata("services_detected", servicesFound)

	sp.logger.Info("Service detection completed", map[string]interface{}{
		"services_found": servicesFound,
		"ports_scanned":  len(portResults),
	})

	return nil
}

// BannerGrabbing executes banner grabbing on open ports
func (sp *ScanPhases) BannerGrabbing(ctx context.Context, target *entities.Target, portResults []PortResult, execution *entities.ModuleExecution) error {
	sp.logger.Info("Starting banner grabbing", map[string]interface{}{
		"open_ports": len(portResults),
	})

	bannersGrabbed := 0
	for _, portResult := range portResults {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sp.stopChan:
			return errors.NewBusinessLogicError("scan stopped", nil)
		default:
		}

		// Grab banner
		banner, err := sp.grabber.GrabBanner(ctx, target, portResult.Port)
		if err != nil {
			sp.logger.Debug("Banner grab failed for port", map[string]interface{}{
				"port":  portResult.Port,
				"error": err.Error(),
			})
			continue
		}

		if banner != "" {
			bannersGrabbed++
			finding, err := sp.createBannerFinding(banner, portResult.Port, target)
			if err != nil {
				sp.logger.Error("Failed to create banner finding", err, map[string]interface{}{
					"port": portResult.Port,
				})
				continue
			}

			execution.AddFinding(finding)

			sp.logger.Debug("Banner grabbed", map[string]interface{}{
				"port":           portResult.Port,
				"banner_preview": banner[:min(50, len(banner))],
				"banner_length":  len(banner),
			})
		}
	}

	execution.SetMetadata("banners_grabbed", bannersGrabbed)

	sp.logger.Info("Banner grabbing completed", map[string]interface{}{
		"banners_grabbed": bannersGrabbed,
		"ports_attempted": len(portResults),
	})

	return nil
}

// OSDetection executes OS detection
func (sp *ScanPhases) OSDetection(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error {
	if sp.osDetector == nil {
		return nil
	}

	osInfo, err := sp.osDetector.DetectOS(ctx, target)
	if err != nil {
		return fmt.Errorf("OS detection failed: %w", err)
	}

	if osInfo != nil && osInfo.Name != "" && osInfo.Confidence >= 0.5 {
		finding, err := sp.createOSFinding(osInfo, target)
		if err != nil {
			return fmt.Errorf("failed to create OS finding: %w", err)
		}

		execution.AddFinding(finding)
		execution.SetMetadata("detected_os", osInfo.Name)
		execution.SetMetadata("os_confidence", osInfo.Confidence)

		sp.logger.Info("OS detected", map[string]interface{}{
			"os":         osInfo.Name,
			"family":     osInfo.Family,
			"confidence": osInfo.Confidence,
			"method":     osInfo.Method,
		})
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
			"port":          result.Port,
			"protocol":      result.Protocol,
			"state":         result.State.String(),
			"banner":        result.Banner,
			"response_time": result.ResponseTime.String(),
		}).
		WithTags("network", "port-scan", result.Protocol).
		Build()

	return finding, err
}

// createServiceFinding creates a finding for a detected service
func (sp *ScanPhases) createServiceFinding(service *ServiceInfo, port int, target *entities.Target) (*entities.Finding, error) {
	severity := GetServiceSeverity(service.Name)
	description := fmt.Sprintf("Service %s detected on port %d", service.Name, port)

	// Enhanced description with version if available
	if service.Version != "" {
		description += fmt.Sprintf(" (version: %s)", service.Version)
	}
	description += fmt.Sprintf(" with %d%% confidence", service.Confidence)

	// Check for insecure services
	if IsInsecureService(service.Name) {
		severity = entities.SeverityHigh
		description += " - WARNING: This is an insecure protocol that transmits data in clear text"
	}

	finding, err := entities.NewFindingBuilder().
		WithID(fmt.Sprintf("network_service_%s_%d_%s", target.Host(), port, service.Name)).
		WithType(entities.FindingTypeInformation).
		WithSeverity(severity).
		WithTitle(fmt.Sprintf("Service detected: %s", service.GetDisplayName())).
		WithDescription(description).
		WithTarget(fmt.Sprintf("%s:%d", target.Original(), port)).
		WithModuleSource("network").
		WithEvidence(entities.Evidence{
			"service_name":     service.Name,
			"service_version":  service.Version,
			"service_product":  service.Product,
			"port":             port,
			"confidence":       service.Confidence,
			"detection_method": service.DetectionMethod,
			"fingerprint":      service.Fingerprint,
			"is_insecure":      IsInsecureService(service.Name),
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
			finding.SetRemediation(fmt.Sprintf("Replace %s with a secure alternative. This protocol transmits data in clear text and is vulnerable to eavesdropping and man-in-the-middle attacks.", service.Name))
		}
	}

	return finding, nil
}

// createBannerFinding creates a finding for grabbed banner
func (sp *ScanPhases) createBannerFinding(banner string, port int, target *entities.Target) (*entities.Finding, error) {
	// Truncate banner for display
	displayBanner := banner
	if len(banner) > 100 {
		displayBanner = banner[:100] + "..."
	}

	finding, err := entities.NewFindingBuilder().
		WithID(fmt.Sprintf("network_banner_%s_%d", target.Host(), port)).
		WithType(entities.FindingTypeInformation).
		WithSeverity(entities.SeverityInfo).
		WithTitle(fmt.Sprintf("Service banner grabbed from port %d", port)).
		WithDescription(fmt.Sprintf("Service banner: %s", displayBanner)).
		WithTarget(fmt.Sprintf("%s:%d", target.Original(), port)).
		WithModuleSource("network").
		WithEvidence(entities.Evidence{
			"port":           port,
			"banner":         banner,
			"banner_length":  len(banner),
			"banner_preview": displayBanner,
		}).
		WithTags("network", "banner-grab", fmt.Sprintf("port-%d", port)).
		Build()

	return finding, err
}

// createOSFinding creates a finding for detected OS information
func (sp *ScanPhases) createOSFinding(osInfo *OSInfo, target *entities.Target) (*entities.Finding, error) {
	confidence := int(osInfo.Confidence * 100)
	description := fmt.Sprintf("Detected operating system: %s", osInfo.GetDisplayName())

	if osInfo.Family != "" {
		description += fmt.Sprintf(" (Family: %s)", osInfo.Family)
	}
	description += fmt.Sprintf(" with %d%% confidence using %s method", confidence, osInfo.Method)

	finding, err := entities.NewFindingBuilder().
		WithID(fmt.Sprintf("network_os_%s", target.Host())).
		WithType(entities.FindingTypeInformation).
		WithSeverity(entities.SeverityInfo).
		WithTitle(fmt.Sprintf("Operating System: %s", osInfo.GetDisplayName())).
		WithDescription(description).
		WithTarget(target.Original()).
		WithModuleSource("network").
		WithEvidence(entities.Evidence{
			"os_name":            osInfo.Name,
			"os_family":          osInfo.Family,
			"os_version":         osInfo.Version,
			"confidence":         osInfo.Confidence,
			"confidence_percent": confidence,
			"fingerprint":        osInfo.Fingerprint,
			"detection_method":   osInfo.Method,
		}).
		WithTags("network", "os-detection", osInfo.GetFamilyName()).
		Build()

	return finding, err
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Progress tracking methods

// GetPhaseProgress returns the progress percentage for a specific phase
func (sp *ScanPhases) GetPhaseProgress(phase string, currentStep, totalSteps int) int {
	phaseWeights := map[string]int{
		"connectivity": 5,
		"port_scan":    60,
		"service":      15,
		"banner_grab":  10,
		"os_detect":    5,
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
		"service":      15,
		"banner_grab":  10,
		"os_detect":    5,
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

	if sp.config.IsOSDetectEnabled() && sp.osDetector == nil {
		return fmt.Errorf("OS detector is not initialized but OS detection is enabled")
	}

	return nil
}

// GetEnabledPhases returns a list of enabled scan phases
func (sp *ScanPhases) GetEnabledPhases() []string {
	var phases []string

	if sp.config.IsPingCheckEnabled() {
		phases = append(phases, "connectivity")
	}

	phases = append(phases, "port_scan") // Always enabled

	if sp.config.IsServiceScanEnabled() {
		phases = append(phases, "service")
	}

	if sp.config.IsBannerGrabEnabled() {
		phases = append(phases, "banner_grab")
	}

	if sp.config.IsOSDetectEnabled() {
		phases = append(phases, "os_detect")
	}

	return phases
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
