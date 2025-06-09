package handlers

import (
	"context"
	"fmt"

	"github.com/riadh-benchouche/security-audit-tool/internal/application/commands"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/services"
	"github.com/riadh-benchouche/security-audit-tool/internal/infrastructure/config"
	"github.com/riadh-benchouche/security-audit-tool/internal/infrastructure/logging"
	"github.com/riadh-benchouche/security-audit-tool/internal/infrastructure/metrics"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// ScanHandler handles scan-related operations
type ScanHandler struct {
	scanService *services.ScanService
	config      *config.Config
	logger      interfaces.ScannerLogger
	metrics     interfaces.ScannerMetrics
}

// NewScanHandler creates a new scan handler
func NewScanHandler() *ScanHandler {
	cfg := config.GetGlobalConfig()
	logger := logging.GetGlobalLogger()
	metrics := metrics.NewMetrics()

	scanService := services.NewScanService()

	// Configure modules with config and dependencies
	h := &ScanHandler{
		scanService: scanService,
		config:      cfg,
		logger:      logger,
		metrics:     metrics,
	}

	h.configureScanners()
	return h
}

// configureScanners configures all available modules
func (h *ScanHandler) configureScanners() {
	scannerManager := h.scanService.GetScannerManager()

	// Get all available modules
	scannerNames := scannerManager.GetAvailableModules()

	for _, name := range scannerNames {
		scanner := scannerManager.GetModule(name)
		if scanner == nil {
			continue
		}

		// Configure scanner with config
		scannerConfig := h.config.GetScannerConfig(name)
		if err := scanner.Configure(scannerConfig); err != nil {
			h.logger.Error(fmt.Sprintf("Failed to configure scanner %s", name), err, nil)
			continue
		}

		// Set logger and metrics if the module supports it
		if ns, ok := scanner.(interface {
			SetLogger(interfaces.ScannerLogger)
		}); ok {
			ns.SetLogger(h.logger)
		}
		if ns, ok := scanner.(interface {
			SetMetrics(interfaces.ScannerMetrics)
		}); ok {
			ns.SetMetrics(h.metrics)
		}

		h.logger.Info(fmt.Sprintf("Configured scanner: %s", name), nil)
	}
}

// HandleStartScan handles the start scan command
func (h *ScanHandler) HandleStartScan(ctx context.Context, cmd *commands.StartScanCommand) (*commands.StartScanResult, error) {
	h.logger.Info("Starting scan", map[string]interface{}{
		"target":  cmd.Target,
		"modules": cmd.Modules,
	})

	// Validate target
	_, err := h.scanService.ValidateTarget(cmd.Target)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeValidation, err, "invalid target: %s", cmd.Target)
	}

	// Create scan
	scan, err := h.scanService.CreateScan(cmd.Target, cmd.Modules, cmd.CreatedBy)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeBusinessLogic, err, "failed to create scan")
	}

	// Configure scan options if provided
	if cmd.Options != nil {
		for key, value := range cmd.Options {
			scan.SetOption(key, value)
		}
	}

	// Execute scan
	if err := h.scanService.ExecuteScan(ctx, scan); err != nil {
		return nil, errors.Wrapf(errors.ErrCodeScannerExecution, err, "scan execution failed")
	}

	result := &commands.StartScanResult{
		Scan:   scan,
		ScanID: scan.ID(),
		Status: scan.Status().String(),
	}

	// Add success message with summary
	if scan.IsCompleted() {
		result.Message = fmt.Sprintf("Scan completed successfully with %d findings",
			len(scan.GetAllFindings()))
	} else if scan.IsPartial() {
		result.Message = fmt.Sprintf("Scan completed with some failures. Found %d findings",
			len(scan.GetAllFindings()))
	} else {
		result.Message = fmt.Sprintf("Scan failed: %s", scan.Status().String())
	}

	h.logger.Info("Scan completed", map[string]interface{}{
		"scan_id":  scan.ID(),
		"status":   scan.Status().String(),
		"findings": len(scan.GetAllFindings()),
		"duration": scan.Duration().String(),
	})

	return result, nil
}

// GetAvailableModules returns available scanner modules
func (h *ScanHandler) GetAvailableModules() []string {
	return h.scanService.GetAvailableModules()
}

// GetModuleInfo returns information about a specific module
func (h *ScanHandler) GetModuleInfo(moduleName string) (*interfaces.ScannerInfo, error) {
	return h.scanService.GetScannerManager().GetModuleInfo(moduleName)
}

// GetAllModuleInfos returns information about all modules
func (h *ScanHandler) GetAllModuleInfos() map[string]*interfaces.ScannerInfo {
	return h.scanService.GetScannerManager().GetAllModuleInfos()
}

// ConfigureModule configures a specific module
func (h *ScanHandler) ConfigureModule(moduleName string, config map[string]interface{}) error {
	return h.scanService.ConfigureModule(moduleName, config)
}

// HealthCheck returns health status of all modules
func (h *ScanHandler) HealthCheck() map[string]*interfaces.HealthStatus {
	return h.scanService.GetScannerManager().HealthCheck()
}

// GetMetrics returns current scan metrics
func (h *ScanHandler) GetMetrics() map[string]interface{} {
	return h.metrics.GetMetrics()
}

// ValidateTarget validates a target string
func (h *ScanHandler) ValidateTarget(targetStr string) (*entities.Target, error) {
	return h.scanService.ValidateTarget(targetStr)
}
