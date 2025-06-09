package services

import (
	"context"
	"fmt"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// ScanService gère la logique métier des scans
type ScanService struct {
	moduleManager *ModuleManager
}

// NewScanService crée une nouvelle instance du service de scan
func NewScanService() *ScanService {
	return &ScanService{
		moduleManager: NewModuleManager(),
	}
}

// CreateScan crée un nouveau scan
func (s *ScanService) CreateScan(targetStr string, moduleNames []string, createdBy string) (*entities.Scan, error) {
	// Créer la target
	target, err := entities.NewTarget(targetStr)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeValidation, err, "invalid target: %s", targetStr)
	}

	// Générer un ID unique pour le scan
	scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())

	// Créer le scan
	scan, err := entities.NewScan(scanID, target, moduleNames, createdBy)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeBusinessLogic, err, "failed to create scan")
	}

	return scan, nil
}

// ExecuteScan exécute un scan complet
func (s *ScanService) ExecuteScan(ctx context.Context, scan *entities.Scan) error {
	// Démarrer le scan
	if err := scan.Start(); err != nil {
		return errors.Wrapf(errors.ErrCodeBusinessLogic, err, "failed to start scan")
	}

	// Exécuter chaque module demandé
	for _, moduleName := range scan.RequestedModules() {
		// Vérifier si on doit s'arrêter
		select {
		case <-ctx.Done():
			scan.Cancel()
			return ctx.Err()
		default:
		}

		// Obtenir le scanner pour ce module
		scanner := s.moduleManager.GetModule(moduleName)
		if scanner == nil {
			// Ajouter une execution échouée
			module, _ := entities.NewModule(moduleName, "unknown", "Unknown module", "system")
			executionID := fmt.Sprintf("%s_%s_%d", scan.ID(), moduleName, time.Now().UnixNano())
			execution, _ := entities.NewModuleExecution(executionID, module, scan.Target())
			execution.Skip(fmt.Sprintf("Scanner '%s' not found", moduleName))
			scan.AddExecution(execution)
			continue
		}

		// Valider que le scanner peut traiter cette target
		if err := scanner.Validate(scan.Target()); err != nil {
			// Ajouter une execution échouée
			module, _ := entities.NewModule(moduleName, "unknown", scanner.Info().Description, scanner.Info().Author)
			executionID := fmt.Sprintf("%s_%s_%d", scan.ID(), moduleName, time.Now().UnixNano())
			execution, _ := entities.NewModuleExecution(executionID, module, scan.Target())
			execution.Skip(fmt.Sprintf("Target validation failed: %v", err))
			scan.AddExecution(execution)
			continue
		}

		// Exécuter le scanner
		execution, err := scanner.Scan(ctx, scan.Target())
		if err != nil {
			// Le scanner a retourné une erreur, mais on a peut-être quand même des résultats
			if execution != nil {
				scan.AddExecution(execution)
			} else {
				// Créer une execution échouée
				module, _ := entities.NewModule(moduleName, "unknown", scanner.Info().Description, scanner.Info().Author)
				executionID := fmt.Sprintf("%s_%s_%d", scan.ID(), moduleName, time.Now().UnixNano())
				failedExecution, _ := entities.NewModuleExecution(executionID, module, scan.Target())
				failedExecution.Fail(err.Error())
				scan.AddExecution(failedExecution)
			}
		} else {
			scan.AddExecution(execution)
		}
	}

	// Terminer le scan
	if err := scan.Complete(); err != nil {
		return errors.Wrapf(errors.ErrCodeBusinessLogic, err, "failed to complete scan")
	}

	return nil
}

// GetScannerManager retourne le gestionnaire de modules
func (s *ScanService) GetScannerManager() *ModuleManager {
	return s.moduleManager
}

// ValidateTarget valide une target avant scan
func (s *ScanService) ValidateTarget(targetStr string) (*entities.Target, error) {
	target, err := entities.NewTarget(targetStr)
	if err != nil {
		return nil, errors.Wrapf(errors.ErrCodeValidation, err, "invalid target format")
	}

	// Résoudre les DNS si nécessaire
	if target.Type() == entities.TargetTypeDomain || target.Type() == entities.TargetTypeURL {
		if err := target.Resolve(); err != nil {
			// Ne pas échouer pour les erreurs DNS, juste logger
			return target, nil
		}
	}

	return target, nil
}

// GetAvailableModules retourne la liste des modules disponibles
func (s *ScanService) GetAvailableModules() []string {
	return s.moduleManager.GetAvailableModules()
}

// ConfigureModule configure un module spécifique
func (s *ScanService) ConfigureModule(moduleName string, config map[string]interface{}) error {
	scanner := s.moduleManager.GetModule(moduleName)
	if scanner == nil {
		return errors.NewNotFoundError("scanner", moduleName)
	}

	if err := scanner.Configure(config); err != nil {
		return errors.Wrapf(errors.ErrCodeScannerConfig, err, "failed to configure module %s", moduleName)
	}

	return nil
}
