package services

import (
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/http"
	"sync"

	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/network"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// ModuleManager gère l'enregistrement et l'accès aux modules
type ModuleManager struct {
	modules map[string]interfaces.Scanner
	mutex   sync.RWMutex
}

// NewModuleManager crée une nouvelle instance du gestionnaire
func NewModuleManager() *ModuleManager {
	manager := &ModuleManager{
		modules: make(map[string]interfaces.Scanner),
	}

	// Enregistrer les modules par défaut
	manager.registerDefaultModules()

	return manager
}

// registerDefaultModules enregistre les modules disponibles
func (mm *ModuleManager) registerDefaultModules() {
	// Scanner réseau
	networkScanner := network.NewNetworkScanner()
	mm.RegisterModule("network", networkScanner)

	httpScanner := http.NewHTTPScanner()
	mm.RegisterModule("http", httpScanner)
}

// RegisterModule enregistre un nouveau module
func (mm *ModuleManager) RegisterModule(name string, module interfaces.Scanner) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if name == "" {
		return errors.NewValidationError("module name cannot be empty", nil)
	}

	if module == nil {
		return errors.NewValidationError("module cannot be nil", nil)
	}

	mm.modules[name] = module
	return nil
}

// GetModule retourne un module par son nom
func (mm *ModuleManager) GetModule(name string) interfaces.Scanner {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	return mm.modules[name]
}

// GetAvailableModules retourne la liste des noms de modules disponibles
func (mm *ModuleManager) GetAvailableModules() []string {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	names := make([]string, 0, len(mm.modules))
	for name := range mm.modules {
		names = append(names, name)
	}

	return names
}

// GetModuleInfo retourne les informations d'un module
func (mm *ModuleManager) GetModuleInfo(name string) (*interfaces.ScannerInfo, error) {
	module := mm.GetModule(name)
	if module == nil {
		return nil, errors.NewNotFoundError("module", name)
	}

	return module.Info(), nil
}

// GetAllModuleInfos retourne les informations de tous les modules
func (mm *ModuleManager) GetAllModuleInfos() map[string]*interfaces.ScannerInfo {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	infos := make(map[string]*interfaces.ScannerInfo)
	for name, module := range mm.modules {
		infos[name] = module.Info()
	}

	return infos
}

// UnregisterModule supprime un module
func (mm *ModuleManager) UnregisterModule(name string) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if _, exists := mm.modules[name]; !exists {
		return errors.NewNotFoundError("module", name)
	}

	delete(mm.modules, name)
	return nil
}

// HealthCheck vérifie la santé de tous les modules
func (mm *ModuleManager) HealthCheck() map[string]*interfaces.HealthStatus {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	health := make(map[string]*interfaces.HealthStatus)
	for name, module := range mm.modules {
		health[name] = module.Health()
	}

	return health
}

// ConfigureModule configure un module spécifique
func (mm *ModuleManager) ConfigureModule(name string, config map[string]interface{}) error {
	module := mm.GetModule(name)
	if module == nil {
		return errors.NewNotFoundError("module", name)
	}

	if err := module.Configure(config); err != nil {
		return errors.Wrapf(errors.ErrCodeScannerConfig, err, "failed to configure module %s", name)
	}

	return nil
}

// Count retourne le nombre de modules enregistrés
func (mm *ModuleManager) Count() int {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	return len(mm.modules)
}
