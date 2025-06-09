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
func (sm *ModuleManager) registerDefaultModules() {
	// Scanner réseau
	networkScanner := network.NewNetworkScanner()
	sm.RegisterModule("network", networkScanner)

	httpScanner := http.NewHTTPScanner()
	sm.RegisterModule("http", httpScanner)
}

// RegisterModule enregistre un nouveau module
func (sm *ModuleManager) RegisterModule(name string, module interfaces.Scanner) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if name == "" {
		return errors.NewValidationError("module name cannot be empty", nil)
	}

	if module == nil {
		return errors.NewValidationError("module cannot be nil", nil)
	}

	sm.modules[name] = module
	return nil
}

// GetModule retourne un module par son nom
func (sm *ModuleManager) GetModule(name string) interfaces.Scanner {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return sm.modules[name]
}

// GetAvailableModules retourne la liste des noms de modules disponibles
func (sm *ModuleManager) GetAvailableModules() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	names := make([]string, 0, len(sm.modules))
	for name := range sm.modules {
		names = append(names, name)
	}

	return names
}

// GetModuleInfo retourne les informations d'un module
func (sm *ModuleManager) GetModuleInfo(name string) (*interfaces.ScannerInfo, error) {
	module := sm.GetModule(name)
	if module == nil {
		return nil, errors.NewNotFoundError("module", name)
	}

	return module.Info(), nil
}

// GetAllModuleInfos retourne les informations de tous les modules
func (sm *ModuleManager) GetAllModuleInfos() map[string]*interfaces.ScannerInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	infos := make(map[string]*interfaces.ScannerInfo)
	for name, module := range sm.modules {
		infos[name] = module.Info()
	}

	return infos
}

// UnregisterModule supprime un module
func (sm *ModuleManager) UnregisterModule(name string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.modules[name]; !exists {
		return errors.NewNotFoundError("module", name)
	}

	delete(sm.modules, name)
	return nil
}

// HealthCheck vérifie la santé de tous les modules
func (sm *ModuleManager) HealthCheck() map[string]*interfaces.HealthStatus {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	health := make(map[string]*interfaces.HealthStatus)
	for name, module := range sm.modules {
		health[name] = module.Health()
	}

	return health
}

// ConfigureModule configure un module spécifique
func (sm *ModuleManager) ConfigureModule(name string, config map[string]interface{}) error {
	module := sm.GetModule(name)
	if module == nil {
		return errors.NewNotFoundError("module", name)
	}

	if err := module.Configure(config); err != nil {
		return errors.Wrapf(errors.ErrCodeScannerConfig, err, "failed to configure module %s", name)
	}

	return nil
}

// Count retourne le nombre de modules enregistrés
func (sm *ModuleManager) Count() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return len(sm.modules)
}
