package services

import (
	"sync"

	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/network"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// ScannerManager gère l'enregistrement et l'accès aux scanners
type ScannerManager struct {
	scanners map[string]interfaces.Scanner
	mutex    sync.RWMutex
}

// NewScannerManager crée une nouvelle instance du gestionnaire
func NewScannerManager() *ScannerManager {
	manager := &ScannerManager{
		scanners: make(map[string]interfaces.Scanner),
	}

	// Enregistrer les scanners par défaut
	manager.registerDefaultScanners()

	return manager
}

// registerDefaultScanners enregistre les scanners disponibles
func (sm *ScannerManager) registerDefaultScanners() {
	// Scanner réseau
	networkScanner := network.NewNetworkScanner()
	sm.RegisterScanner("network", networkScanner)

	// TODO: Ajouter d'autres scanners quand ils seront implémentés
	// httpScanner := http.NewHTTPScanner()
	// sm.RegisterScanner("http", httpScanner)
}

// RegisterScanner enregistre un nouveau scanner
func (sm *ScannerManager) RegisterScanner(name string, scanner interfaces.Scanner) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if name == "" {
		return errors.NewValidationError("scanner name cannot be empty", nil)
	}

	if scanner == nil {
		return errors.NewValidationError("scanner cannot be nil", nil)
	}

	sm.scanners[name] = scanner
	return nil
}

// GetScanner retourne un scanner par son nom
func (sm *ScannerManager) GetScanner(name string) interfaces.Scanner {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return sm.scanners[name]
}

// GetAvailableScanners retourne la liste des noms de scanners disponibles
func (sm *ScannerManager) GetAvailableScanners() []string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	names := make([]string, 0, len(sm.scanners))
	for name := range sm.scanners {
		names = append(names, name)
	}

	return names
}

// GetScannerInfo retourne les informations d'un scanner
func (sm *ScannerManager) GetScannerInfo(name string) (*interfaces.ScannerInfo, error) {
	scanner := sm.GetScanner(name)
	if scanner == nil {
		return nil, errors.NewNotFoundError("scanner", name)
	}

	return scanner.Info(), nil
}

// GetAllScannerInfos retourne les informations de tous les scanners
func (sm *ScannerManager) GetAllScannerInfos() map[string]*interfaces.ScannerInfo {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	infos := make(map[string]*interfaces.ScannerInfo)
	for name, scanner := range sm.scanners {
		infos[name] = scanner.Info()
	}

	return infos
}

// UnregisterScanner supprime un scanner
func (sm *ScannerManager) UnregisterScanner(name string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if _, exists := sm.scanners[name]; !exists {
		return errors.NewNotFoundError("scanner", name)
	}

	delete(sm.scanners, name)
	return nil
}

// HealthCheck vérifie la santé de tous les scanners
func (sm *ScannerManager) HealthCheck() map[string]*interfaces.HealthStatus {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	health := make(map[string]*interfaces.HealthStatus)
	for name, scanner := range sm.scanners {
		health[name] = scanner.Health()
	}

	return health
}

// ConfigureScanner configure un scanner spécifique
func (sm *ScannerManager) ConfigureScanner(name string, config map[string]interface{}) error {
	scanner := sm.GetScanner(name)
	if scanner == nil {
		return errors.NewNotFoundError("scanner", name)
	}

	if err := scanner.Configure(config); err != nil {
		return errors.Wrapf(errors.ErrCodeScannerConfig, err, "failed to configure scanner %s", name)
	}

	return nil
}

// Count retourne le nombre de scanners enregistrés
func (sm *ScannerManager) Count() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return len(sm.scanners)
}
