package scanner

import (
	"fmt"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/pkg/core"
	"github.com/riadh-benchouche/security-audit-tool/pkg/models"
)

// Scanner interface que tous les scanners doivent implémenter
type Scanner interface {
	Name() string
	Description() string
	Scan(target string) (*models.ModuleResult, error)
	Configure(config map[string]interface{}) error
}

// Manager gère l'exécution des scanners
type Manager struct {
	scanners []Scanner
	logger   *core.StructuredLogger
	mutex    sync.RWMutex
}

// NewManager crée une nouvelle instance du gestionnaire de scanners
func NewManager() *Manager {
	return &Manager{
		scanners: make([]Scanner, 0),
		logger:   core.NewStructuredLogger("scanner-manager"),
	}
}

// AddScanner ajoute un scanner au gestionnaire
func (m *Manager) AddScanner(scanner Scanner) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.scanners = append(m.scanners, scanner)
	m.logger.Infof("Scanner ajouté: %s", scanner.Name())
}

// RemoveScanner supprime un scanner par nom
func (m *Manager) RemoveScanner(name string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, scanner := range m.scanners {
		if scanner.Name() == name {
			m.scanners = append(m.scanners[:i], m.scanners[i+1:]...)
			m.logger.Infof("Scanner supprimé: %s", name)
			return true
		}
	}
	return false
}

// GetScanners retourne la liste des scanners disponibles
func (m *Manager) GetScanners() []Scanner {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Retourner une copie pour éviter les modifications concurrentes
	result := make([]Scanner, len(m.scanners))
	copy(result, m.scanners)
	return result
}

// Scan exécute tous les scanners sur la cible spécifiée
func (m *Manager) Scan(target string) (*models.ScanResult, error) {
	m.logger.Infof("Démarrage du scan pour la cible: %s", target)

	startTime := time.Now()

	result := &models.ScanResult{
		Target:    target,
		StartTime: startTime,
		Results:   make([]models.ModuleResult, 0),
	}

	// Valider la cible
	if target == "" {
		return nil, fmt.Errorf("cible vide")
	}

	m.mutex.RLock()
	scanners := make([]Scanner, len(m.scanners))
	copy(scanners, m.scanners)
	m.mutex.RUnlock()

	if len(scanners) == 0 {
		m.logger.Warn("Aucun scanner configuré")
		return nil, fmt.Errorf("aucun scanner configuré")
	}

	// Exécuter les scanners de manière séquentielle pour l'instant
	for _, scanner := range scanners {
		m.logger.Infof("Exécution du scanner: %s", scanner.Name())

		moduleResult, err := m.executeScannerSafely(scanner, target)
		if err != nil {
			m.logger.Errorf("Erreur dans le scanner %s: %v", scanner.Name(), err)
			// Continuer avec les autres scanners même en cas d'erreur
			moduleResult = &models.ModuleResult{
				Module:    scanner.Name(),
				Status:    models.StatusFailed,
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Findings:  make([]models.Finding, 0),
				Errors:    []string{err.Error()},
			}
		}

		result.Results = append(result.Results, *moduleResult)
	}

	// Finaliser le résultat
	result.EndTime = time.Now()
	result.CalculateDuration()
	result.GenerateSummary()

	m.logger.Infof("Scan terminé en %s avec %d findings",
		result.Duration, result.Summary.TotalFindings)

	return result, nil
}

// ScanConcurrent exécute tous les scanners en parallèle
func (m *Manager) ScanConcurrent(target string) (*models.ScanResult, error) {
	m.logger.Infof("Démarrage du scan concurrent pour: %s", target)

	startTime := time.Now()

	result := &models.ScanResult{
		Target:    target,
		StartTime: startTime,
		Results:   make([]models.ModuleResult, 0),
	}

	m.mutex.RLock()
	scanners := make([]Scanner, len(m.scanners))
	copy(scanners, m.scanners)
	m.mutex.RUnlock()

	if len(scanners) == 0 {
		return nil, fmt.Errorf("aucun scanner configuré")
	}

	// Canal pour collecter les résultats
	resultsChan := make(chan models.ModuleResult, len(scanners))
	var wg sync.WaitGroup

	// Lancer tous les scanners en parallèle
	for _, scanner := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			moduleResult, err := m.executeScannerSafely(s, target)
			if err != nil {
				m.logger.Errorf("Erreur dans le scanner %s: %v", s.Name(), err)
				moduleResult = &models.ModuleResult{
					Module:    s.Name(),
					Status:    models.StatusFailed,
					StartTime: time.Now(),
					EndTime:   time.Now(),
					Findings:  make([]models.Finding, 0),
					Errors:    []string{err.Error()},
				}
			}

			resultsChan <- *moduleResult
		}(scanner)
	}

	// Attendre que tous les scanners se terminent
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collecter les résultats
	for moduleResult := range resultsChan {
		result.Results = append(result.Results, moduleResult)
	}

	// Finaliser le résultat
	result.EndTime = time.Now()
	result.CalculateDuration()
	result.GenerateSummary()

	m.logger.Infof("Scan concurrent terminé en %s avec %d findings",
		result.Duration, result.Summary.TotalFindings)

	return result, nil
}

// executeScannerSafely exécute un scanner de manière sécurisée avec récupération de panic
func (m *Manager) executeScannerSafely(scanner Scanner, target string) (result *models.ModuleResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			m.logger.Errorf("Panic dans le scanner %s: %v", scanner.Name(), r)
			err = fmt.Errorf("panic dans le scanner: %v", r)
			result = &models.ModuleResult{
				Module:    scanner.Name(),
				Status:    models.StatusFailed,
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Findings:  make([]models.Finding, 0),
				Errors:    []string{fmt.Sprintf("panic: %v", r)},
			}
		}
	}()

	return scanner.Scan(target)
}

// GetScannerByName retourne un scanner par son nom
func (m *Manager) GetScannerByName(name string) Scanner {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, scanner := range m.scanners {
		if scanner.Name() == name {
			return scanner
		}
	}
	return nil
}

// ConfigureScanner configure un scanner spécifique
func (m *Manager) ConfigureScanner(name string, config map[string]interface{}) error {
	scanner := m.GetScannerByName(name)
	if scanner == nil {
		return fmt.Errorf("scanner non trouvé: %s", name)
	}

	return scanner.Configure(config)
}

// ClearScanners supprime tous les scanners
func (m *Manager) ClearScanners() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.scanners = make([]Scanner, 0)
	m.logger.Info("Tous les scanners ont été supprimés")
}

// CountScanners retourne le nombre de scanners configurés
func (m *Manager) CountScanners() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return len(m.scanners)
}
