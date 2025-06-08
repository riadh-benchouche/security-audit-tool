package metrics

import (
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
)

// Metrics implements the ScannerMetrics interface
type Metrics struct {
	scansTotal      map[string]int
	scansSuccessful map[string]int
	scansFailed     map[string]int
	scanDurations   map[string][]time.Duration
	findingsCounts  map[string][]int
	mutex           sync.RWMutex
}

// NewMetrics creates a new metrics instance
func NewMetrics() interfaces.ScannerMetrics {
	return &Metrics{
		scansTotal:      make(map[string]int),
		scansSuccessful: make(map[string]int),
		scansFailed:     make(map[string]int),
		scanDurations:   make(map[string][]time.Duration),
		findingsCounts:  make(map[string][]int),
	}
}

// IncrementScansTotal increments the total scans counter
func (m *Metrics) IncrementScansTotal(scanner string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.scansTotal[scanner]++
}

// IncrementScansSuccessful increments successful scans counter
func (m *Metrics) IncrementScansSuccessful(scanner string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.scansSuccessful[scanner]++
}

// IncrementScansFailed increments failed scans counter
func (m *Metrics) IncrementScansFailed(scanner string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.scansFailed[scanner]++
}

// ObserveScanDuration records scan duration
func (m *Metrics) ObserveScanDuration(scanner string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.scanDurations[scanner] = append(m.scanDurations[scanner], duration)
}

// ObserveFindingsCount records number of findings
func (m *Metrics) ObserveFindingsCount(scanner string, count int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.findingsCounts[scanner] = append(m.findingsCounts[scanner], count)
}

// GetMetrics returns current metrics
func (m *Metrics) GetMetrics() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	metrics := make(map[string]interface{})

	for scanner := range m.scansTotal {
		scannerMetrics := map[string]interface{}{
			"total_scans":      m.scansTotal[scanner],
			"successful_scans": m.scansSuccessful[scanner],
			"failed_scans":     m.scansFailed[scanner],
		}

		// Calculate average duration
		if durations, exists := m.scanDurations[scanner]; exists && len(durations) > 0 {
			var total time.Duration
			for _, d := range durations {
				total += d
			}
			scannerMetrics["avg_duration"] = total / time.Duration(len(durations))
		}

		// Calculate average findings
		if counts, exists := m.findingsCounts[scanner]; exists && len(counts) > 0 {
			var total int
			for _, c := range counts {
				total += c
			}
			scannerMetrics["avg_findings"] = float64(total) / float64(len(counts))
		}

		metrics[scanner] = scannerMetrics
	}

	return metrics
}
