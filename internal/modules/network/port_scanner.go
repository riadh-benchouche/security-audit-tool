package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// portScanner implements the PortScanner interface
type portScanner struct {
	config    *Config
	isHealthy bool
	mu        sync.RWMutex
}

// NewPortScanner creates a new port scanner instance
func NewPortScanner() PortScanner {
	return &portScanner{
		isHealthy: true,
	}
}

// Configure sets up the port scanner with provided configuration
func (ps *portScanner) Configure(config *Config) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.config = config
	return nil
}

// ScanPorts executes port scanning against the target
func (ps *portScanner) ScanPorts(ctx context.Context, target *entities.Target, ports []int, stopChan <-chan struct{}) ([]PortResult, error) {
	ps.mu.RLock()
	config := ps.config
	ps.mu.RUnlock()

	if config == nil {
		return nil, errors.NewScannerError("port-scanner", "scan", fmt.Errorf("port scanner not configured"))
	}

	var results []PortResult
	var mu sync.Mutex

	// Use semaphore to limit concurrent connections
	semaphore := make(chan struct{}, config.MaxThreads)
	var wg sync.WaitGroup

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-stopChan:
			return results, errors.NewBusinessLogicError("scan stopped", nil)
		default:
		}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := ps.scanPort(ctx, target, p)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results, nil
}

// scanPort scans a single port
func (ps *portScanner) scanPort(ctx context.Context, target *entities.Target, port int) PortResult {
	result := PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    PortStateClosed,
	}

	timeout := time.Duration(ps.config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	// ✅ Utiliser DialTimeout avec contexte et timeout approprié
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		// ✅ Analyser le type d'erreur pour distinguer fermé vs filtré
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = PortStateFiltered
		} else {
			result.State = PortStateClosed
		}
		return result
	}

	// ✅ Le port est vraiment ouvert
	defer conn.Close()
	result.State = PortStateOpen

	// ✅ Essayer de récupérer une bannière seulement si le port est ouvert
	if ps.config.BannerGrab {
		banner := ps.grabBanner(conn, timeout)
		result.Banner = banner
	}

	return result
}

// grabBanner attempts to grab banner from the connection
func (ps *portScanner) grabBanner(conn net.Conn, timeout time.Duration) string {
	// Définir un timeout plus court pour la bannière
	bannerTimeout := timeout
	if bannerTimeout > 3*time.Second {
		bannerTimeout = 3 * time.Second
	}

	err := conn.SetReadDeadline(time.Now().Add(bannerTimeout))
	if err != nil {
		return err.Error()
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	// Nettoyer la bannière
	banner = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, banner)

	return banner
}

// Stop stops the port scanner
func (ps *portScanner) Stop() {
	// Implementation for stopping ongoing scans
	// This would typically involve setting a stop flag
}

// IsHealthy returns the health status of the port scanner
func (ps *portScanner) IsHealthy() bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.isHealthy
}
