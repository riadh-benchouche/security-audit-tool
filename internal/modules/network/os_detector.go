package network

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// osDetector implements the OSDetector interface
type osDetector struct {
	config       *Config
	isHealthy    bool
	mu           sync.RWMutex
	osSignatures []OSSignature
}

// OSSignature represents an OS detection signature
type OSSignature struct {
	Name       string
	Family     string
	Pattern    *regexp.Regexp
	Confidence float64 // Changé de int à float64 pour correspondre à OSInfo
	Method     string
}

// NewOSDetector creates a new OS detector instance
func NewOSDetector() OSDetector {
	detector := &osDetector{
		isHealthy: true,
	}

	detector.initializeSignatures()
	return detector
}

// Configure sets up the OS detector with provided configuration
func (od *osDetector) Configure(config *Config) error {
	od.mu.Lock()
	defer od.mu.Unlock()

	od.config = config
	return nil
}

// DetectOS detects the operating system of the target
func (od *osDetector) DetectOS(ctx context.Context, target *entities.Target) (*OSInfo, error) {
	od.mu.RLock()
	config := od.config
	od.mu.RUnlock()

	if config == nil {
		return nil, fmt.Errorf("not configured")
	}

	// Méthodes ordonnées par efficacité
	methods := []func(context.Context, *entities.Target) (*OSInfo, error){
		od.detectOSFromBanners,
		od.detectOSFromPortPattern,
		od.detectOSFromTCPFingerprint,
	}

	for _, method := range methods {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if osInfo, err := method(ctx, target); err == nil && osInfo != nil && osInfo.Confidence > 0.5 {
			return osInfo, nil
		}
	}

	return nil, nil
}

// detectOSFromBanners detects OS from service banners
func (od *osDetector) detectOSFromBanners(ctx context.Context, target *entities.Target) (*OSInfo, error) {
	// Ports prioritaires pour la détection OS
	ports := []int{22, 80, 443, 21, 25}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		banner, err := od.grabBanner(ctx, target, port)
		if err != nil || banner == "" {
			continue
		}

		// Analyse HTTP spécialisée
		if port == 80 || port == 443 {
			if osInfo := od.analyzeHTTPHeaders(banner); osInfo != nil {
				return osInfo, nil
			}
		}

		// Signatures générales
		for _, signature := range od.osSignatures {
			if signature.Method == "banner" && signature.Pattern.MatchString(banner) {
				return &OSInfo{
					OS:          signature.Name,
					Name:        signature.Name,
					Family:      signature.Family,
					Confidence:  signature.Confidence,
					Fingerprint: banner,
					Method:      "banner-analysis",
				}, nil
			}
		}
	}

	return nil, nil
}

func (od *osDetector) analyzeHTTPHeaders(banner string) *OSInfo {
	banner = strings.ToLower(banner)

	// Détection basée sur les headers HTTP
	patterns := map[string]OSInfo{
		// Server headers
		"server: nginx": {
			Name:       "Linux",
			Family:     "Linux",
			Confidence: 0.6, // Moderate confidence
			Method:     "http-server-analysis",
		},
		"server: apache": {
			Name:       "Linux",
			Family:     "Unix",
			Confidence: 0.5,
			Method:     "http-server-analysis",
		},
		"server: microsoft-iis": {
			Name:       "Windows Server",
			Family:     "Windows",
			Confidence: 0.9,
			Method:     "http-server-analysis",
		},
		"server: apache.*ubuntu": {
			Name:       "Ubuntu Linux",
			Family:     "Linux",
			Confidence: 0.8,
			Method:     "http-server-analysis",
		},
		"server: apache.*centos": {
			Name:       "CentOS Linux",
			Family:     "Linux",
			Confidence: 0.8,
			Method:     "http-server-analysis",
		},
		// PHP headers (your target has PHP/8.2.28)
		"x-powered-by: php": {
			Name:       "Linux",
			Family:     "Unix",
			Confidence: 0.4, // PHP runs mostly on Linux
			Method:     "http-technology-analysis",
		},
		// Autres indices
		"server:.*windows": {
			Name:       "Windows",
			Family:     "Windows",
			Confidence: 0.7,
			Method:     "http-server-analysis",
		},
	}

	for pattern, osInfo := range patterns {
		matched, _ := regexp.MatchString(pattern, banner)
		if matched {
			result := osInfo
			result.OS = osInfo.Name
			result.Fingerprint = banner
			return &result
		}
	}

	return nil
}

// detectOSFromTCPFingerprint detects OS using TCP fingerprinting
func (od *osDetector) detectOSFromTCPFingerprint(ctx context.Context, target *entities.Target) (*OSInfo, error) {
	// This is a simplified TCP fingerprinting approach
	// In practice, you'd want to implement more sophisticated techniques

	// Test different TCP options and behaviors
	fingerprint, err := od.performTCPFingerprinting(ctx, target)
	if err != nil {
		return nil, err
	}

	// Analyze fingerprint against known patterns
	for _, signature := range od.osSignatures {
		if signature.Method == "tcp-fingerprint" && signature.Pattern.MatchString(fingerprint) {
			return &OSInfo{
				OS:          signature.Name,
				Name:        signature.Name,
				Family:      signature.Family,
				Confidence:  signature.Confidence,
				Fingerprint: fingerprint,
				Method:      "tcp-fingerprint",
			}, nil
		}
	}

	return nil, nil
}

// detectOSFromPortPattern detects OS based on open port patterns
func (od *osDetector) detectOSFromPortPattern(ctx context.Context, target *entities.Target) (*OSInfo, error) {
	// Scan plus de ports pour une meilleure détection
	commonPorts := []int{22, 80, 135, 139, 443, 445, 993, 995, 3389, 5900, 8080, 8443, 21, 25, 110, 143}

	var openPorts []int
	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if od.isPortOpen(ctx, target, port) {
			openPorts = append(openPorts, port)
		}
	}

	if len(openPorts) == 0 {
		return nil, nil
	}

	// Analyse plus fine des patterns
	return od.analyzePortPattern(openPorts), nil
}

func (od *osDetector) analyzePortPattern(openPorts []int) *OSInfo {
	portsSet := make(map[int]bool)
	for _, port := range openPorts {
		portsSet[port] = true
	}

	// Patterns spécifiques

	// Linux web server pattern (80, 443, 22 souvent)
	if portsSet[80] && portsSet[443] && portsSet[22] {
		return &OSInfo{
			Name:        "Linux Server",
			OS:          "Linux Server",
			Family:      "Linux",
			Confidence:  0.6,
			Method:      "port-pattern-analysis",
			Fingerprint: fmt.Sprintf("ports: %v", openPorts),
		}
	}

	// Web server with common alternate port
	if portsSet[80] && portsSet[8080] && len(openPorts) <= 5 {
		return &OSInfo{
			Name:        "Linux Web Server",
			OS:          "Linux Web Server",
			Family:      "Linux",
			Confidence:  0.5,
			Method:      "port-pattern-analysis",
			Fingerprint: fmt.Sprintf("web-server-ports: %v", openPorts),
		}
	}

	// Windows patterns
	if portsSet[135] && portsSet[445] {
		return &OSInfo{
			Name:        "Windows Server",
			OS:          "Windows Server",
			Family:      "Windows",
			Confidence:  0.8,
			Method:      "port-pattern-analysis",
			Fingerprint: fmt.Sprintf("windows-ports: %v", openPorts),
		}
	}

	return nil
}

// performTCPFingerprinting performs basic TCP fingerprinting
func (od *osDetector) performTCPFingerprinting(ctx context.Context, target *entities.Target) (string, error) {
	// This is a simplified implementation
	// Real TCP fingerprinting would involve analyzing TCP window sizes,
	// options, fragmentation behavior, etc.

	timeout := time.Duration(od.config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), "80")

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		// Try another port
		address = net.JoinHostPort(target.Host(), "443")
		conn, err = net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return "", err
		}
	}

	if conn != nil {
		defer conn.Close()
	}

	// For now, just return a basic fingerprint
	// In a real implementation, you'd analyze TCP characteristics
	fingerprint := fmt.Sprintf("tcp-connect:%s", address)

	return fingerprint, nil
}

// grabBanner grabs banner from a specific port
func (od *osDetector) grabBanner(ctx context.Context, target *entities.Target, port int) (string, error) {
	timeout := time.Duration(od.config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send appropriate probe based on port
	probe := od.getProbeForPort(port)
	if probe != "" {
		conn.Write([]byte(probe))
	}

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buffer[:n])), nil
}

// getProbeForPort returns appropriate probe for the port
func (od *osDetector) getProbeForPort(port int) string {
	probes := map[int]string{
		22:  "", // SSH sends banner immediately
		80:  "GET / HTTP/1.0\r\n\r\n",
		443: "GET / HTTP/1.0\r\n\r\n",
		21:  "", // FTP sends banner immediately
		25:  "", // SMTP sends banner immediately
		110: "", // POP3 sends banner immediately
		143: "", // IMAP sends banner immediately
	}

	if probe, exists := probes[port]; exists {
		return probe
	}

	return "\r\n"
}

// isPortOpen checks if a port is open
func (od *osDetector) isPortOpen(ctx context.Context, target *entities.Target, port int) bool {
	timeout := time.Duration(od.config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// generatePortPattern generates a pattern string from open ports
func (od *osDetector) generatePortPattern(openPorts []int) string {
	var pattern strings.Builder

	// Check for Windows-specific ports
	windowsPorts := map[int]bool{135: true, 139: true, 445: true, 3389: true}
	windowsCount := 0
	for _, port := range openPorts {
		if windowsPorts[port] {
			windowsCount++
		}
	}

	// Check for Unix/Linux-specific ports
	unixPorts := map[int]bool{22: true, 993: true, 995: true}
	unixCount := 0
	for _, port := range openPorts {
		if unixPorts[port] {
			unixCount++
		}
	}

	if windowsCount >= 2 {
		pattern.WriteString("windows-pattern")
	} else if unixCount >= 1 {
		pattern.WriteString("unix-pattern")
	} else {
		pattern.WriteString("unknown-pattern")
	}

	return pattern.String()
}

// initializeSignatures initializes OS detection signatures
func (od *osDetector) initializeSignatures() {
	od.osSignatures = []OSSignature{
		// SSH Banner Signatures
		{
			Name:       "Ubuntu Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*Ubuntu`),
			Confidence: 0.85, // Convertis en float64 (85%)
			Method:     "banner",
		},
		{
			Name:       "CentOS Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*CentOS`),
			Confidence: 0.85,
			Method:     "banner",
		},
		{
			Name:       "Red Hat Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*Red Hat`),
			Confidence: 0.85,
			Method:     "banner",
		},
		{
			Name:       "Debian Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*Debian`),
			Confidence: 0.85,
			Method:     "banner",
		},
		{
			Name:       "FreeBSD",
			Family:     "BSD",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*FreeBSD`),
			Confidence: 0.85,
			Method:     "banner",
		},

		// HTTP Banner Signatures
		{
			Name:       "Microsoft IIS",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft-IIS`),
			Confidence: 0.90,
			Method:     "banner",
		},
		{
			Name:       "Apache on Unix",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Apache.*\(Unix\)`),
			Confidence: 0.80,
			Method:     "banner",
		},
		{
			Name:       "Apache on Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)Apache.*\(Ubuntu|Debian|CentOS|Red Hat\)`),
			Confidence: 0.80,
			Method:     "banner",
		},
		{
			Name:       "nginx on Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)nginx.*\(Ubuntu|Debian|CentOS\)`),
			Confidence: 0.75,
			Method:     "banner",
		},

		// FTP Banner Signatures
		{
			Name:       "Microsoft FTP Service",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft FTP Service`),
			Confidence: 0.85,
			Method:     "banner",
		},
		{
			Name:       "vsftpd",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)vsFTPd`),
			Confidence: 0.80,
			Method:     "banner",
		},
		{
			Name:       "ProFTPD",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)ProFTPD`),
			Confidence: 0.75,
			Method:     "banner",
		},

		// SMTP Banner Signatures
		{
			Name:       "Microsoft Exchange",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service`),
			Confidence: 0.90,
			Method:     "banner",
		},
		{
			Name:       "Postfix",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Postfix`),
			Confidence: 0.80,
			Method:     "banner",
		},
		{
			Name:       "Sendmail",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Sendmail`),
			Confidence: 0.80,
			Method:     "banner",
		},

		// Port Pattern Signatures
		{
			Name:       "Windows Server",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`windows-pattern`),
			Confidence: 0.60,
			Method:     "port-pattern",
		},
		{
			Name:       "Linux/Unix Server",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`unix-pattern`),
			Confidence: 0.60,
			Method:     "port-pattern",
		},

		// TCP Fingerprint Signatures (simplified)
		{
			Name:       "Windows TCP Stack",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`tcp-connect.*:445`),
			Confidence: 0.50,
			Method:     "tcp-fingerprint",
		},
		{
			Name:       "Unix TCP Stack",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`tcp-connect.*:22`),
			Confidence: 0.50,
			Method:     "tcp-fingerprint",
		},
	}
}

// Stop stops the OS detector
func (od *osDetector) Stop() {
	// Implementation for stopping ongoing OS detection
	od.mu.Lock()
	defer od.mu.Unlock()
	// Set a stop flag if needed
}

// IsHealthy returns the health status of the OS detector
func (od *osDetector) IsHealthy() bool {
	od.mu.RLock()
	defer od.mu.RUnlock()
	return od.isHealthy
}
