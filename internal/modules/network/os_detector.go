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
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
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
	Confidence int
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
		return nil, errors.NewScannerError("os-detector", "detect", fmt.Errorf("OS detector not configured"))
	}

	// Try different OS detection methods
	methods := []struct {
		name string
		fn   func(context.Context, *entities.Target) (*OSInfo, error)
	}{
		{"banner-analysis", od.detectOSFromBanners},
		{"tcp-fingerprint", od.detectOSFromTCPFingerprint},
		{"port-pattern", od.detectOSFromPortPattern},
	}

	var bestMatch *OSInfo
	maxConfidence := 0

	for _, method := range methods {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		osInfo, err := method.fn(ctx, target)
		if err != nil {
			continue // Try next method
		}

		if osInfo != nil && osInfo.Confidence > maxConfidence {
			bestMatch = osInfo
			maxConfidence = osInfo.Confidence
		}
	}

	return bestMatch, nil
}

// detectOSFromBanners detects OS from service banners
func (od *osDetector) detectOSFromBanners(ctx context.Context, target *entities.Target) (*OSInfo, error) {
	// Common ports that often reveal OS information
	ports := []int{22, 80, 443, 21, 25, 110, 143}

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

		// Check banner against OS signatures
		for _, signature := range od.osSignatures {
			if signature.Method == "banner" && signature.Pattern.MatchString(banner) {
				return &OSInfo{
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
	// Scan common ports to determine OS based on typical port patterns
	commonPorts := []int{22, 80, 135, 139, 443, 445, 993, 995, 3389, 5900}

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

	// Analyze port patterns
	portPattern := od.generatePortPattern(openPorts)

	for _, signature := range od.osSignatures {
		if signature.Method == "port-pattern" && signature.Pattern.MatchString(portPattern) {
			return &OSInfo{
				Name:        signature.Name,
				Family:      signature.Family,
				Confidence:  signature.Confidence,
				Fingerprint: portPattern,
				Method:      "port-pattern",
			}, nil
		}
	}

	return nil, nil
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
			Confidence: 85,
			Method:     "banner",
		},
		{
			Name:       "CentOS Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*CentOS`),
			Confidence: 85,
			Method:     "banner",
		},
		{
			Name:       "Red Hat Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*Red Hat`),
			Confidence: 85,
			Method:     "banner",
		},
		{
			Name:       "Debian Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*Debian`),
			Confidence: 85,
			Method:     "banner",
		},
		{
			Name:       "FreeBSD",
			Family:     "BSD",
			Pattern:    regexp.MustCompile(`(?i)SSH-2\.0-OpenSSH.*FreeBSD`),
			Confidence: 85,
			Method:     "banner",
		},

		// HTTP Banner Signatures
		{
			Name:       "Microsoft IIS",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft-IIS`),
			Confidence: 90,
			Method:     "banner",
		},
		{
			Name:       "Apache on Unix",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Apache.*\(Unix\)`),
			Confidence: 80,
			Method:     "banner",
		},
		{
			Name:       "Apache on Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)Apache.*\(Ubuntu|Debian|CentOS|Red Hat\)`),
			Confidence: 80,
			Method:     "banner",
		},
		{
			Name:       "nginx on Linux",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)nginx.*\(Ubuntu|Debian|CentOS\)`),
			Confidence: 75,
			Method:     "banner",
		},

		// FTP Banner Signatures
		{
			Name:       "Microsoft FTP Service",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft FTP Service`),
			Confidence: 85,
			Method:     "banner",
		},
		{
			Name:       "vsftpd",
			Family:     "Linux",
			Pattern:    regexp.MustCompile(`(?i)vsFTPd`),
			Confidence: 80,
			Method:     "banner",
		},
		{
			Name:       "ProFTPD",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)ProFTPD`),
			Confidence: 75,
			Method:     "banner",
		},

		// SMTP Banner Signatures
		{
			Name:       "Microsoft Exchange",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`(?i)Microsoft ESMTP MAIL Service`),
			Confidence: 90,
			Method:     "banner",
		},
		{
			Name:       "Postfix",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Postfix`),
			Confidence: 80,
			Method:     "banner",
		},
		{
			Name:       "Sendmail",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`(?i)Sendmail`),
			Confidence: 80,
			Method:     "banner",
		},

		// Port Pattern Signatures
		{
			Name:       "Windows Server",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`windows-pattern`),
			Confidence: 60,
			Method:     "port-pattern",
		},
		{
			Name:       "Linux/Unix Server",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`unix-pattern`),
			Confidence: 60,
			Method:     "port-pattern",
		},

		// TCP Fingerprint Signatures (simplified)
		{
			Name:       "Windows TCP Stack",
			Family:     "Windows",
			Pattern:    regexp.MustCompile(`tcp-connect.*:445`),
			Confidence: 50,
			Method:     "tcp-fingerprint",
		},
		{
			Name:       "Unix TCP Stack",
			Family:     "Unix",
			Pattern:    regexp.MustCompile(`tcp-connect.*:22`),
			Confidence: 50,
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
