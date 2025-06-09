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

// serviceDetector implements the ServiceDetector interface
type serviceDetector struct {
	config       *Config
	isHealthy    bool
	mu           sync.RWMutex
	serviceRules map[int][]ServiceRule
}

// ServiceRule represents a service detection rule
type ServiceRule struct {
	Name       string
	Pattern    *regexp.Regexp
	Confidence int
	Probe      string
}

// NewServiceDetector creates a new service detector instance
func NewServiceDetector() ServiceDetector {
	detector := &serviceDetector{
		isHealthy:    true,
		serviceRules: make(map[int][]ServiceRule),
	}

	detector.initializeServiceRules()
	return detector
}

// Configure sets up the service detector with provided configuration
func (sd *serviceDetector) Configure(config *Config) error {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	sd.config = config
	return nil
}

// DetectService detects the service running on a specific port
func (sd *serviceDetector) DetectService(ctx context.Context, target *entities.Target, port int) (*ServiceInfo, error) {
	sd.mu.RLock()
	config := sd.config
	rules := sd.serviceRules[port]
	sd.mu.RUnlock()

	if config == nil {
		return nil, errors.NewScannerError("service-detector", "detect", fmt.Errorf("service detector not configured"))
	}

	banner, err := sd.grabServiceBanner(ctx, target, port)
	if err != nil {
		return nil, nil
	}

	if banner != "" {
		for _, rule := range rules {
			if rule.Pattern.MatchString(banner) {
				return &ServiceInfo{
					Name:            rule.Name,
					Version:         sd.extractVersion(banner, rule.Pattern),
					Confidence:      rule.Confidence,
					DetectionMethod: "banner",
					Fingerprint:     banner,
				}, nil
			}
		}

		if genericRules, exists := sd.serviceRules[0]; exists {
			for _, rule := range genericRules {
				if rule.Pattern.MatchString(banner) {
					return &ServiceInfo{
						Name:            rule.Name,
						Version:         sd.extractVersion(banner, rule.Pattern),
						Confidence:      rule.Confidence,
						DetectionMethod: "banner",
						Fingerprint:     banner,
					}, nil
				}
			}
		}
	}

	if port == 22 || port == 80 || port == 443 {
		return sd.getWellKnownService(port), nil
	}

	return nil, nil
}

// getWellKnownService returns service info based on well-known ports
func (sd *serviceDetector) getWellKnownService(port int) *ServiceInfo {
	wellKnownServices := map[int]ServiceInfo{
		22:  {Name: "ssh", Confidence: 60, DetectionMethod: "port"},    // Réduit de 90 à 60
		80:  {Name: "http", Confidence: 70, DetectionMethod: "port"},   // Réduit de 90 à 70
		443: {Name: "https", Confidence: 70, DetectionMethod: "port"},  // Réduit de 90 à 70
		25:  {Name: "smtp", Confidence: 50, DetectionMethod: "port"},   // Réduit de 80 à 50
		21:  {Name: "ftp", Confidence: 30, DetectionMethod: "port"},    // Très réduit
		23:  {Name: "telnet", Confidence: 20, DetectionMethod: "port"}, // Très réduit
		110: {Name: "pop3", Confidence: 30, DetectionMethod: "port"},   // Très réduit
		143: {Name: "imap", Confidence: 30, DetectionMethod: "port"},   // Très réduit
	}

	if service, exists := wellKnownServices[port]; exists {
		return &service
	}

	return nil
}

// grabServiceBanner grabs banner from the service
func (sd *serviceDetector) grabServiceBanner(ctx context.Context, target *entities.Target, port int) (string, error) {
	timeout := time.Duration(sd.config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Send service-specific probes
	probe := sd.getServiceProbe(port)
	if probe != "" {
		conn.Write([]byte(probe))
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(buffer[:n])), nil
}

// getServiceProbe returns appropriate probe for the port
func (sd *serviceDetector) getServiceProbe(port int) string {
	probes := map[int]string{
		80:  "GET / HTTP/1.0\r\n\r\n",
		443: "GET / HTTP/1.0\r\n\r\n",
		21:  "HELP\r\n",
		25:  "EHLO test\r\n",
		110: "CAPA\r\n",
		143: "A001 CAPABILITY\r\n",
	}

	if probe, exists := probes[port]; exists {
		return probe
	}

	return "\r\n"
}

// extractVersion extracts version information from banner using regex
func (sd *serviceDetector) extractVersion(banner string, pattern *regexp.Regexp) string {
	matches := pattern.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// initializeServiceRules initializes service detection rules
func (sd *serviceDetector) initializeServiceRules() {
	// HTTP service rules
	sd.serviceRules[80] = []ServiceRule{
		{
			Name:       "apache",
			Pattern:    regexp.MustCompile(`(?i)Apache/([0-9\.]+)`),
			Confidence: 95,
		},
		{
			Name:       "nginx",
			Pattern:    regexp.MustCompile(`(?i)nginx/([0-9\.]+)`),
			Confidence: 95,
		},
		{
			Name:       "iis",
			Pattern:    regexp.MustCompile(`(?i)Microsoft-IIS/([0-9\.]+)`),
			Confidence: 95,
		},
	}

	// HTTPS service rules
	sd.serviceRules[443] = sd.serviceRules[80] // Same as HTTP

	// SSH service rules
	sd.serviceRules[22] = []ServiceRule{
		{
			Name:       "openssh",
			Pattern:    regexp.MustCompile(`(?i)OpenSSH[/_]([0-9\.]+)`),
			Confidence: 95,
		},
	}

	// FTP service rules
	sd.serviceRules[21] = []ServiceRule{
		{
			Name:       "vsftpd",
			Pattern:    regexp.MustCompile(`(?i)vsFTPd ([0-9\.]+)`),
			Confidence: 95,
		},
		{
			Name:       "proftpd",
			Pattern:    regexp.MustCompile(`(?i)ProFTPD ([0-9\.]+)`),
			Confidence: 95,
		},
	}

	// Generic rules (port 0 means apply to all ports)
	sd.serviceRules[0] = []ServiceRule{
		{
			Name:       "http",
			Pattern:    regexp.MustCompile(`(?i)HTTP/[0-9]\.[0-9]`),
			Confidence: 80,
		},
		{
			Name:       "ftp",
			Pattern:    regexp.MustCompile(`(?i)220.*FTP`),
			Confidence: 85,
		},
		{
			Name:       "smtp",
			Pattern:    regexp.MustCompile(`(?i)220.*SMTP`),
			Confidence: 85,
		},
		{
			Name:       "ssh",
			Pattern:    regexp.MustCompile(`(?i)SSH-[0-9]\.[0-9]`),
			Confidence: 90,
		},
	}
}

// Stop stops the service detector
func (sd *serviceDetector) Stop() {
	// Implementation for stopping ongoing detections
}

// IsHealthy returns the health status of the service detector
func (sd *serviceDetector) IsHealthy() bool {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.isHealthy
}
