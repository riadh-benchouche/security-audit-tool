package entities

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// TargetType represent the type of target for security scanning
type TargetType int

const (
	TargetTypeIP TargetType = iota + 1
	TargetTypeDomain
	TargetTypeURL
	TargetTypeCIDR
)

func (tt TargetType) String() string {
	switch tt {
	case TargetTypeIP:
		return "ip"
	case TargetTypeDomain:
		return "domain"
	case TargetTypeURL:
		return "url"
	case TargetTypeCIDR:
		return "cidr"
	default:
		return "unknown"
	}
}

// Target represents a target for security scanning
type Target struct {
	original    string
	targetType  TargetType
	host        string
	port        int
	scheme      string
	path        string
	resolvedIPs []net.IP
	isValid     bool
	errors      []string
}

// NewTarget creates a new Target instance from a string input
func NewTarget(input string) (*Target, error) {
	if input == "" {
		return nil, fmt.Errorf("target input cannot be empty")
	}

	target := &Target{
		original:    strings.TrimSpace(input),
		resolvedIPs: make([]net.IP, 0),
		errors:      make([]string, 0),
	}

	if err := target.parse(); err != nil {
		return nil, fmt.Errorf("failed to parse target: %w", err)
	}

	return target, nil
}

// parse analyzes the original input and determines its type
func (t *Target) parse() error {
	input := t.original

	// Try to parse as CIDR notation first
	if t.tryParseCIDR(input) {
		return nil
	}

	// Try to parse as URL
	if t.tryParseURL(input) {
		return nil
	}

	// Try to parse as IP address
	if t.tryParseIP(input) {
		return nil
	}

	// Try to parse as domain name
	if t.tryParseDomain(input) {
		return nil
	}

	return fmt.Errorf("unable to determine target type for: %s", input)
}

// tryParseCIDR tries to parse the input as CIDR notation
func (t *Target) tryParseCIDR(input string) bool {
	if strings.Contains(input, "/") {
		if _, _, err := net.ParseCIDR(input); err == nil {
			t.targetType = TargetTypeCIDR
			t.host = input
			t.isValid = true
			return true
		}
	}
	return false
}

// tryParseURL tries to parse the input as a URL
func (t *Target) tryParseURL(input string) bool {
	// Add http:// if no scheme is present
	testInput := input
	if !strings.Contains(input, "://") {
		testInput = "http://" + input
	}

	if parsed, err := url.Parse(testInput); err == nil && parsed.Host != "" {
		t.targetType = TargetTypeURL
		t.scheme = parsed.Scheme
		t.host = parsed.Hostname()
		t.path = parsed.Path

		// Extract port if present
		if portStr := parsed.Port(); portStr != "" {
			if port := parseInt(portStr); port > 0 && port <= 65535 {
				t.port = port
			}
		} else {
			// Default ports based on scheme
			switch parsed.Scheme {
			case "http":
				t.port = 80
			case "https":
				t.port = 443
			case "ftp":
				t.port = 21
			}
		}

		t.isValid = true
		return true
	}
	return false
}

// tryParseIP tries to parse the input as an IP address
func (t *Target) tryParseIP(input string) bool {
	if ip := net.ParseIP(input); ip != nil {
		t.targetType = TargetTypeIP
		t.host = input
		t.resolvedIPs = []net.IP{ip}
		t.isValid = true
		return true
	}
	return false
}

// tryParseDomain tries to parse the input as a domain name
func (t *Target) tryParseDomain(input string) bool {
	// Clean the input by removing any trailing slashes
	host := input
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		host = parts[0]
		if len(parts) == 2 {
			if port := parseInt(parts[1]); port > 0 && port <= 65535 {
				t.port = port
			}
		}
	}

	// Check if the host is a valid domain
	if t.isValidDomain(host) {
		t.targetType = TargetTypeDomain
		t.host = host
		t.isValid = true
		return true
	}
	return false
}

// isValidDomain verifies if the given string is a valid domain name
func (t *Target) isValidDomain(domain string) bool {
	// Regex-based validation for domain names
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

	if len(domain) > 253 || len(domain) == 0 {
		return false
	}

	return domainRegex.MatchString(domain)
}

// parseInt Converts a string to an integer, ensuring it's a valid port number
func parseInt(s string) int {
	var result int
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		result = result*10 + int(r-'0')
		if result > 65535 { // Port numbers must be between 0 and 65535 (max port number)
			return -1
		}
	}
	return result
}

func (t *Target) Original() string      { return t.original }
func (t *Target) Type() TargetType      { return t.targetType }
func (t *Target) Host() string          { return t.host }
func (t *Target) Port() int             { return t.port }
func (t *Target) Scheme() string        { return t.scheme }
func (t *Target) Path() string          { return t.path }
func (t *Target) ResolvedIPs() []net.IP { return t.resolvedIPs }
func (t *Target) IsValid() bool         { return t.isValid }
func (t *Target) Errors() []string      { return t.errors }

// Resolve resolves the target to its IP addresses
func (t *Target) Resolve() error {
	if t.targetType != TargetTypeDomain && t.targetType != TargetTypeURL {
		return nil
	}

	ips, err := net.LookupIP(t.host)
	if err != nil {
		t.errors = append(t.errors, fmt.Sprintf("DNS resolution failed: %v", err))
		return fmt.Errorf("failed to resolve %s: %w", t.host, err)
	}

	// Filter and categorize IPs into IPv4 and IPv6
	ipv4s := make([]net.IP, 0)
	ipv6s := make([]net.IP, 0)

	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}

	t.resolvedIPs = append(ipv4s, ipv6s...)

	if len(t.resolvedIPs) == 0 {
		return fmt.Errorf("no IP addresses found for %s", t.host)
	}

	return nil
}

// PrimaryIP returns the first resolved IP address
func (t *Target) PrimaryIP() net.IP {
	if len(t.resolvedIPs) > 0 {
		return t.resolvedIPs[0]
	}
	return nil
}

// HasIPv4 verifies if the target has at least one IPv4 address
func (t *Target) HasIPv4() bool {
	for _, ip := range t.resolvedIPs {
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

// HasIPv6 verifies if the target has at least one IPv6 address
func (t *Target) HasIPv6() bool {
	for _, ip := range t.resolvedIPs {
		if ip.To4() == nil {
			return true
		}
	}
	return false
}

// IsHTTPS verifies if the target uses HTTPS
func (t *Target) IsHTTPS() bool {
	return t.scheme == "https" || t.port == 443
}

// IsHTTP verifies if the target uses HTTP
func (t *Target) IsHTTP() bool {
	return t.scheme == "http" || t.port == 80
}

// ToURL converts the target to a URL string
func (t *Target) ToURL() string {
	switch t.targetType {
	case TargetTypeURL:
		if t.scheme != "" {
			result := fmt.Sprintf("%s://%s", t.scheme, t.host)
			if t.port > 0 && !t.isDefaultPort() {
				result += fmt.Sprintf(":%d", t.port)
			}
			if t.path != "" {
				result += t.path
			}
			return result
		}
		return t.original
	case TargetTypeDomain:
		if t.port == 443 {
			return fmt.Sprintf("https://%s", t.host)
		}
		if t.port == 80 || t.port == 0 {
			return fmt.Sprintf("http://%s", t.host)
		}
		return fmt.Sprintf("http://%s:%d", t.host, t.port)
	case TargetTypeIP:
		if t.port > 0 {
			return fmt.Sprintf("http://%s:%d", t.host, t.port)
		}
		return fmt.Sprintf("http://%s", t.host)
	default:
		return t.original
	}
}

// isDefaultPort verifies if the target's port is the default for its scheme
func (t *Target) isDefaultPort() bool {
	switch t.scheme {
	case "http":
		return t.port == 80
	case "https":
		return t.port == 443
	case "ftp":
		return t.port == 21
	default:
		return false
	}
}

// String implements the Stringer interface for Target
func (t *Target) String() string {
	return fmt.Sprintf("Target{type=%s, host=%s, port=%d, resolved=%d IPs}",
		t.targetType.String(), t.host, t.port, len(t.resolvedIPs))
}

// ToMap converts the target to a map representation
func (t *Target) ToMap() map[string]interface{} {
	ips := make([]string, len(t.resolvedIPs))
	for i, ip := range t.resolvedIPs {
		ips[i] = ip.String()
	}

	return map[string]interface{}{
		"original":     t.original,
		"type":         t.targetType.String(),
		"host":         t.host,
		"port":         t.port,
		"scheme":       t.scheme,
		"path":         t.path,
		"resolved_ips": ips,
		"is_valid":     t.isValid,
		"errors":       t.errors,
	}
}

// Equals compares two targets for equality
func (t *Target) Equals(other *Target) bool {
	if other == nil {
		return false
	}
	return t.original == other.original
}

// Clone creates a deep copy of the Target instance
func (t *Target) Clone() *Target {
	clone := &Target{
		original:    t.original,
		targetType:  t.targetType,
		host:        t.host,
		port:        t.port,
		scheme:      t.scheme,
		path:        t.path,
		resolvedIPs: make([]net.IP, len(t.resolvedIPs)),
		isValid:     t.isValid,
		errors:      make([]string, len(t.errors)),
	}

	copy(clone.resolvedIPs, t.resolvedIPs)
	copy(clone.errors, t.errors)

	return clone
}
