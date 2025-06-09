package network

import (
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"
)

// IsHighRiskPort checks if a port is considered high-risk
func IsHighRiskPort(port int) bool {
	highRiskPorts := map[int]bool{
		21:   true, // FTP
		23:   true, // Telnet
		25:   true, // SMTP
		53:   true, // DNS
		135:  true, // RPC
		139:  true, // NetBIOS
		445:  true, // SMB
		1433: true, // MSSQL
		1521: true, // Oracle
		3306: true, // MySQL
		3389: true, // RDP
		5432: true, // PostgreSQL
		5900: true, // VNC
	}

	return highRiskPorts[port]
}

// IsInsecureService checks if a service is considered insecure
func IsInsecureService(serviceName string) bool {
	insecureServices := map[string]bool{
		"telnet": true,
		"ftp":    true,
		"rsh":    true,
		"rlogin": true,
		"tftp":   true,
		"snmp":   true,
		"pop3":   true,
		"imap":   true,
		"http":   true, // Depending on context
	}

	return insecureServices[serviceName]
}

// Severity Assessment Utilities

// GetPortSeverity returns the appropriate severity level for a port
func GetPortSeverity(port int) entities.Severity {
	if IsHighRiskPort(port) {
		return entities.SeverityMedium
	}
	return entities.SeverityInfo
}

// GetServiceSeverity returns the appropriate severity level for a service
func GetServiceSeverity(serviceName string) entities.Severity {
	if IsInsecureService(serviceName) {
		return entities.SeverityHigh
	}
	return entities.SeverityInfo
}

// GetPortDescription returns a description for a port finding
func GetPortDescription(port int, protocol string) string {
	description := ""

	switch port {
	case 21:
		description = "FTP (File Transfer Protocol) - Transmits data in clear text"
	case 22:
		description = "SSH (Secure Shell) - Encrypted remote access"
	case 23:
		description = "Telnet - Unencrypted remote access (insecure)"
	case 25:
		description = "SMTP (Simple Mail Transfer Protocol)"
	case 53:
		description = "DNS (Domain Name System)"
	case 80:
		description = "HTTP (Hypertext Transfer Protocol) - Unencrypted web traffic"
	case 110:
		description = "POP3 (Post Office Protocol) - Email retrieval"
	case 143:
		description = "IMAP (Internet Message Access Protocol) - Email access"
	case 443:
		description = "HTTPS (HTTP Secure) - Encrypted web traffic"
	case 993:
		description = "IMAPS (IMAP over SSL) - Secure email access"
	case 995:
		description = "POP3S (POP3 over SSL) - Secure email retrieval"
	case 1433:
		description = "Microsoft SQL Server"
	case 3306:
		description = "MySQL Database Server"
	case 3389:
		description = "RDP (Remote Desktop Protocol)"
	case 5432:
		description = "PostgreSQL Database Server"
	case 5900:
		description = "VNC (Virtual Network Computing)"
	case 8080:
		description = "HTTP Alternative Port"
	case 8443:
		description = "HTTPS Alternative Port"
	default:
		description = "Unknown service"
	}

	if IsHighRiskPort(port) {
		description += " (potentially high-risk service)"
	}

	return description
}

// GetServiceRemediation returns remediation advice for insecure services
func GetServiceRemediation(serviceName string) string {
	remediations := map[string]string{
		"telnet": "Replace Telnet with SSH for secure remote access. Telnet transmits credentials and data in clear text.",
		"ftp":    "Replace FTP with SFTP or FTPS for secure file transfer. FTP transmits credentials and data in clear text.",
		"rsh":    "Replace RSH with SSH for secure remote execution. RSH provides no encryption.",
		"rlogin": "Replace RLOGIN with SSH for secure remote login. RLOGIN provides no encryption.",
		"tftp":   "Replace TFTP with secure alternatives like SFTP. TFTP has no authentication or encryption.",
		"snmp":   "Use SNMPv3 with authentication and encryption. Earlier SNMP versions are insecure.",
		"pop3":   "Use POP3S (POP3 over SSL/TLS) for secure email retrieval.",
		"imap":   "Use IMAPS (IMAP over SSL/TLS) for secure email access.",
		"http":   "Use HTTPS instead of HTTP for encrypted web traffic.",
	}

	if remediation, exists := remediations[serviceName]; exists {
		return remediation
	}

	return ""
}

// Port Validation Utilities

// IsValidPort checks if a port number is valid
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// IsWellKnownPort checks if a port is in the well-known range (1-1023)
func IsWellKnownPort(port int) bool {
	return port >= 1 && port <= 1023
}

// IsRegisteredPort checks if a port is in the registered range (1024-49151)
func IsRegisteredPort(port int) bool {
	return port >= 1024 && port <= 49151
}

// IsDynamicPort checks if a port is in the dynamic/private range (49152-65535)
func IsDynamicPort(port int) bool {
	return port >= 49152 && port <= 65535
}

// ValidatePortList validates a list of ports
func ValidatePortList(ports []int) error {
	if len(ports) == 0 {
		return errors.NewValidationError("port list cannot be empty", nil)
	}

	for _, port := range ports {
		if !IsValidPort(port) {
			return errors.NewValidationError("invalid port number", nil)
		}
	}

	return nil
}

// IsSupportedTargetType checks if a target type is supported for network scanning
func IsSupportedTargetType(targetType entities.TargetType) bool {
	supportedTypes := map[entities.TargetType]bool{
		entities.TargetTypeIP:     true,
		entities.TargetTypeDomain: true,
		entities.TargetTypeCIDR:   true,
		entities.TargetTypeURL:    true,
	}

	return supportedTypes[targetType]
}

// noOpLogger provides a no-operation logger implementation
type noOpLogger struct{}

func (l *noOpLogger) Debug(msg string, fields map[string]interface{})                   {}
func (l *noOpLogger) Info(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Warn(msg string, fields map[string]interface{})                    {}
func (l *noOpLogger) Error(msg string, err error, fields map[string]interface{})        {}
func (l *noOpLogger) WithField(key string, value interface{}) interfaces.ScannerLogger  { return l }
func (l *noOpLogger) WithFields(fields map[string]interface{}) interfaces.ScannerLogger { return l }
func (l *noOpLogger) WithScanner(name string) interfaces.ScannerLogger                  { return l }
func (l *noOpLogger) WithTarget(target *entities.Target) interfaces.ScannerLogger       { return l }

// noOpMetrics provides a no-operation metrics implementation
type noOpMetrics struct{}

func (m *noOpMetrics) IncrementScansTotal(scanner string)                         {}
func (m *noOpMetrics) IncrementScansSuccessful(scanner string)                    {}
func (m *noOpMetrics) IncrementScansFailed(scanner string)                        {}
func (m *noOpMetrics) ObserveScanDuration(scanner string, duration time.Duration) {}
func (m *noOpMetrics) ObserveFindingsCount(scanner string, count int)             {}
func (m *noOpMetrics) GetMetrics() map[string]interface{}                         { return nil }

// NewNoOpLogger creates a new no-operation logger
func NewNoOpLogger() interfaces.ScannerLogger {
	return &noOpLogger{}
}

// NewNoOpMetrics creates a new no-operation metrics collector
func NewNoOpMetrics() interfaces.ScannerMetrics {
	return &noOpMetrics{}
}

var (
	WellKnownServices = map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "rpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		1433: "mssql",
		1521: "oracle",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-alt",
		8443: "https-alt",
		9200: "elasticsearch",
		9300: "elasticsearch-transport",
	}
)

// GetServiceNameByPort returns the common service name for a port
func GetServiceNameByPort(port int) string {
	if serviceName, exists := WellKnownServices[port]; exists {
		return serviceName
	}
	return "unknown"
}

// IsCommonService checks if a port runs a commonly known service
func IsCommonService(port int) bool {
	_, exists := WellKnownServices[port]
	return exists
}
