package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/internal/scanners/interfaces"
	"strings"
	"time"
)

type SSLAnalyzer struct {
	logger interfaces.ScannerLogger
}

// isWeakCipherSuite checks if cipher suite is considered weak
func (sa *SSLAnalyzer) isWeakCipherSuite(cipherSuite string) bool {
	weakCiphers := []string{
		"RC4", "DES", "3DES", "MD5", "SHA1",
	}

	cipherUpper := strings.ToUpper(cipherSuite)
	for _, weak := range weakCiphers {
		if strings.Contains(cipherUpper, weak) {
			return true
		}
	}
	return false
}

// calculateSSLScore calculates SSL configuration score
func (sa *SSLAnalyzer) calculateSSLScore(ssl *SSLResult) int {
	score := 100

	// Penalties for vulnerabilities
	score -= len(ssl.Vulnerabilities) * 20

	// Penalty for expired certificate
	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		score -= 50
	}

	// Penalty for weak key size
	if ssl.Certificate != nil && ssl.Certificate.KeySize < 2048 {
		score -= 30
	}

	// Penalty for old TLS version
	if ssl.Version == "TLS 1.0" || ssl.Version == "TLS 1.1" {
		score -= 40
	}

	if score < 0 {
		score = 0
	}

	return score
}

// calculateSSLGrade calculates SSL grade from score
func (sa *SSLAnalyzer) calculateSSLGrade(score int) string {
	return GetSecurityGrade(score)
}

// getKeySize extracts key size from certificate
func (sa *SSLAnalyzer) getKeySize(cert *x509.Certificate) int {
	// Simplified key size detection
	// In production, this should properly analyze the public key
	return 2048 // Default value
}

// getTLSVersionString converts a TLS version to string
func (sa *SSLAnalyzer) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// NewSSLAnalyzer creates a new SSL analyzer
func NewSSLAnalyzer(logger interfaces.ScannerLogger) *SSLAnalyzer {
	return &SSLAnalyzer{
		logger: logger,
	}
}

// AnalyzeSSL analyzes SSL/TLS configuration
func (sa *SSLAnalyzer) AnalyzeSSL(tlsState *tls.ConnectionState) *SSLResult {
	if tlsState == nil {
		return nil
	}

	sslResult := &SSLResult{
		Enabled:         true,
		Version:         sa.getTLSVersionString(tlsState.Version),
		Protocols:       []string{sa.getTLSVersionString(tlsState.Version)},
		Vulnerabilities: make([]string, 0),
	}

	// Analyze certificate
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		sslResult.Certificate = sa.analyzeCertificate(cert)
	}

	// Check vulnerabilities
	sslResult.Vulnerabilities = sa.checkVulnerabilities(tlsState)

	// Calculate grade and score
	sslResult.Score = sa.calculateSSLScore(sslResult)
	sslResult.Grade = sa.calculateSSLGrade(sslResult.Score)

	return sslResult
}

// analyzeCertificate analyzes X.509 certificate
func (sa *SSLAnalyzer) analyzeCertificate(cert *x509.Certificate) *Certificate {
	return &Certificate{
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		IsExpired:      time.Now().After(cert.NotAfter),
		IsCA:           cert.IsCA,
		KeySize:        sa.getKeySize(cert),
		SignatureAlg:   cert.SignatureAlgorithm.String(),
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
	}
}

// checkVulnerabilities checks for SSL/TLS vulnerabilities
func (sa *SSLAnalyzer) checkVulnerabilities(tlsState *tls.ConnectionState) []string {
	vulnerabilities := make([]string, 0)

	// Check TLS version
	if tlsState.Version < tls.VersionTLS12 {
		vulnerabilities = append(vulnerabilities, "Outdated TLS version (< 1.2)")
	}

	// Check cipher suite
	cipherSuite := tls.CipherSuiteName(tlsState.CipherSuite)
	if sa.isWeakCipherSuite(cipherSuite) {
		vulnerabilities = append(vulnerabilities, "Weak cipher suite: "+cipherSuite)
	}

	return vulnerabilities
}

// CreateSSLFindings creates findings from SSL analysis
func (sa *SSLAnalyzer) CreateSSLFindings(execution *entities.ModuleExecution, ssl *SSLResult, targetURL string) {
	// Expired certificate
	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		finding, err := entities.NewFindingBuilder().
			WithID("ssl-expired-certificate").
			WithType(entities.FindingTypeVulnerability).
			WithSeverity(entities.SeverityHigh).
			WithTitle("Expired SSL Certificate").
			WithDescription(fmt.Sprintf("The SSL certificate expired on %s", ssl.Certificate.NotAfter.Format("2006-01-02"))).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"not_after": ssl.Certificate.NotAfter,
				"subject":   ssl.Certificate.Subject,
			}).
			WithTags("ssl", "certificate", "expired").
			Build()

		if err == nil {
			finding.SetRemediation("Renew the SSL certificate before it expires")
			execution.AddFinding(finding)
		}
	}

	// Certificate expiring soon
	if ssl.Certificate != nil && ssl.Certificate.IsExpiringSoon() {
		finding, err := entities.NewFindingBuilder().
			WithID("ssl-certificate-expiring-soon").
			WithType(entities.FindingTypeMisconfiguration).
			WithSeverity(entities.SeverityMedium).
			WithTitle("SSL Certificate Expiring Soon").
			WithDescription(fmt.Sprintf("The SSL certificate expires in %d days", ssl.Certificate.DaysUntilExpiry())).
			WithTarget(targetURL).
			WithModuleSource("http").
			WithEvidence(entities.Evidence{
				"days_until_expiry": ssl.Certificate.DaysUntilExpiry(),
				"not_after":         ssl.Certificate.NotAfter,
			}).
			WithTags("ssl", "certificate", "expiring").
			Build()

		if err == nil {
			finding.SetRemediation("Plan to renew the SSL certificate before it expires")
			execution.AddFinding(finding)
		}
	}

	// Outdated TLS version
	for _, vuln := range ssl.Vulnerabilities {
		if strings.Contains(vuln, "Outdated TLS") {
			finding, err := entities.NewFindingBuilder().
				WithID("ssl-outdated-tls").
				WithType(entities.FindingTypeVulnerability).
				WithSeverity(entities.SeverityMedium).
				WithTitle("Outdated TLS Version").
				WithDescription("The server supports outdated TLS versions that may be vulnerable").
				WithTarget(targetURL).
				WithModuleSource("http").
				WithEvidence(entities.Evidence{
					"tls_version": ssl.Version,
				}).
				WithTags("ssl", "tls", "outdated").
				Build()

			if err == nil {
				finding.SetRemediation("Disable TLS 1.0 and 1.1, use TLS 1.2 or higher")
				execution.AddFinding(finding)
			}
		}
	}

	// Weak cipher suite
	for _, vuln := range ssl.Vulnerabilities {
		if strings.Contains(vuln, "Weak cipher") {
			finding, err := entities.NewFindingBuilder().
				WithID("ssl-weak-cipher").
				WithType(entities.FindingTypeVulnerability).
				WithSeverity(entities.SeverityMedium).
				WithTitle("Weak Cipher Suite").
				WithDescription("The server supports weak cipher suites that may be vulnerable").
				WithTarget(targetURL).
				WithModuleSource("http").
				WithEvidence(entities.Evidence{
					"vulnerability": vuln,
				}).
				WithTags("ssl", "cipher", "weak").
				Build()

			if err == nil {
				finding.SetRemediation("Configure server to use only strong cipher suites")
				execution.AddFinding(finding)
			}
		}
	}
}
