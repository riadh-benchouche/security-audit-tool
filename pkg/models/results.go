package models

import (
	"time"
)

// ScanResult représente le résultat complet d'un scan
type ScanResult struct {
	Target    string         `json:"target"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Duration  time.Duration  `json:"duration"`
	Results   []ModuleResult `json:"results"`
	Summary   ScanSummary    `json:"summary"`
}

// ModuleResult représente le résultat d'un module de scan
type ModuleResult struct {
	Module    string                 `json:"module"`
	Status    ScanStatus             `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  time.Duration          `json:"duration"`
	Findings  []Finding              `json:"findings"`
	Errors    []string               `json:"errors,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Finding représente une découverte de sécurité
type Finding struct {
	ID          string                 `json:"id"`
	Type        FindingType            `json:"type"`
	Severity    Severity               `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Target      string                 `json:"target"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	References  []string               `json:"references,omitempty"`
	CVSS        *CVSSScore             `json:"cvss,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NetworkResult représente les résultats d'un scan réseau
type NetworkResult struct {
	Host     string       `json:"host"`
	IP       string       `json:"ip"`
	Ports    []PortResult `json:"ports"`
	OS       *OSDetection `json:"os,omitempty"`
	Services []Service    `json:"services"`
	Ping     *PingResult  `json:"ping,omitempty"`
}

// PortResult représente le résultat d'un scan de port
type PortResult struct {
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	State    PortState `json:"state"`
	Service  *Service  `json:"service,omitempty"`
	Banner   string    `json:"banner,omitempty"`
}

// Service représente un service détecté
type Service struct {
	Name      string            `json:"name"`
	Version   string            `json:"version,omitempty"`
	Product   string            `json:"product,omitempty"`
	ExtraInfo string            `json:"extra_info,omitempty"`
	Tunnel    string            `json:"tunnel,omitempty"`
	Method    string            `json:"method,omitempty"`
	Conf      int               `json:"conf,omitempty"`
	CPE       []string          `json:"cpe,omitempty"`
	Scripts   map[string]string `json:"scripts,omitempty"`
}

// OSDetection représente la détection d'OS
type OSDetection struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	Generation  string `json:"generation,omitempty"`
	Type        string `json:"type,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Accuracy    int    `json:"accuracy"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// PingResult représente le résultat d'un ping
type PingResult struct {
	Alive  bool          `json:"alive"`
	RTT    time.Duration `json:"rtt,omitempty"`
	Method string        `json:"method"`
	Error  string        `json:"error,omitempty"`
}

// HTTPResult représente les résultats d'un scan HTTP
type HTTPResult struct {
	URL          string            `json:"url"`
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Title        string            `json:"title,omitempty"`
	Server       string            `json:"server,omitempty"`
	Technologies []Technology      `json:"technologies,omitempty"`
	SSL          *SSLResult        `json:"ssl,omitempty"`
	Security     SecurityHeaders   `json:"security"`
	Redirects    []Redirect        `json:"redirects,omitempty"`
	ResponseTime time.Duration     `json:"response_time"`
}

// Technology représente une technologie détectée
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Website    string   `json:"website,omitempty"`
	Icon       string   `json:"icon,omitempty"`
}

// SSLResult représente les résultats d'une analyse SSL
type SSLResult struct {
	Enabled         bool         `json:"enabled"`
	Version         string       `json:"version,omitempty"`
	Certificate     *Certificate `json:"certificate,omitempty"`
	Ciphers         []string     `json:"ciphers,omitempty"`
	Protocols       []string     `json:"protocols,omitempty"`
	Vulnerabilities []string     `json:"vulnerabilities,omitempty"`
	Grade           string       `json:"grade,omitempty"`
}

// Certificate représente un certificat SSL
type Certificate struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	SerialNumber   string    `json:"serial_number"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	IsExpired      bool      `json:"is_expired"`
	IsCA           bool      `json:"is_ca"`
	KeySize        int       `json:"key_size"`
	SignatureAlg   string    `json:"signature_algorithm"`
	DNSNames       []string  `json:"dns_names,omitempty"`
	EmailAddresses []string  `json:"email_addresses,omitempty"`
}

// SecurityHeaders représente l'analyse des headers de sécurité
type SecurityHeaders struct {
	HSTS                *Header `json:"hsts,omitempty"`
	CSP                 *Header `json:"csp,omitempty"`
	XFrameOptions       *Header `json:"x_frame_options,omitempty"`
	XContentTypeOptions *Header `json:"x_content_type_options,omitempty"`
	XSSProtection       *Header `json:"x_xss_protection,omitempty"`
	ReferrerPolicy      *Header `json:"referrer_policy,omitempty"`
	PermissionsPolicy   *Header `json:"permissions_policy,omitempty"`
	ExpectCT            *Header `json:"expect_ct,omitempty"`
	Score               int     `json:"score"`
	Grade               string  `json:"grade"`
}

// Header représente un header HTTP avec son analyse
type Header struct {
	Present bool     `json:"present"`
	Value   string   `json:"value,omitempty"`
	Valid   bool     `json:"valid"`
	Issues  []string `json:"issues,omitempty"`
	Score   int      `json:"score"`
}

// Redirect représente une redirection HTTP
type Redirect struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode int    `json:"status_code"`
}

// CVSSScore représente un score CVSS
type CVSSScore struct {
	Version float64 `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Rating  string  `json:"rating"`
}

// ScanSummary représente un résumé du scan
type ScanSummary struct {
	TotalFindings      int                 `json:"total_findings"`
	FindingsBySeverity map[Severity]int    `json:"findings_by_severity"`
	FindingsByType     map[FindingType]int `json:"findings_by_type"`
	ModulesExecuted    []string            `json:"modules_executed"`
	ModulesFailed      []string            `json:"modules_failed,omitempty"`
	Score              int                 `json:"score"`
	Grade              string              `json:"grade"`
}

// Énumérations et constantes

// ScanStatus représente le statut d'un scan
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCanceled  ScanStatus = "canceled"
)

// Severity représente la sévérité d'une vulnérabilité
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// FindingType représente le type de découverte
type FindingType string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeInformation      FindingType = "information"
	FindingTypeCompliance       FindingType = "compliance"
	FindingTypeBestPractice     FindingType = "best_practice"
)

// PortState représente l'état d'un port
type PortState string

const (
	PortStateOpen     PortState = "open"
	PortStateClosed   PortState = "closed"
	PortStateFiltered PortState = "filtered"
)

// Méthodes utilitaires

// GetSeverityScore retourne un score numérique pour une sévérité
func (s Severity) GetScore() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// IsCompleted vérifie si le scan est terminé
func (s ScanStatus) IsCompleted() bool {
	return s == StatusCompleted || s == StatusFailed || s == StatusCanceled
}

// AddFinding ajoute une découverte au résultat d'un module
func (mr *ModuleResult) AddFinding(finding Finding) {
	mr.Findings = append(mr.Findings, finding)
}

// AddError ajoute une erreur au résultat d'un module
func (mr *ModuleResult) AddError(err string) {
	mr.Errors = append(mr.Errors, err)
}

// CalculateDuration calcule la durée du scan
func (sr *ScanResult) CalculateDuration() {
	if !sr.EndTime.IsZero() && !sr.StartTime.IsZero() {
		sr.Duration = sr.EndTime.Sub(sr.StartTime)
	}
}

// GenerateSummary génère un résumé du scan
func (sr *ScanResult) GenerateSummary() {
	summary := ScanSummary{
		FindingsBySeverity: make(map[Severity]int),
		FindingsByType:     make(map[FindingType]int),
		ModulesExecuted:    make([]string, 0),
		ModulesFailed:      make([]string, 0),
	}

	for _, result := range sr.Results {
		summary.ModulesExecuted = append(summary.ModulesExecuted, result.Module)
		if result.Status == StatusFailed {
			summary.ModulesFailed = append(summary.ModulesFailed, result.Module)
		}

		for _, finding := range result.Findings {
			summary.TotalFindings++
			summary.FindingsBySeverity[finding.Severity]++
			summary.FindingsByType[finding.Type]++
		}
	}

	// Calculer le score global (0-100)
	totalScore := 0
	criticalCount := summary.FindingsBySeverity[SeverityCritical]
	highCount := summary.FindingsBySeverity[SeverityHigh]
	mediumCount := summary.FindingsBySeverity[SeverityMedium]
	lowCount := summary.FindingsBySeverity[SeverityLow]

	// Pénalités par sévérité
	totalScore = 100 - (criticalCount*20 + highCount*10 + mediumCount*5 + lowCount*2)
	if totalScore < 0 {
		totalScore = 0
	}

	summary.Score = totalScore

	// Attribuer une note
	switch {
	case totalScore >= 90:
		summary.Grade = "A"
	case totalScore >= 80:
		summary.Grade = "B"
	case totalScore >= 70:
		summary.Grade = "C"
	case totalScore >= 60:
		summary.Grade = "D"
	default:
		summary.Grade = "F"
	}

	sr.Summary = summary
}
