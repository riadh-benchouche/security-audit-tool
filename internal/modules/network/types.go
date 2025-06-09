// types.go - Version corrigée avec tous les types manquants

package network

import (
	"fmt"
	"time"
)

// PortResult represents the result of a port scan
type PortResult struct {
	Port         int           `json:"port"`
	Number       int           `json:"number"` // Alias pour Port
	Protocol     string        `json:"protocol"`
	State        PortState     `json:"state"`
	Banner       string        `json:"banner,omitempty"`
	Service      string        `json:"service,omitempty"`
	Description  string        `json:"description,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
}

// PortState represents the state of a port
type PortState int

const (
	PortStateOpen PortState = iota + 1
	PortStateClosed
	PortStateFiltered
)

// String returns the string representation of the port state
func (ps PortState) String() string {
	switch ps {
	case PortStateOpen:
		return "open"
	case PortStateClosed:
		return "closed"
	case PortStateFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// ServiceInfo represents detected service information
type ServiceInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Product         string `json:"product,omitempty"`
	Confidence      int    `json:"confidence"`
	DetectionMethod string `json:"detection_method"`
	Fingerprint     string `json:"fingerprint,omitempty"`
}

// IsConfident returns true if the service detection confidence is high (>= 80%)
func (si *ServiceInfo) IsConfident() bool {
	return si.Confidence >= 80
}

// IsVersionKnown returns true if the service version is detected
func (si *ServiceInfo) IsVersionKnown() bool {
	return si.Version != ""
}

// GetDisplayName returns a formatted display name for the service
func (si *ServiceInfo) GetDisplayName() string {
	if si.Version != "" {
		return fmt.Sprintf("%s %s", si.Name, si.Version)
	}
	return si.Name
}

// ServiceResult est un alias pour ServiceInfo pour compatibilité
type ServiceResult = ServiceInfo

// OSInfo represents detected OS information
type OSInfo struct {
	OS          string  `json:"os"`   // Champ principal
	Name        string  `json:"name"` // Alias pour OS
	Family      string  `json:"family"`
	Version     string  `json:"version,omitempty"`
	Confidence  float64 `json:"confidence"` // Changé en float64 pour compatibilité
	Fingerprint string  `json:"fingerprint,omitempty"`
	Method      string  `json:"method"`
}

// IsConfident returns true if the OS detection confidence is high (>= 70%)
func (oi *OSInfo) IsConfident() bool {
	return oi.Confidence >= 0.70
}

// IsVersionKnown returns true if the OS version is detected
func (oi *OSInfo) IsVersionKnown() bool {
	return oi.Version != ""
}

// GetDisplayName returns a formatted display name for the OS
func (oi *OSInfo) GetDisplayName() string {
	name := oi.Name
	if name == "" {
		name = oi.OS
	}
	if oi.Version != "" {
		return fmt.Sprintf("%s %s", name, oi.Version)
	}
	return name
}

// GetFamilyName returns the OS family name
func (oi *OSInfo) GetFamilyName() string {
	if oi.Family != "" {
		return oi.Family
	}
	return "Unknown"
}

// OSResult est un alias pour OSInfo pour compatibilité
type OSResult = OSInfo

// BannerResult represents the result of banner grabbing
type BannerResult struct {
	Port    int    `json:"port"`
	Content string `json:"content"`
	Length  int    `json:"length"`
	Error   string `json:"error,omitempty"`
}

// IsSuccessful returns true if banner was successfully grabbed
func (br *BannerResult) IsSuccessful() bool {
	return br.Content != "" && br.Error == ""
}

// HasError returns true if there was an error during banner grabbing
func (br *BannerResult) HasError() bool {
	return br.Error != ""
}

// GetPreview returns a truncated version of the banner for display
func (br *BannerResult) GetPreview(maxLength int) string {
	if len(br.Content) <= maxLength {
		return br.Content
	}
	return br.Content[:maxLength] + "..."
}

// ConnectivityResult represents the result of a connectivity check
type ConnectivityResult struct {
	Target       string `json:"target"`
	Reachable    bool   `json:"reachable"`
	Method       string `json:"method"`
	Port         int    `json:"port,omitempty"`
	ResponseTime int64  `json:"response_time_ms,omitempty"`
	Error        string `json:"error,omitempty"`
}

// IsSuccessful returns true if the connectivity check was successful
func (cr *ConnectivityResult) IsSuccessful() bool {
	return cr.Reachable
}

// HasError returns true if there was an error during connectivity check
func (cr *ConnectivityResult) HasError() bool {
	return cr.Error != ""
}

// GetResponseTimeMs returns the response time in milliseconds
func (cr *ConnectivityResult) GetResponseTimeMs() int64 {
	return cr.ResponseTime
}

// ScanResult represents the overall result of a network scan
type ScanResult struct {
	Target           string          `json:"target"`
	OpenPorts        []PortResult    `json:"open_ports"`
	Services         []ServiceResult `json:"services"`        // Nouveau champ
	Banners          []BannerResult  `json:"banners"`         // Nouveau champ
	OSFingerprints   []OSResult      `json:"os_fingerprints"` // Nouveau champ
	DetectedServices []ServiceInfo   `json:"detected_services,omitempty"`
	DetectedOS       *OSInfo         `json:"detected_os,omitempty"`
	ScanDuration     int64           `json:"scan_duration_ms"`
	TotalPorts       int             `json:"total_ports_scanned"`
}

// GetOpenPortCount returns the number of open ports
func (sr *ScanResult) GetOpenPortCount() int {
	return len(sr.OpenPorts)
}

// GetServiceCount returns the number of detected services
func (sr *ScanResult) GetServiceCount() int {
	if len(sr.Services) > 0 {
		return len(sr.Services)
	}
	return len(sr.DetectedServices)
}

// HasOpenPorts returns true if any ports are open
func (sr *ScanResult) HasOpenPorts() bool {
	return len(sr.OpenPorts) > 0
}

// HasServices returns true if any services were detected
func (sr *ScanResult) HasServices() bool {
	return len(sr.Services) > 0 || len(sr.DetectedServices) > 0
}

// HasOSDetection returns true if OS was detected
func (sr *ScanResult) HasOSDetection() bool {
	if len(sr.OSFingerprints) > 0 {
		return true
	}
	return sr.DetectedOS != nil && sr.DetectedOS.Name != ""
}

// HasBanners returns true if any banners were grabbed
func (sr *ScanResult) HasBanners() bool {
	return len(sr.Banners) > 0
}

// GetPortsByProtocol returns ports filtered by protocol
func (sr *ScanResult) GetPortsByProtocol(protocol string) []PortResult {
	var filtered []PortResult
	for _, port := range sr.OpenPorts {
		if port.Protocol == protocol {
			filtered = append(filtered, port)
		}
	}
	return filtered
}

// GetTCPPorts returns only TCP ports
func (sr *ScanResult) GetTCPPorts() []PortResult {
	return sr.GetPortsByProtocol("tcp")
}

// GetUDPPorts returns only UDP ports
func (sr *ScanResult) GetUDPPorts() []PortResult {
	return sr.GetPortsByProtocol("udp")
}

// GetSummary returns a summary of scan results
func (sr *ScanResult) GetSummary() map[string]interface{} {
	return map[string]interface{}{
		"target":           sr.Target,
		"open_ports":       sr.GetOpenPortCount(),
		"services_found":   sr.GetServiceCount(),
		"banners_grabbed":  len(sr.Banners),
		"os_detected":      sr.HasOSDetection(),
		"scan_duration_ms": sr.ScanDuration,
	}
}

// ScanProgress represents the progress of a network scan
type ScanProgress struct {
	Phase           string `json:"phase"`
	CurrentStep     int    `json:"current_step"`
	TotalSteps      int    `json:"total_steps"`
	ProgressPercent int    `json:"progress_percent"`
	Message         string `json:"message,omitempty"`
}

// IsComplete returns true if the scan is complete
func (sp *ScanProgress) IsComplete() bool {
	return sp.ProgressPercent >= 100
}

// GetProgressRatio returns the progress as a ratio (0.0 to 1.0)
func (sp *ScanProgress) GetProgressRatio() float64 {
	return float64(sp.ProgressPercent) / 100.0
}

// GetDisplayMessage returns a formatted progress message
func (sp *ScanProgress) GetDisplayMessage() string {
	if sp.Message != "" {
		return sp.Message
	}
	return sp.Phase
}
