package network

// PortResult represents the result of a port scan
type PortResult struct {
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	State    PortState `json:"state"`
	Banner   string    `json:"banner,omitempty"`
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

// IsOpen returns true if the port is open
func (ps PortState) IsOpen() bool {
	return ps == PortStateOpen
}

// IsClosed returns true if the port is closed
func (ps PortState) IsClosed() bool {
	return ps == PortStateClosed
}

// IsFiltered returns true if the port is filtered
func (ps PortState) IsFiltered() bool {
	return ps == PortStateFiltered
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
		return si.Name + " " + si.Version
	}
	return si.Name
}

// OSInfo represents detected OS information
type OSInfo struct {
	Name        string `json:"name"`
	Family      string `json:"family"`
	Version     string `json:"version,omitempty"`
	Confidence  int    `json:"confidence"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Method      string `json:"method"`
}

// IsConfident returns true if the OS detection confidence is high (>= 70%)
func (oi *OSInfo) IsConfident() bool {
	return oi.Confidence >= 70
}

// IsVersionKnown returns true if the OS version is detected
func (oi *OSInfo) IsVersionKnown() bool {
	return oi.Version != ""
}

// GetDisplayName returns a formatted display name for the OS
func (oi *OSInfo) GetDisplayName() string {
	if oi.Version != "" {
		return oi.Name + " " + oi.Version
	}
	return oi.Name
}

// GetFamilyName returns the OS family name
func (oi *OSInfo) GetFamilyName() string {
	if oi.Family != "" {
		return oi.Family
	}
	return "Unknown"
}

// ScanResult represents the overall result of a network scan
type ScanResult struct {
	Target           string        `json:"target"`
	OpenPorts        []PortResult  `json:"open_ports"`
	DetectedServices []ServiceInfo `json:"detected_services,omitempty"`
	DetectedOS       *OSInfo       `json:"detected_os,omitempty"`
	ScanDuration     int64         `json:"scan_duration_ms"`
	TotalPorts       int           `json:"total_ports_scanned"`
}

// GetOpenPortCount returns the number of open ports
func (sr *ScanResult) GetOpenPortCount() int {
	return len(sr.OpenPorts)
}

// GetServiceCount returns the number of detected services
func (sr *ScanResult) GetServiceCount() int {
	return len(sr.DetectedServices)
}

// HasOpenPorts returns true if any ports are open
func (sr *ScanResult) HasOpenPorts() bool {
	return len(sr.OpenPorts) > 0
}

// HasServices returns true if any services were detected
func (sr *ScanResult) HasServices() bool {
	return len(sr.DetectedServices) > 0
}

// HasOSDetection returns true if OS was detected
func (sr *ScanResult) HasOSDetection() bool {
	return sr.DetectedOS != nil && sr.DetectedOS.Name != ""
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
