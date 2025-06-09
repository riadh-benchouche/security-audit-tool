package network

import (
	"context"
	"github.com/riadh-benchouche/security-audit-tool/internal/modules/interfaces"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// PortScanner handles port scanning operations
type PortScanner interface {
	Configure(config *Config) error
	ScanPorts(ctx context.Context, target *entities.Target, ports []int, stopChan <-chan struct{}) ([]PortResult, error)
	Stop()
	IsHealthy() bool
}

// ServiceDetector handles service detection
type ServiceDetector interface {
	Configure(config *Config) error
	DetectService(ctx context.Context, target *entities.Target, port int) (*ServiceInfo, error)
	Stop()
	IsHealthy() bool
}

// BannerGrabber handles banner grabbing
type BannerGrabber interface {
	Configure(config *Config) error
	GrabBanner(ctx context.Context, target *entities.Target, port int) (string, error)
	Stop()
	IsHealthy() bool
}

// OSDetector handles OS detection
type OSDetector interface {
	Configure(config *Config) error
	DetectOS(ctx context.Context, target *entities.Target) (*OSInfo, error)
	Stop()
	IsHealthy() bool
}

// ScanExecutor interface for executing different scan phases
type ScanExecutor interface {
	Execute(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error
	Stop()
	IsHealthy() bool
}

// Validator interface for target validation
type Validator interface {
	ValidateTarget(target *entities.Target) error
	ValidateConnectivity(target *entities.Target) error
}

// ProgressReporter interface for reporting scan progress
type ProgressReporter interface {
	ReportProgress(phase string, percent int, message string)
	ReportPhaseStart(phase string)
	ReportPhaseComplete(phase string)
}

// ResultProcessor interface for processing scan results
type ResultProcessor interface {
	ProcessPortResult(result PortResult, target *entities.Target) *entities.Finding
	ProcessServiceResult(service *ServiceInfo, port int, target *entities.Target) *entities.Finding
	ProcessOSResult(osInfo *OSInfo, target *entities.Target) *entities.Finding
	ProcessConnectivityResult(reachable bool, target *entities.Target) *entities.Finding
}

// ConfigValidator interface for configuration validation
type ConfigValidator interface {
	ValidateConfig(config *Config) error
	ValidatePortRange(ports []int) error
	ValidateTimeouts(tcpTimeout, udpTimeout int) error
}

// MetricsCollector interface for collecting scan metrics
type MetricsCollector interface {
	RecordScanStart(scanner string, target string)
	RecordScanComplete(scanner string, target string, duration int64, findingsCount int)
	RecordScanFailed(scanner string, target string, error string)
	RecordPortScanResult(target string, openPorts int, totalPorts int)
	RecordServiceDetection(target string, detectedServices int)
	GetMetrics() map[string]interface{}
}

// NetworkConnectivityChecker interface for checking network connectivity
type NetworkConnectivityChecker interface {
	CheckTCPConnectivity(host string, port int, timeout int) (bool, error)
	CheckUDPConnectivity(host string, port int, timeout int) (bool, error)
	CheckPing(host string, timeout int) (bool, int64, error)
	CheckDNSResolution(hostname string) ([]string, error)
}

// PortRangeParser interface for parsing port specifications
type PortRangeParser interface {
	ParsePortRange(portSpec string) ([]int, error)
	ParsePortList(portList []string) ([]int, error)
	GetTopPorts(count int) []int
	GetCommonPorts() []int
}

// ServiceFingerprinter interface for advanced service fingerprinting
type ServiceFingerprinter interface {
	FingerprintService(ctx context.Context, host string, port int) (*ServiceInfo, error)
	AnalyzeBanner(banner string, port int) (*ServiceInfo, error)
	DetectVersion(serviceName string, banner string) string
	GetConfidenceScore(detectionMethod string, banner string) int
}

// ReportGenerator interface for generating scan reports
type ReportGenerator interface {
	GenerateReport(results *ScanResult) ([]byte, error)
	GenerateJSONReport(results *ScanResult) ([]byte, error)
	GenerateHTMLReport(results *ScanResult) ([]byte, error)
	GenerateTextReport(results *ScanResult) ([]byte, error)
}

// Component interfaces for better modularity

// ScanPhaseExecutor represents a single scan phase executor
type ScanPhaseExecutor interface {
	Execute(ctx context.Context, target *entities.Target, execution *entities.ModuleExecution) error
	GetPhaseName() string
	GetProgressWeight() int
}

// ConnectivityPhaseExecutor handles connectivity checking phase
type ConnectivityPhaseExecutor interface {
	ScanPhaseExecutor
	CheckConnectivity(ctx context.Context, target *entities.Target) (*ConnectivityResult, error)
}

// PortScanPhaseExecutor handles port scanning phase
type PortScanPhaseExecutor interface {
	ScanPhaseExecutor
	ScanPorts(ctx context.Context, target *entities.Target, ports []int) ([]PortResult, error)
}

// ServiceDetectionPhaseExecutor handles service detection phase
type ServiceDetectionPhaseExecutor interface {
	ScanPhaseExecutor
	DetectServices(ctx context.Context, target *entities.Target, openPorts []PortResult) ([]ServiceInfo, error)
}

// OSDetectionPhaseExecutor handles OS detection phase
type OSDetectionPhaseExecutor interface {
	ScanPhaseExecutor
	DetectOS(ctx context.Context, target *entities.Target) (*OSInfo, error)
}

// Factory interfaces for component creation

// ScannerComponentFactory creates scanner components
type ScannerComponentFactory interface {
	CreatePortScanner(config *Config) PortScanner
	CreateServiceDetector(config *Config) ServiceDetector
	CreateBannerGrabber(config *Config) BannerGrabber
	CreateOSDetector(config *Config) OSDetector
}

// PhaseExecutorFactory creates phase executors
type PhaseExecutorFactory interface {
	CreateConnectivityExecutor(config *Config) ConnectivityPhaseExecutor
	CreatePortScanExecutor(config *Config) PortScanPhaseExecutor
	CreateServiceDetectionExecutor(config *Config) ServiceDetectionPhaseExecutor
	CreateOSDetectionExecutor(config *Config) OSDetectionPhaseExecutor
}

// Composite interfaces for full functionality

// NetworkScannerCore represents the core scanning functionality
type NetworkScannerCore interface {
	Info() *interfaces.ScannerInfo
	Configure(config map[string]interface{}) error
	Validate(target *entities.Target) error
	Scan(ctx context.Context, target *entities.Target) (*entities.ModuleExecution, error)
	Stop() error
	Health() *interfaces.HealthStatus
}

// ExtendedNetworkScanner represents a network scanner with additional capabilities
type ExtendedNetworkScanner interface {
	NetworkScannerCore
	SetLogger(logger interfaces.ScannerLogger)
	SetMetrics(metrics interfaces.ScannerMetrics)
	GetConfig() *Config
	GetLastScanResult() *ScanResult
}

// Ensure NetworkScanner implements the required interfaces
var (
	_ NetworkScannerCore = (*NetworkScanner)(nil)
)

// Configurable represents components that can be configured
type Configurable interface {
	Configure(config *Config) error
}

// Startable represents components that can be started/stopped
type Startable interface {
	Start() error
	Stop() error
}

// Healthable represents components that can report health status
type Healthable interface {
	IsHealthy() bool
	GetHealthStatus() string
}

// Testable represents components that can be tested
type Testable interface {
	Test(ctx context.Context, target *entities.Target) error
	ValidateConfiguration() error
}
