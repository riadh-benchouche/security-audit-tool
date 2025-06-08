package config

import (
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	*viper.Viper
}

// ScanConfig contains scan configuration
type ScanConfig struct {
	Timeout   int      `yaml:"timeout" json:"timeout"`
	Threads   int      `yaml:"threads" json:"threads"`
	UserAgent string   `yaml:"user_agent" json:"user_agent"`
	Modules   []string `yaml:"modules" json:"modules"`
}

// NetworkConfig contains network scan configuration
type NetworkConfig struct {
	Ports      []int `yaml:"ports" json:"ports"`
	TopPorts   int   `yaml:"top_ports" json:"top_ports"`
	TCPTimeout int   `yaml:"tcp_timeout" json:"tcp_timeout"`
	UDPTimeout int   `yaml:"udp_timeout" json:"udp_timeout"`
	MaxThreads int   `yaml:"max_threads" json:"max_threads"`
	PingCheck  bool  `yaml:"ping_check" json:"ping_check"`
}

// HTTPConfig contains HTTP scan configuration
type HTTPConfig struct {
	FollowRedirects bool     `yaml:"follow_redirects" json:"follow_redirects"`
	MaxRedirects    int      `yaml:"max_redirects" json:"max_redirects"`
	Timeout         int      `yaml:"timeout" json:"timeout"`
	UserAgent       string   `yaml:"user_agent" json:"user_agent"`
	Headers         []string `yaml:"headers" json:"headers"`
	Cookies         []string `yaml:"cookies" json:"cookies"`
	SSLCheck        bool     `yaml:"ssl_check" json:"ssl_check"`
	CheckRedirects  bool     `yaml:"check_redirects" json:"check_redirects"`
}

// ServerConfig contains server configuration
type ServerConfig struct {
	Host         string `yaml:"host" json:"host"`
	Port         int    `yaml:"port" json:"port"`
	ReadTimeout  int    `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout" json:"write_timeout"`
	IdleTimeout  int    `yaml:"idle_timeout" json:"idle_timeout"`
}

// ReportsConfig contains reports configuration
type ReportsConfig struct {
	DefaultFormat  string `yaml:"default_format" json:"default_format"`
	IncludeRawData bool   `yaml:"include_raw_data" json:"include_raw_data"`
	MaxFindings    int    `yaml:"max_findings" json:"max_findings"`
}

// AdvancedConfig contains advanced configuration
type AdvancedConfig struct {
	MaxScanTime        int  `yaml:"max_scan_time" json:"max_scan_time"`
	MaxConcurrentScans int  `yaml:"max_concurrent_scans" json:"max_concurrent_scans"`
	CacheEnabled       bool `yaml:"cache_enabled" json:"cache_enabled"`
	CacheTTL           int  `yaml:"cache_ttl" json:"cache_ttl"`
}

// AppConfig contains the complete application configuration
type AppConfig struct {
	Scan     ScanConfig     `yaml:"scan" json:"scan"`
	Network  NetworkConfig  `yaml:"network" json:"network"`
	HTTP     HTTPConfig     `yaml:"http" json:"http"`
	Server   ServerConfig   `yaml:"server" json:"server"`
	Reports  ReportsConfig  `yaml:"reports" json:"reports"`
	Advanced AdvancedConfig `yaml:"advanced" json:"advanced"`
	LogLevel string         `yaml:"log_level" json:"log_level"`
}

var globalConfig *Config

// NewConfig creates a new configuration instance
func NewConfig() *Config {
	v := viper.New()

	// ✅ Set defaults that match your YAML structure
	v.SetDefault("scan.timeout", 300)
	v.SetDefault("scan.threads", 10)
	v.SetDefault("scan.user_agent", "SecurityAuditTool/2.0")
	v.SetDefault("scan.modules", []string{"network"})

	v.SetDefault("network.top_ports", 1000)
	v.SetDefault("network.tcp_timeout", 5)
	v.SetDefault("network.udp_timeout", 5)
	v.SetDefault("network.max_threads", 50)
	v.SetDefault("network.ping_check", true)
	v.SetDefault("network.ports", []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 9300,
	})

	v.SetDefault("http.follow_redirects", true)
	v.SetDefault("http.max_redirects", 5)
	v.SetDefault("http.timeout", 30)
	v.SetDefault("http.user_agent", "SecurityAuditTool/2.0")
	v.SetDefault("http.ssl_check", true)
	v.SetDefault("http.check_redirects", true)
	v.SetDefault("http.headers", []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
	})

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30)
	v.SetDefault("server.write_timeout", 30)
	v.SetDefault("server.idle_timeout", 120)

	v.SetDefault("reports.default_format", "json")
	v.SetDefault("reports.include_raw_data", false)
	v.SetDefault("reports.max_findings", 1000)

	v.SetDefault("advanced.max_scan_time", 3600)
	v.SetDefault("advanced.max_concurrent_scans", 5)
	v.SetDefault("advanced.cache_enabled", true)
	v.SetDefault("advanced.cache_ttl", 3600)

	v.SetDefault("log_level", "info")

	v.SetConfigName("security-audit")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("$HOME/.config/security-audit")
	v.AddConfigPath("/etc/security-audit")

	// Environment variables
	v.SetEnvPrefix("SECAUDIT")
	v.AutomaticEnv()

	config := &Config{Viper: v}
	globalConfig = config

	return config
}

// Load loads configuration from file
func (c *Config) Load() error {
	return c.ReadInConfig()
}

// SetConfigFile sets the configuration file to use
func (c *Config) SetConfigFile(file string) {
	c.Viper.SetConfigFile(file)
}

// GetAppConfig returns the complete application configuration
func (c *Config) GetAppConfig() (*AppConfig, error) {
	var config AppConfig
	err := c.Unmarshal(&config)
	return &config, err
}

// GetScanConfig returns scan configuration
func (c *Config) GetScanConfig() ScanConfig {
	var config ScanConfig
	c.UnmarshalKey("scan", &config)
	return config
}

// GetNetworkConfig returns network configuration
func (c *Config) GetNetworkConfig() NetworkConfig {
	var config NetworkConfig
	c.UnmarshalKey("network", &config)
	return config
}

// GetHTTPConfig returns HTTP configuration
func (c *Config) GetHTTPConfig() HTTPConfig {
	var config HTTPConfig
	c.UnmarshalKey("http", &config)
	return config
}

// GetServerConfig returns server configuration
func (c *Config) GetServerConfig() ServerConfig {
	var config ServerConfig
	c.UnmarshalKey("server", &config)
	return config
}

// GetScannerConfig amélioré pour utiliser votre structure
func (c *Config) GetScannerConfig(scannerName string) map[string]interface{} {
	configMap := make(map[string]interface{})

	switch scannerName {
	case "network":
		networkConfig := c.GetNetworkConfig()
		scanConfig := c.GetScanConfig()

		// Utiliser les valeurs du YAML ou des defaults
		timeout := scanConfig.Timeout
		if timeout <= 0 {
			timeout = 300
		}

		maxThreads := networkConfig.MaxThreads
		if maxThreads <= 0 {
			maxThreads = scanConfig.Threads
		}
		if maxThreads <= 0 {
			maxThreads = 10
		}

		tcpTimeout := networkConfig.TCPTimeout
		if tcpTimeout <= 0 {
			tcpTimeout = 5
		}

		configMap["timeout"] = timeout
		configMap["max_threads"] = maxThreads
		configMap["ports"] = networkConfig.Ports
		configMap["tcp_timeout"] = tcpTimeout
		configMap["udp_timeout"] = networkConfig.UDPTimeout
		configMap["ping_check"] = true // Toujours activé
		configMap["service_scan"] = true
		configMap["banner_grab"] = true
		configMap["os_detect"] = false

	case "http":
		httpConfig := c.GetHTTPConfig()

		timeout := httpConfig.Timeout
		if timeout <= 0 {
			timeout = 30
		}

		maxRedirects := httpConfig.MaxRedirects
		if maxRedirects < 0 {
			maxRedirects = 5
		}

		configMap["timeout"] = timeout
		configMap["user_agent"] = httpConfig.UserAgent
		configMap["max_redirects"] = maxRedirects
		configMap["follow_redirects"] = httpConfig.FollowRedirects
		configMap["ssl_check"] = httpConfig.SSLCheck
	}

	return configMap
}

// GetGlobalConfig returns the global configuration
func GetGlobalConfig() *Config {
	if globalConfig == nil {
		return NewConfig()
	}
	return globalConfig
}
