package core

import (
	"github.com/spf13/viper"
)

// Config représente la configuration de l'application
type Config struct {
	*viper.Viper
}

// ScanConfig contient la configuration pour les scans
type ScanConfig struct {
	Timeout   int      `yaml:"timeout" json:"timeout"`
	Threads   int      `yaml:"threads" json:"threads"`
	UserAgent string   `yaml:"user_agent" json:"user_agent"`
	Modules   []string `yaml:"modules" json:"modules"`
}

// NetworkConfig contient la configuration pour les scans réseau
type NetworkConfig struct {
	Ports      []int `yaml:"ports" json:"ports"`
	TopPorts   int   `yaml:"top_ports" json:"top_ports"`
	TCPTimeout int   `yaml:"tcp_timeout" json:"tcp_timeout"`
	UDPTimeout int   `yaml:"udp_timeout" json:"udp_timeout"`
}

// HTTPConfig contient la configuration pour les scans HTTP
type HTTPConfig struct {
	FollowRedirects bool     `yaml:"follow_redirects" json:"follow_redirects"`
	MaxRedirects    int      `yaml:"max_redirects" json:"max_redirects"`
	Headers         []string `yaml:"headers" json:"headers"`
	Cookies         []string `yaml:"cookies" json:"cookies"`
}

// AppConfig contient toute la configuration de l'application
type AppConfig struct {
	Scan     ScanConfig    `yaml:"scan" json:"scan"`
	Network  NetworkConfig `yaml:"network" json:"network"`
	HTTP     HTTPConfig    `yaml:"http" json:"http"`
	LogLevel string        `yaml:"log_level" json:"log_level"`
}

var globalConfig *Config

// NewConfig crée une nouvelle instance de configuration
func NewConfig() *Config {
	v := viper.New()

	// Définir les valeurs par défaut
	v.SetDefault("scan.timeout", 300)
	v.SetDefault("scan.threads", 10)
	v.SetDefault("scan.user_agent", "SecurityAuditTool/1.0")
	v.SetDefault("scan.modules", []string{"network"})

	v.SetDefault("network.top_ports", 1000)
	v.SetDefault("network.tcp_timeout", 5)
	v.SetDefault("network.udp_timeout", 5)
	v.SetDefault("network.ports", []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
	})

	v.SetDefault("http.follow_redirects", true)
	v.SetDefault("http.max_redirects", 5)
	v.SetDefault("http.headers", []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	})

	v.SetDefault("log_level", "info")

	// Configuration des fichiers
	v.SetConfigName("security-audit")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.config/security-audit")
	v.AddConfigPath("/etc/security-audit")

	// Variables d'environnement
	v.SetEnvPrefix("SECAUDIT")
	v.AutomaticEnv()

	config := &Config{Viper: v}
	globalConfig = config

	return config
}

// Load charge la configuration depuis le fichier
func (c *Config) Load() error {
	return c.ReadInConfig()
}

// SetConfigFile définit le fichier de configuration à utiliser
func (c *Config) SetConfigFile(file string) {
	c.Viper.SetConfigFile(file)
}

// GetAppConfig retourne la configuration complète de l'application
func (c *Config) GetAppConfig() (*AppConfig, error) {
	var config AppConfig
	err := c.Unmarshal(&config)
	return &config, err
}

// GetScanConfig retourne la configuration de scan
func (c *Config) GetScanConfig() ScanConfig {
	var config ScanConfig
	c.UnmarshalKey("scan", &config)
	return config
}

// GetNetworkConfig retourne la configuration réseau
func (c *Config) GetNetworkConfig() NetworkConfig {
	var config NetworkConfig
	c.UnmarshalKey("network", &config)
	return config
}

// GetHTTPConfig retourne la configuration HTTP
func (c *Config) GetHTTPConfig() HTTPConfig {
	var config HTTPConfig
	c.UnmarshalKey("http", &config)
	return config
}

// GetGlobalConfig retourne la configuration globale
func GetGlobalConfig() *Config {
	if globalConfig == nil {
		return NewConfig()
	}
	return globalConfig
}
