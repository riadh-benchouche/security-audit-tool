package network

import (
	"fmt"
)

// Config represents network scanner configuration
type Config struct {
	Timeout     int   `json:"timeout"`
	MaxThreads  int   `json:"max_threads"`
	Ports       []int `json:"ports"`
	TopPorts    int   `json:"top_ports"`
	TCPTimeout  int   `json:"tcp_timeout"`
	UDPTimeout  int   `json:"udp_timeout"`
	PingCheck   bool  `json:"ping_check"`
	ServiceScan bool  `json:"service_scan"`
	BannerGrab  bool  `json:"banner_grab"`
	OSDetect    bool  `json:"os_detect"`
}

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *Config {
	return &Config{
		Timeout:    300,
		MaxThreads: 50,
		Ports: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
			1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 9300,
		},
		TopPorts:    1000,
		TCPTimeout:  5,
		UDPTimeout:  5,
		PingCheck:   true,
		ServiceScan: true,
		BannerGrab:  true,
		OSDetect:    false, // Disabled by default as it can be slow
	}
}

// Update updates the configuration with provided values
func (c *Config) Update(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok {
			if t <= 0 {
				c.Timeout = 300
			} else if t <= 3600 {
				c.Timeout = t
			} else {
				return fmt.Errorf("timeout must be between 1 and 3600 seconds, got: %v", timeout)
			}
		} else {
			return fmt.Errorf("invalid timeout type: %T, expected int", timeout)
		}
	}

	if maxThreads, ok := config["max_threads"]; ok {
		if mt, ok := maxThreads.(int); ok {
			if mt <= 0 {
				c.MaxThreads = 10 // Valeur par défaut
			} else if mt <= 200 {
				c.MaxThreads = mt
			} else {
				return fmt.Errorf("max_threads must be between 1 and 200, got: %v", maxThreads)
			}
		} else {
			return fmt.Errorf("invalid max_threads type: %T, expected int", maxThreads)
		}
	}

	if ports, ok := config["ports"]; ok {
		if portList, ok := ports.([]int); ok {
			c.Ports = portList
		} else if portInterface, ok := ports.([]interface{}); ok {
			// Handle JSON unmarshal case
			c.Ports = make([]int, len(portInterface))
			for i, p := range portInterface {
				if port, ok := p.(float64); ok {
					c.Ports[i] = int(port)
				} else {
					return fmt.Errorf("invalid port value: %v", p)
				}
			}
		} else {
			return fmt.Errorf("invalid ports value: %v", ports)
		}
	}

	if tcpTimeout, ok := config["tcp_timeout"]; ok {
		if tt, ok := tcpTimeout.(int); ok {
			if tt <= 0 {
				c.TCPTimeout = 5
			} else if tt <= 30 {
				c.TCPTimeout = tt
			} else {
				return fmt.Errorf("tcp_timeout must be between 1 and 30 seconds, got: %v", tcpTimeout)
			}
		} else {
			return fmt.Errorf("invalid tcp_timeout type: %T, expected int", tcpTimeout)
		}
	}

	if udpTimeout, ok := config["udp_timeout"]; ok {
		if ut, ok := udpTimeout.(int); ok {
			if ut <= 0 {
				c.UDPTimeout = 5
			} else if ut <= 30 {
				c.UDPTimeout = ut
			} else {
				return fmt.Errorf("udp_timeout must be between 1 and 30 seconds, got: %v", udpTimeout)
			}
		} else {
			return fmt.Errorf("invalid udp_timeout type: %T, expected int", udpTimeout)
		}
	}

	if pingCheck, ok := config["ping_check"]; ok {
		if pc, ok := pingCheck.(bool); ok {
			c.PingCheck = pc
		}
	}

	if serviceScan, ok := config["service_scan"]; ok {
		if ss, ok := serviceScan.(bool); ok {
			c.ServiceScan = ss
		}
	}

	if bannerGrab, ok := config["banner_grab"]; ok {
		if bg, ok := bannerGrab.(bool); ok {
			c.BannerGrab = bg
		}
	}

	if osDetect, ok := config["os_detect"]; ok {
		if od, ok := osDetect.(bool); ok {
			c.OSDetect = od
		}
	}

	return nil
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > 3600 {
		return fmt.Errorf("timeout must be between 1 and 3600 seconds")
	}

	if c.MaxThreads <= 0 || c.MaxThreads > 200 {
		return fmt.Errorf("max_threads must be between 1 and 200")
	}

	if c.TCPTimeout <= 0 || c.TCPTimeout > 30 {
		return fmt.Errorf("tcp_timeout must be between 1 and 30 seconds")
	}

	if c.UDPTimeout <= 0 || c.UDPTimeout > 30 {
		return fmt.Errorf("udp_timeout must be between 1 and 30 seconds")
	}

	if len(c.Ports) == 0 {
		return fmt.Errorf("at least one port must be specified")
	}

	// Validate port ranges
	for _, port := range c.Ports {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("port %d is invalid, must be between 1 and 65535", port)
		}
	}

	return nil
}

// GetPortList returns the list of ports to scan
func (c *Config) GetPortList() []int {
	if len(c.Ports) > 0 {
		return c.Ports
	}
	// Return default ports if none specified
	return NewDefaultConfig().Ports
}

// IsServiceScanEnabled returns true if service scanning is enabled
func (c *Config) IsServiceScanEnabled() bool {
	return c.ServiceScan
}

// IsBannerGrabEnabled returns true if banner grabbing is enabled
func (c *Config) IsBannerGrabEnabled() bool {
	return c.BannerGrab
}

// IsOSDetectionEnabled returns true if OS detection is enabled
func (c *Config) IsOSDetectionEnabled() bool {
	return c.OSDetect
}

// IsPingCheckEnabled returns true if ping check is enabled
func (c *Config) IsPingCheckEnabled() bool {
	return c.PingCheck
}

// GetTimeoutDuration returns the timeout as a time.Duration
func (c *Config) GetTimeoutDuration() int {
	return c.Timeout
}

// GetTCPTimeoutDuration returns the TCP timeout as a time.Duration
func (c *Config) GetTCPTimeoutDuration() int {
	return c.TCPTimeout
}

// GetUDPTimeoutDuration returns the UDP timeout as a time.Duration
func (c *Config) GetUDPTimeoutDuration() int {
	return c.UDPTimeout
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	clone := *c
	clone.Ports = make([]int, len(c.Ports))
	copy(clone.Ports, c.Ports)
	return &clone
}
