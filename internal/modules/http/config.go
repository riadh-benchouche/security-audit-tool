package http

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Config represents HTTP scanner configuration
type Config struct {
	Timeout         time.Duration `json:"timeout"`
	UserAgent       string        `json:"user_agent"`
	MaxRedirects    int           `json:"max_redirects"`
	FollowRedirects bool          `json:"follow_redirects"`
	InsecureSkipTLS bool          `json:"insecure_skip_tls"`
	MaxResponseSize int64         `json:"max_response_size"`
}

// NewDefaultConfig creates a default HTTP scanner configuration
func NewDefaultConfig() *Config {
	return &Config{
		Timeout:         30 * time.Second,
		UserAgent:       "SecurityAuditTool/2.0",
		MaxRedirects:    5,
		FollowRedirects: true,
		InsecureSkipTLS: true,        // For security analysis
		MaxResponseSize: 1024 * 1024, // 1MB
	}
}

// Update updates the configuration with provided values
func (c *Config) Update(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok {
			if t <= 0 {
				c.Timeout = 30 * time.Second
			} else if t <= 300 {
				c.Timeout = time.Duration(t) * time.Second
			} else {
				return fmt.Errorf("timeout must be between 1 and 300 seconds, got: %v", timeout)
			}
		} else {
			return fmt.Errorf("invalid timeout type: %T, expected int", timeout)
		}
	}

	if userAgent, ok := config["user_agent"]; ok {
		if ua, ok := userAgent.(string); ok {
			if ua != "" {
				c.UserAgent = ua
			}
		} else {
			return fmt.Errorf("invalid user_agent type: %T, expected string", userAgent)
		}
	}

	if maxRedirects, ok := config["max_redirects"]; ok {
		if mr, ok := maxRedirects.(int); ok {
			if mr < 0 {
				c.MaxRedirects = 0
			} else if mr <= 10 {
				c.MaxRedirects = mr
			} else {
				return fmt.Errorf("max_redirects must be between 0 and 10, got: %v", maxRedirects)
			}
		} else {
			return fmt.Errorf("invalid max_redirects type: %T, expected int", maxRedirects)
		}
	}

	if followRedirects, ok := config["follow_redirects"]; ok {
		if fr, ok := followRedirects.(bool); ok {
			c.FollowRedirects = fr
		}
	}

	if insecureSkipTLS, ok := config["insecure_skip_tls"]; ok {
		if ist, ok := insecureSkipTLS.(bool); ok {
			c.InsecureSkipTLS = ist
		}
	}

	if maxResponseSize, ok := config["max_response_size"]; ok {
		if mrs, ok := maxResponseSize.(int); ok {
			if mrs <= 0 {
				c.MaxResponseSize = 1024 * 1024 // 1MB default
			} else if mrs <= 10*1024*1024 { // Max 10MB
				c.MaxResponseSize = int64(mrs)
			} else {
				return fmt.Errorf("max_response_size must be between 1 and 10MB, got: %v", maxResponseSize)
			}
		} else {
			return fmt.Errorf("invalid max_response_size type: %T, expected int", maxResponseSize)
		}
	}

	return nil
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	if c.Timeout <= 0 || c.Timeout > 300*time.Second {
		return fmt.Errorf("timeout must be between 1 and 300 seconds")
	}

	if c.UserAgent == "" {
		return fmt.Errorf("user_agent cannot be empty")
	}

	if c.MaxRedirects < 0 || c.MaxRedirects > 10 {
		return fmt.Errorf("max_redirects must be between 0 and 10")
	}

	if c.MaxResponseSize <= 0 || c.MaxResponseSize > 10*1024*1024 {
		return fmt.Errorf("max_response_size must be between 1 byte and 10MB")
	}

	return nil
}

// CreateHTTPClient creates a configured HTTP client
func (c *Config) CreateHTTPClient() *http.Client {
	client := &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.InsecureSkipTLS,
			},
		},
	}

	// Configure a redirect policy
	if !c.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}

	return client
}

// GetTimeout returns the timeout duration
func (c *Config) GetTimeout() time.Duration {
	return c.Timeout
}

// GetUserAgent returns the user agent string
func (c *Config) GetUserAgent() string {
	return c.UserAgent
}

// GetMaxRedirects returns the maximum number of redirects
func (c *Config) GetMaxRedirects() int {
	return c.MaxRedirects
}

// IsFollowRedirectsEnabled returns true if redirects should be followed
func (c *Config) IsFollowRedirectsEnabled() bool {
	return c.FollowRedirects
}

// IsInsecureSkipTLSEnabled returns true if TLS verification should be skipped
func (c *Config) IsInsecureSkipTLSEnabled() bool {
	return c.InsecureSkipTLS
}

// GetMaxResponseSize returns the maximum response size in bytes
func (c *Config) GetMaxResponseSize() int64 {
	return c.MaxResponseSize
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	clone := *c
	return &clone
}

// String returns a string representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf("HTTPConfig{Timeout:%v, UserAgent:%s, MaxRedirects:%d, FollowRedirects:%v, InsecureSkipTLS:%v, MaxResponseSize:%d}",
		c.Timeout, c.UserAgent, c.MaxRedirects, c.FollowRedirects, c.InsecureSkipTLS, c.MaxResponseSize)
}
