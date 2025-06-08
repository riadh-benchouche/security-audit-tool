package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
	"github.com/riadh-benchouche/security-audit-tool/pkg/errors"
)

// bannerGrabber implements the BannerGrabber interface
type bannerGrabber struct {
	config    *Config
	isHealthy bool
	mu        sync.RWMutex
	probes    map[int][]string
}

// NewBannerGrabber creates a new banner grabber instance
func NewBannerGrabber() BannerGrabber {
	bg := &bannerGrabber{
		isHealthy: true,
		probes:    make(map[int][]string),
	}

	bg.initializeProbes()
	return bg
}

// Configure sets up the banner grabber with provided configuration
func (bg *bannerGrabber) Configure(config *Config) error {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	bg.config = config
	return nil
}

// GrabBanner grabs banner from the specified port
func (bg *bannerGrabber) GrabBanner(ctx context.Context, target *entities.Target, port int) (string, error) {
	bg.mu.RLock()
	config := bg.config
	probes := bg.probes[port]
	bg.mu.RUnlock()

	if config == nil {
		return "", errors.NewScannerError("banner-grabber", "grab", fmt.Errorf("banner grabber not configured"))
	}

	timeout := time.Duration(config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", errors.NewNetworkError("banner grab", address, err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetWriteDeadline(time.Now().Add(timeout))

	// Try different probes for the specific port
	for _, probe := range probes {
		banner, err := bg.sendProbeAndRead(conn, probe)
		if err == nil && banner != "" {
			return banner, nil
		}

		// Reset connection timeout for next probe
		conn.SetReadDeadline(time.Now().Add(timeout))
	}

	// Try generic probes if port-specific ones didn't work
	if genericProbes, exists := bg.probes[0]; exists {
		for _, probe := range genericProbes {
			banner, err := bg.sendProbeAndRead(conn, probe)
			if err == nil && banner != "" {
				return banner, nil
			}

			// Reset connection timeout for next probe
			conn.SetReadDeadline(time.Now().Add(timeout))
		}
	}

	// Try just reading without sending anything (for services that send banners immediately)
	banner, err := bg.readBanner(conn)
	if err == nil && banner != "" {
		return banner, nil
	}

	return "", errors.NewScannerError("banner-grabber", "grab", fmt.Errorf("no banner received from %s", address))
}

// sendProbeAndRead sends a probe and reads the response
func (bg *bannerGrabber) sendProbeAndRead(conn net.Conn, probe string) (string, error) {
	if probe != "" {
		_, err := conn.Write([]byte(probe))
		if err != nil {
			return "", err
		}
	}

	return bg.readBanner(conn)
}

// readBanner reads banner from the connection
func (bg *bannerGrabber) readBanner(conn net.Conn) (string, error) {
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	// Clean up the banner (remove control characters, etc.)
	banner = bg.cleanBanner(banner)

	return banner, nil
}

// cleanBanner cleans up the banner text
func (bg *bannerGrabber) cleanBanner(banner string) string {
	// Remove null bytes and other control characters
	banner = strings.ReplaceAll(banner, "\x00", "")

	// Replace multiple whitespaces with single space
	lines := strings.Split(banner, "\n")
	var cleanLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			cleanLines = append(cleanLines, line)
		}
	}

	return strings.Join(cleanLines, " ")
}

// initializeProbes initializes probes for different services
func (bg *bannerGrabber) initializeProbes() {
	// HTTP probes
	bg.probes[80] = []string{
		"GET / HTTP/1.0\r\n\r\n",
		"HEAD / HTTP/1.0\r\n\r\n",
		"OPTIONS / HTTP/1.0\r\n\r\n",
	}

	// HTTPS probes (same as HTTP)
	bg.probes[443] = bg.probes[80]

	// FTP probes
	bg.probes[21] = []string{
		"HELP\r\n",
		"SYST\r\n",
		"FEAT\r\n",
		"", // FTP usually sends banner immediately
	}

	// SSH probes
	bg.probes[22] = []string{
		"", // SSH sends banner immediately
		"SSH-2.0-Test\r\n",
	}

	// Telnet probes
	bg.probes[23] = []string{
		"", // Telnet usually sends banner immediately
		"\r\n",
		"\n",
	}

	// SMTP probes
	bg.probes[25] = []string{
		"", // SMTP sends banner immediately
		"EHLO test\r\n",
		"HELO test\r\n",
	}

	// DNS probes (TCP)
	bg.probes[53] = []string{
		"", // Try reading banner first
	}

	// POP3 probes
	bg.probes[110] = []string{
		"", // POP3 sends banner immediately
		"CAPA\r\n",
		"HELP\r\n",
	}

	// IMAP probes
	bg.probes[143] = []string{
		"", // IMAP sends banner immediately
		"A001 CAPABILITY\r\n",
	}

	// HTTPS Alt probes
	bg.probes[8080] = bg.probes[80]
	bg.probes[8443] = bg.probes[80]

	// IMAPS probes
	bg.probes[993] = []string{
		"", // IMAPS sends banner immediately after TLS handshake
	}

	// POP3S probes
	bg.probes[995] = []string{
		"", // POP3S sends banner immediately after TLS handshake
	}

	// MSSQL probes
	bg.probes[1433] = []string{
		"", // Try reading banner first
	}

	// MySQL probes
	bg.probes[3306] = []string{
		"", // MySQL sends banner immediately
	}

	// RDP probes
	bg.probes[3389] = []string{
		"", // Try reading banner first
	}

	// PostgreSQL probes
	bg.probes[5432] = []string{
		"", // Try reading banner first
	}

	// VNC probes
	bg.probes[5900] = []string{
		"", // VNC sends banner immediately
	}

	// Generic probes (applied to all ports if specific probes fail)
	bg.probes[0] = []string{
		"", // Try reading without sending anything first
		"\r\n",
		"\n",
		"HELP\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"QUIT\r\n",
	}
}

// Stop stops the banner grabber
func (bg *bannerGrabber) Stop() {
	// Implementation for stopping ongoing banner grabs
	bg.mu.Lock()
	defer bg.mu.Unlock()
	// Set a stop flag if needed
}

// IsHealthy returns the health status of the banner grabber
func (bg *bannerGrabber) IsHealthy() bool {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	return bg.isHealthy
}
