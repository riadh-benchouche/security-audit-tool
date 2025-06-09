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

// GrabBanner grabs banner from the specified port - retourne string comme défini dans l'interface
func (bg *bannerGrabber) GrabBanner(ctx context.Context, target *entities.Target, port int) (string, error) {
	bg.mu.RLock()
	config := bg.config
	probes := bg.probes[port]
	bg.mu.RUnlock()

	if config == nil {
		return "", errors.NewScannerError("banner-grabber", "grab", fmt.Errorf("not configured"))
	}

	timeout := time.Duration(config.TCPTimeout) * time.Second
	address := net.JoinHostPort(target.Host(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", nil // Retourne silencieusement en cas d'échec
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Essayer les sondes spécifiques au port
	for _, probe := range probes {
		if banner := bg.tryProbe(conn, probe); banner != "" {
			return bg.cleanBanner(banner), nil
		}
	}

	// Essayer les sondes génériques
	if genericProbes, exists := bg.probes[0]; exists {
		for _, probe := range genericProbes {
			if banner := bg.tryProbe(conn, probe); banner != "" {
				return bg.cleanBanner(banner), nil
			}
		}
	}

	// Lecture simple sans sonde
	if banner := bg.readBanner(conn); banner != "" {
		return bg.cleanBanner(banner), nil
	}

	return "", nil
}

func (bg *bannerGrabber) tryProbe(conn net.Conn, probe string) string {
	if probe != "" {
		if _, err := conn.Write([]byte(probe)); err != nil {
			return ""
		}
	}
	return bg.readBanner(conn)
}

// GrabBannerResult retourne un BannerResult pour compatibilité avec les nouvelles fonctionnalités
func (bg *bannerGrabber) GrabBannerResult(ctx context.Context, target *entities.Target, port int) (BannerResult, error) {
	banner, err := bg.GrabBanner(ctx, target, port)

	result := BannerResult{
		Port:    port,
		Content: banner,
		Length:  len(banner),
	}

	if err != nil {
		result.Error = err.Error()
	}

	return result, err
}

// sendProbeAndRead sends a probe and reads the response
func (bg *bannerGrabber) sendProbeAndRead(conn net.Conn, probe string) (string, error) {
	if probe != "" {
		_, err := conn.Write([]byte(probe))
		if err != nil {
			return "", err
		}
	}

	return bg.readBanner(conn), nil
}

// readBanner reads banner from the connection
func (bg *bannerGrabber) readBanner(conn net.Conn) string {
	buffer := make([]byte, 2048) // Réduit de 4096 à 2048
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
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

	result := strings.Join(cleanLines, " ")

	// Limit banner length for security
	if len(result) > 500 {
		result = result[:500] + "..."
	}

	return result
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
		"", // FTP usually sends banner immediately
		"HELP\r\n",
		"SYST\r\n",
		"FEAT\r\n",
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
