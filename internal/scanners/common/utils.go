package common

import (
	"net"
	"time"
)

// IsPortOpen vérifie rapidement si un port est ouvert
func IsPortOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, string(rune(port))), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// CleanBanner nettoie une bannière de service
func CleanBanner(banner string) string {
	// Implémentation de nettoyage
	return banner
}
