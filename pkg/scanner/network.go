package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/pkg/core"
	"github.com/riadh-benchouche/security-audit-tool/pkg/models"
)

// NetworkScanner implémente le scanner réseau
type NetworkScanner struct {
	logger  *core.StructuredLogger
	timeout time.Duration
	threads int
	ports   []int
}

// NewNetworkScanner crée une nouvelle instance du scanner réseau
func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		logger:  core.NewStructuredLogger("network-scanner"),
		timeout: 5 * time.Second,
		threads: 50,
		ports: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
			1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 9300,
		},
	}
}

// Name retourne le nom du scanner
func (ns *NetworkScanner) Name() string {
	return "network"
}

// Description retourne la description du scanner
func (ns *NetworkScanner) Description() string {
	return "Network port scanning and service detection"
}

// Configure configure le scanner avec les options données
func (ns *NetworkScanner) Configure(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok {
			ns.timeout = time.Duration(t) * time.Second
		}
	}

	if threads, ok := config["threads"]; ok {
		if t, ok := threads.(int); ok {
			ns.threads = t
		}
	}

	if ports, ok := config["ports"]; ok {
		if p, ok := ports.([]int); ok {
			ns.ports = p
		}
	}

	return nil
}

// Scan exécute le scan réseau sur la cible
func (ns *NetworkScanner) Scan(target string) (*models.ModuleResult, error) {
	startTime := time.Now()

	result := &models.ModuleResult{
		Module:    ns.Name(),
		Status:    models.StatusRunning,
		StartTime: startTime,
		Findings:  make([]models.Finding, 0),
		Errors:    make([]string, 0),
		Metadata:  make(map[string]interface{}),
	}

	ns.logger.Infof("Démarrage du scan réseau pour: %s", target)

	// Résoudre l'IP de la cible
	ip, err := ns.resolveTarget(target)
	if err != nil {
		result.Status = models.StatusFailed
		result.AddError(fmt.Sprintf("Impossible de résoudre la cible: %v", err))
		result.EndTime = time.Now()
		return result, err
	}

	ns.logger.Infof("Cible résolue: %s -> %s", target, ip)

	// Test de connectivité (ping)
	pingResult := ns.ping(ip)

	// Scan des ports
	networkResult, err := ns.scanPorts(ip)
	if err != nil {
		result.AddError(fmt.Sprintf("Erreur lors du scan de ports: %v", err))
	}

	// Analyser les résultats et créer les findings
	ns.analyzeResults(result, networkResult, pingResult, target, ip)

	// Finaliser le résultat
	result.Status = models.StatusCompleted
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Ajouter les métadonnées
	result.Metadata["target_ip"] = ip
	result.Metadata["ports_scanned"] = len(ns.ports)
	result.Metadata["open_ports"] = len(networkResult.Ports)
	result.Metadata["ping_alive"] = pingResult.Alive

	ns.logger.Infof("Scan réseau terminé pour %s: %d ports ouverts trouvés",
		target, len(networkResult.Ports))

	return result, nil
}

// resolveTarget résout le nom d'hôte en adresse IP
func (ns *NetworkScanner) resolveTarget(target string) (string, error) {
	// Si c'est déjà une IP, la retourner directement
	if net.ParseIP(target) != nil {
		return target, nil
	}

	// Résoudre le nom d'hôte
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Errorf("impossible de résoudre %s: %w", target, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("aucune IP trouvée pour %s", target)
	}

	// Retourner la première IP IPv4 trouvée
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Si aucune IPv4, retourner la première IP
	return ips[0].String(), nil
}

// ping teste la connectivité avec la cible
func (ns *NetworkScanner) ping(ip string) *models.PingResult {
	start := time.Now()

	// Test de connectivité simple via TCP sur port commun
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), ns.timeout)
	if err != nil {
		// Essayer le port 443
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), ns.timeout)
		if err != nil {
			return &models.PingResult{
				Alive:  false,
				Method: "tcp",
				Error:  err.Error(),
			}
		}
	}

	if conn != nil {
		conn.Close()
		rtt := time.Since(start)
		return &models.PingResult{
			Alive:  true,
			RTT:    rtt,
			Method: "tcp",
		}
	}

	return &models.PingResult{
		Alive:  false,
		Method: "tcp",
		Error:  "no response",
	}
}

// scanPorts scanne les ports spécifiés
func (ns *NetworkScanner) scanPorts(ip string) (*models.NetworkResult, error) {
	result := &models.NetworkResult{
		Host:     ip,
		IP:       ip,
		Ports:    make([]models.PortResult, 0),
		Services: make([]models.Service, 0),
	}

	// Canal pour les résultats
	portChan := make(chan models.PortResult, len(ns.ports))

	// Limiter le nombre de goroutines concurrentes
	semaphore := make(chan struct{}, ns.threads)
	var wg sync.WaitGroup

	for _, port := range ns.ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquérir le sémaphore
			defer func() { <-semaphore }() // Libérer le sémaphore

			portResult := ns.scanPort(ip, p)
			if portResult.State == models.PortStateOpen {
				portChan <- portResult
			}
		}(port)
	}

	// Attendre que tous les scans se terminent
	go func() {
		wg.Wait()
		close(portChan)
	}()

	// Collecter les résultats
	for portResult := range portChan {
		result.Ports = append(result.Ports, portResult)
		if portResult.Service != nil {
			result.Services = append(result.Services, *portResult.Service)
		}
	}

	return result, nil
}

// scanPort scanne un port spécifique
func (ns *NetworkScanner) scanPort(ip string, port int) models.PortResult {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, ns.timeout)
	if err != nil {
		return models.PortResult{
			Port:     port,
			Protocol: "tcp",
			State:    models.PortStateClosed,
		}
	}

	defer conn.Close()

	// Port ouvert, essayer de détecter le service
	service := ns.detectService(conn, port)
	banner := ns.grabBanner(conn)

	return models.PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    models.PortStateOpen,
		Service:  service,
		Banner:   banner,
	}
}

// detectService tente de détecter le service sur un port
func (ns *NetworkScanner) detectService(conn net.Conn, port int) *models.Service {
	serviceName := ns.getCommonService(port)

	if serviceName != "" {
		return &models.Service{
			Name:   serviceName,
			Method: "port-based",
			Conf:   50, // Confiance moyenne pour la détection basée sur le port
		}
	}

	return nil
}

// grabBanner tente de récupérer la bannière du service
func (ns *NetworkScanner) grabBanner(conn net.Conn) string {
	// Définir un timeout pour la lecture de la bannière
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	// Nettoyer la bannière (enlever les caractères non imprimables)
	banner = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, banner)

	return banner
}

// getCommonService retourne le nom du service commun pour un port donné
func (ns *NetworkScanner) getCommonService(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		1723: "pptp",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-proxy",
		8443: "https-alt",
		9200: "elasticsearch",
		9300: "elasticsearch",
	}

	return services[port]
}

// analyzeResults analyse les résultats et crée les findings
func (ns *NetworkScanner) analyzeResults(result *models.ModuleResult, networkResult *models.NetworkResult,
	pingResult *models.PingResult, target, ip string) {

	// Finding pour la connectivité
	if pingResult.Alive {
		result.AddFinding(models.Finding{
			ID:          fmt.Sprintf("network-connectivity-%s", ip),
			Type:        models.FindingTypeInformation,
			Severity:    models.SeverityInfo,
			Title:       "Host is alive",
			Description: fmt.Sprintf("Target %s (%s) is reachable", target, ip),
			Target:      target,
			Evidence: map[string]interface{}{
				"ip":     ip,
				"method": pingResult.Method,
				"rtt":    pingResult.RTT.String(),
			},
			Timestamp: time.Now(),
		})
	}

	// Findings pour les ports ouverts
	for _, port := range networkResult.Ports {
		severity := models.SeverityInfo
		title := fmt.Sprintf("Open port %d/%s", port.Port, port.Protocol)
		description := fmt.Sprintf("Port %d is open", port.Port)

		// Ajuster la sévérité selon le service
		if port.Service != nil {
			switch port.Service.Name {
			case "telnet", "ftp", "rsh", "rlogin":
				severity = models.SeverityHigh
				description += " (insecure service)"
			case "ssh", "rdp", "vnc":
				severity = models.SeverityMedium
				description += " (remote access service)"
			case "http", "https":
				severity = models.SeverityInfo
				description += " (web service)"
			}
		}

		evidence := map[string]interface{}{
			"port":     port.Port,
			"protocol": port.Protocol,
			"state":    port.State,
		}

		if port.Service != nil {
			evidence["service"] = port.Service.Name
		}

		if port.Banner != "" {
			evidence["banner"] = port.Banner
		}

		result.AddFinding(models.Finding{
			ID:          fmt.Sprintf("network-port-%s-%d", ip, port.Port),
			Type:        models.FindingTypeInformation,
			Severity:    severity,
			Title:       title,
			Description: description,
			Target:      fmt.Sprintf("%s:%d", target, port.Port),
			Evidence:    evidence,
			Tags:        []string{"network", "port-scan", port.Protocol},
			Timestamp:   time.Now(),
		})
	}

	// Findings pour les services à risque
	riskServices := []string{"telnet", "ftp", "rsh", "rlogin", "tftp"}
	for _, port := range networkResult.Ports {
		if port.Service != nil {
			for _, riskService := range riskServices {
				if port.Service.Name == riskService {
					result.AddFinding(models.Finding{
						ID:          fmt.Sprintf("network-insecure-service-%s-%d", ip, port.Port),
						Type:        models.FindingTypeVulnerability,
						Severity:    models.SeverityHigh,
						Title:       fmt.Sprintf("Insecure service detected: %s", riskService),
						Description: fmt.Sprintf("The service %s on port %d is insecure and transmits data in clear text", riskService, port.Port),
						Target:      fmt.Sprintf("%s:%d", target, port.Port),
						Evidence: map[string]interface{}{
							"service": riskService,
							"port":    port.Port,
							"reason":  "clear text protocol",
						},
						Remediation: fmt.Sprintf("Disable %s service and use secure alternatives like SSH", riskService),
						Tags:        []string{"network", "insecure-protocol", "clear-text"},
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
}
