package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/riadh-benchouche/security-audit-tool/pkg/core"
	"github.com/riadh-benchouche/security-audit-tool/pkg/models"
)

// HTTPScanner implémente le scanner HTTP
type HTTPScanner struct {
	logger       *core.StructuredLogger
	timeout      time.Duration
	userAgent    string
	maxRedirects int
	client       *http.Client
}

// NewHTTPScanner crée une nouvelle instance du scanner HTTP
func NewHTTPScanner() *HTTPScanner {
	scanner := &HTTPScanner{
		logger:       core.NewStructuredLogger("http-scanner"),
		timeout:      30 * time.Second,
		userAgent:    "SecurityAuditTool/1.0",
		maxRedirects: 5,
	}

	// Configuration du client HTTP
	scanner.client = &http.Client{
		Timeout: scanner.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Pour pouvoir analyser les certificats invalides
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= scanner.maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return scanner
}

// Name retourne le nom du scanner
func (hs *HTTPScanner) Name() string {
	return "http"
}

// Description retourne la description du scanner
func (hs *HTTPScanner) Description() string {
	return "HTTP security headers and SSL/TLS analysis"
}

// Configure configure le scanner avec les options données
func (hs *HTTPScanner) Configure(config map[string]interface{}) error {
	if timeout, ok := config["timeout"]; ok {
		if t, ok := timeout.(int); ok {
			hs.timeout = time.Duration(t) * time.Second
			hs.client.Timeout = hs.timeout
		}
	}

	if userAgent, ok := config["user_agent"]; ok {
		if ua, ok := userAgent.(string); ok {
			hs.userAgent = ua
		}
	}

	if maxRedirects, ok := config["max_redirects"]; ok {
		if mr, ok := maxRedirects.(int); ok {
			hs.maxRedirects = mr
		}
	}

	return nil
}

// Scan exécute le scan HTTP sur la cible
func (hs *HTTPScanner) Scan(target string) (*models.ModuleResult, error) {
	startTime := time.Now()

	result := &models.ModuleResult{
		Module:    hs.Name(),
		Status:    models.StatusRunning,
		StartTime: startTime,
		Findings:  make([]models.Finding, 0),
		Errors:    make([]string, 0),
		Metadata:  make(map[string]interface{}),
	}

	hs.logger.Infof("Démarrage du scan HTTP pour: %s", target)

	// Normaliser l'URL
	targetURL, err := hs.normalizeURL(target)
	if err != nil {
		result.Status = models.StatusFailed
		result.AddError(fmt.Sprintf("URL invalide: %v", err))
		result.EndTime = time.Now()
		return result, err
	}

	hs.logger.Infof("URL normalisée: %s", targetURL)

	// Effectuer la requête HTTP
	httpResult, err := hs.performHTTPRequest(targetURL)
	if err != nil {
		result.AddError(fmt.Sprintf("Erreur lors de la requête HTTP: %v", err))
		// Continuer l'analyse même en cas d'erreur
	}

	// Analyser les résultats
	if httpResult != nil {
		hs.analyzeHTTPResponse(result, httpResult, targetURL)
	}

	// Finaliser le résultat
	result.Status = models.StatusCompleted
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Ajouter les métadonnées
	if httpResult != nil {
		result.Metadata["status_code"] = httpResult.StatusCode
		result.Metadata["response_time"] = httpResult.ResponseTime.Milliseconds()
		result.Metadata["url"] = httpResult.URL
	}

	hs.logger.Infof("Scan HTTP terminé pour %s", target)

	return result, nil
}

// normalizeURL normalise l'URL cible
func (hs *HTTPScanner) normalizeURL(target string) (string, error) {
	// Si l'URL ne commence pas par http:// ou https://, ajouter https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// Valider l'URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("URL invalide: %w", err)
	}

	if parsedURL.Host == "" {
		return "", fmt.Errorf("host manquant dans l'URL")
	}

	return target, nil
}

// performHTTPRequest effectue une requête HTTP et retourne les résultats
func (hs *HTTPScanner) performHTTPRequest(targetURL string) (*models.HTTPResult, error) {
	start := time.Now()

	// Créer la requête
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la création de la requête: %w", err)
	}

	// Ajouter les headers
	req.Header.Set("User-Agent", hs.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "close")

	// Effectuer la requête
	resp, err := hs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la requête: %w", err)
	}
	defer resp.Body.Close()

	responseTime := time.Since(start)

	// Lire le contenu de la réponse (limité pour éviter les gros fichiers)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limite à 1MB
	if err != nil {
		hs.logger.Warnf("Erreur lors de la lecture du body: %v", err)
	}

	// Extraire le titre de la page
	title := hs.extractTitle(string(body))

	// Analyser les technologies
	technologies := hs.detectTechnologies(resp.Header, string(body))

	// Analyser SSL si HTTPS
	var sslResult *models.SSLResult
	if strings.HasPrefix(targetURL, "https://") {
		sslResult = hs.analyzeSSL(resp.TLS)
	}

	// Analyser les headers de sécurité
	securityHeaders := hs.analyzeSecurityHeaders(resp.Header)

	// Construire le résultat HTTP
	httpResult := &models.HTTPResult{
		URL:          targetURL,
		StatusCode:   resp.StatusCode,
		Headers:      hs.convertHeaders(resp.Header),
		Title:        title,
		Server:       resp.Header.Get("Server"),
		Technologies: technologies,
		SSL:          sslResult,
		Security:     securityHeaders,
		ResponseTime: responseTime,
	}

	return httpResult, nil
}

// extractTitle extrait le titre de la page HTML
func (hs *HTTPScanner) extractTitle(body string) string {
	titleRegex := regexp.MustCompile(`<title[^>]*>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Nettoyer le titre (enlever les caractères de contrôle)
		title = strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 || r > 127 {
				return r
			}
			return -1
		}, title)
		return title
	}
	return ""
}

// detectTechnologies détecte les technologies utilisées
func (hs *HTTPScanner) detectTechnologies(headers http.Header, body string) []models.Technology {
	technologies := make([]models.Technology, 0)

	// Détection basée sur les headers
	if server := headers.Get("Server"); server != "" {
		tech := hs.parseServerHeader(server)
		if tech != nil {
			technologies = append(technologies, *tech)
		}
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		technologies = append(technologies, models.Technology{
			Name:       powered,
			Categories: []string{"Web Server Extension"},
		})
	}

	// Détection basée sur le contenu
	bodyTech := hs.detectTechnologiesFromBody(body)
	technologies = append(technologies, bodyTech...)

	return technologies
}

// parseServerHeader analyse le header Server
func (hs *HTTPScanner) parseServerHeader(server string) *models.Technology {
	server = strings.ToLower(server)

	switch {
	case strings.Contains(server, "nginx"):
		return &models.Technology{
			Name:       "Nginx",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "apache"):
		return &models.Technology{
			Name:       "Apache",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "iis"):
		return &models.Technology{
			Name:       "Microsoft IIS",
			Categories: []string{"Web Server"},
		}
	case strings.Contains(server, "cloudflare"):
		return &models.Technology{
			Name:       "Cloudflare",
			Categories: []string{"CDN", "Security"},
		}
	default:
		return &models.Technology{
			Name:       server,
			Categories: []string{"Web Server"},
		}
	}
}

// detectTechnologiesFromBody détecte les technologies depuis le contenu
func (hs *HTTPScanner) detectTechnologiesFromBody(body string) []models.Technology {
	technologies := make([]models.Technology, 0)
	bodyLower := strings.ToLower(body)

	// Détections communes
	detections := map[string]models.Technology{
		"wordpress":  {Name: "WordPress", Categories: []string{"CMS"}},
		"wp-content": {Name: "WordPress", Categories: []string{"CMS"}},
		"drupal":     {Name: "Drupal", Categories: []string{"CMS"}},
		"joomla":     {Name: "Joomla", Categories: []string{"CMS"}},
		"react":      {Name: "React", Categories: []string{"JavaScript Framework"}},
		"angular":    {Name: "Angular", Categories: []string{"JavaScript Framework"}},
		"vue.js":     {Name: "Vue.js", Categories: []string{"JavaScript Framework"}},
		"jquery":     {Name: "jQuery", Categories: []string{"JavaScript Library"}},
		"bootstrap":  {Name: "Bootstrap", Categories: []string{"CSS Framework"}},
	}

	for pattern, tech := range detections {
		if strings.Contains(bodyLower, pattern) {
			technologies = append(technologies, tech)
		}
	}

	return technologies
}

// analyzeSSL analyse la configuration SSL/TLS
func (hs *HTTPScanner) analyzeSSL(tlsState *tls.ConnectionState) *models.SSLResult {
	if tlsState == nil {
		return nil
	}

	sslResult := &models.SSLResult{
		Enabled:         true,
		Version:         hs.getTLSVersionString(tlsState.Version),
		Protocols:       []string{hs.getTLSVersionString(tlsState.Version)},
		Vulnerabilities: make([]string, 0),
	}

	// Analyser le certificat
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		sslResult.Certificate = &models.Certificate{
			Subject:        cert.Subject.String(),
			Issuer:         cert.Issuer.String(),
			SerialNumber:   cert.SerialNumber.String(),
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			IsExpired:      time.Now().After(cert.NotAfter),
			IsCA:           cert.IsCA,
			KeySize:        hs.getKeySize(cert),
			SignatureAlg:   cert.SignatureAlgorithm.String(),
			DNSNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
	}

	// Vérifier les vulnérabilités
	if tlsState.Version < tls.VersionTLS12 {
		sslResult.Vulnerabilities = append(sslResult.Vulnerabilities, "Outdated TLS version")
	}

	// Calculer une note simple
	sslResult.Grade = hs.calculateSSLGrade(sslResult)

	return sslResult
}

// getTLSVersionString convertit la version TLS en string
func (hs *HTTPScanner) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

// getKeySize extrait la taille de clé du certificat
func (hs *HTTPScanner) getKeySize(cert *x509.Certificate) int {
	// Simplification - dans un vrai scanner, on analyserait le type de clé
	return 2048 // Valeur par défaut
}

// calculateSSLGrade calcule une note pour la configuration SSL
func (hs *HTTPScanner) calculateSSLGrade(ssl *models.SSLResult) string {
	score := 100

	// Pénalités
	if len(ssl.Vulnerabilities) > 0 {
		score -= len(ssl.Vulnerabilities) * 20
	}

	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		score -= 50
	}

	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// analyzeSecurityHeaders analyse les headers de sécurité
func (hs *HTTPScanner) analyzeSecurityHeaders(headers http.Header) models.SecurityHeaders {
	security := models.SecurityHeaders{
		Score: 0,
	}

	// Analyser chaque header de sécurité
	security.HSTS = hs.analyzeHSTS(headers.Get("Strict-Transport-Security"))
	security.CSP = hs.analyzeCSP(headers.Get("Content-Security-Policy"))
	security.XFrameOptions = hs.analyzeXFrameOptions(headers.Get("X-Frame-Options"))
	security.XContentTypeOptions = hs.analyzeXContentTypeOptions(headers.Get("X-Content-Type-Options"))
	security.XSSProtection = hs.analyzeXSSProtection(headers.Get("X-XSS-Protection"))
	security.ReferrerPolicy = hs.analyzeReferrerPolicy(headers.Get("Referrer-Policy"))

	// Calculer le score global
	security.Score = hs.calculateSecurityScore(&security)
	security.Grade = hs.calculateSecurityGrade(security.Score)

	return security
}

// analyzeHSTS analyse le header HSTS
func (hs *HTTPScanner) analyzeHSTS(hsts string) *models.Header {
	header := &models.Header{
		Present: hsts != "",
		Value:   hsts,
	}

	if header.Present {
		header.Valid = strings.Contains(hsts, "max-age=")
		header.Score = 20
		if strings.Contains(hsts, "includeSubDomains") {
			header.Score += 5
		}
		if strings.Contains(hsts, "preload") {
			header.Score += 5
		}
	} else {
		header.Issues = []string{"HSTS header missing"}
	}

	return header
}

// analyzeCSP analyse le header CSP
func (hs *HTTPScanner) analyzeCSP(csp string) *models.Header {
	header := &models.Header{
		Present: csp != "",
		Value:   csp,
	}

	if header.Present {
		header.Valid = true
		header.Score = 25
		if strings.Contains(csp, "unsafe-inline") {
			header.Issues = append(header.Issues, "unsafe-inline directive found")
			header.Score -= 10
		}
		if strings.Contains(csp, "unsafe-eval") {
			header.Issues = append(header.Issues, "unsafe-eval directive found")
			header.Score -= 10
		}
	} else {
		header.Issues = []string{"CSP header missing"}
	}

	return header
}

// analyzeXFrameOptions analyse le header X-Frame-Options
func (hs *HTTPScanner) analyzeXFrameOptions(xfo string) *models.Header {
	header := &models.Header{
		Present: xfo != "",
		Value:   xfo,
	}

	if header.Present {
		xfoLower := strings.ToLower(xfo)
		header.Valid = xfoLower == "deny" || xfoLower == "sameorigin" || strings.HasPrefix(xfoLower, "allow-from")
		if header.Valid {
			header.Score = 15
		}
	} else {
		header.Issues = []string{"X-Frame-Options header missing"}
	}

	return header
}

// analyzeXContentTypeOptions analyse le header X-Content-Type-Options
func (hs *HTTPScanner) analyzeXContentTypeOptions(xcto string) *models.Header {
	header := &models.Header{
		Present: xcto != "",
		Value:   xcto,
	}

	if header.Present {
		header.Valid = strings.ToLower(xcto) == "nosniff"
		if header.Valid {
			header.Score = 10
		}
	} else {
		header.Issues = []string{"X-Content-Type-Options header missing"}
	}

	return header
}

// analyzeXSSProtection analyse le header X-XSS-Protection
func (hs *HTTPScanner) analyzeXSSProtection(xss string) *models.Header {
	header := &models.Header{
		Present: xss != "",
		Value:   xss,
	}

	if header.Present {
		header.Valid = strings.Contains(xss, "1") && strings.Contains(xss, "mode=block")
		if header.Valid {
			header.Score = 10
		}
	} else {
		header.Issues = []string{"X-XSS-Protection header missing"}
	}

	return header
}

// analyzeReferrerPolicy analyse le header Referrer-Policy
func (hs *HTTPScanner) analyzeReferrerPolicy(rp string) *models.Header {
	header := &models.Header{
		Present: rp != "",
		Value:   rp,
	}

	if header.Present {
		validPolicies := []string{"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
		for _, policy := range validPolicies {
			if strings.Contains(strings.ToLower(rp), policy) {
				header.Valid = true
				header.Score = 10
				break
			}
		}
	} else {
		header.Issues = []string{"Referrer-Policy header missing"}
	}

	return header
}

// calculateSecurityScore calcule le score de sécurité global
func (hs *HTTPScanner) calculateSecurityScore(security *models.SecurityHeaders) int {
	score := 0

	if security.HSTS != nil {
		score += security.HSTS.Score
	}
	if security.CSP != nil {
		score += security.CSP.Score
	}
	if security.XFrameOptions != nil {
		score += security.XFrameOptions.Score
	}
	if security.XContentTypeOptions != nil {
		score += security.XContentTypeOptions.Score
	}
	if security.XSSProtection != nil {
		score += security.XSSProtection.Score
	}
	if security.ReferrerPolicy != nil {
		score += security.ReferrerPolicy.Score
	}

	return score
}

// calculateSecurityGrade calcule la note de sécurité
func (hs *HTTPScanner) calculateSecurityGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// convertHeaders convertit les headers HTTP en map
func (hs *HTTPScanner) convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

// analyzeHTTPResponse analyse la réponse HTTP et crée les findings
func (hs *HTTPScanner) analyzeHTTPResponse(result *models.ModuleResult, httpResult *models.HTTPResult, targetURL string) {
	// Finding pour le statut HTTP
	if httpResult.StatusCode >= 400 {
		severity := models.SeverityMedium
		if httpResult.StatusCode >= 500 {
			severity = models.SeverityHigh
		}

		result.AddFinding(models.Finding{
			ID:          fmt.Sprintf("http-status-%d", httpResult.StatusCode),
			Type:        models.FindingTypeInformation,
			Severity:    severity,
			Title:       fmt.Sprintf("HTTP %d Response", httpResult.StatusCode),
			Description: fmt.Sprintf("Server returned HTTP %d status code", httpResult.StatusCode),
			Target:      targetURL,
			Evidence: map[string]interface{}{
				"status_code": httpResult.StatusCode,
				"url":         httpResult.URL,
			},
			Timestamp: time.Now(),
		})
	}

	// Findings pour les headers de sécurité manquants
	hs.analyzeSecurityHeadersFindings(result, httpResult, targetURL)

	// Findings pour SSL/TLS
	if httpResult.SSL != nil {
		hs.analyzeSSLFindings(result, httpResult.SSL, targetURL)
	}

	// Findings pour les technologies détectées
	for _, tech := range httpResult.Technologies {
		result.AddFinding(models.Finding{
			ID:          fmt.Sprintf("http-technology-%s", strings.ToLower(tech.Name)),
			Type:        models.FindingTypeInformation,
			Severity:    models.SeverityInfo,
			Title:       fmt.Sprintf("Technology detected: %s", tech.Name),
			Description: fmt.Sprintf("The website uses %s", tech.Name),
			Target:      targetURL,
			Evidence: map[string]interface{}{
				"technology": tech.Name,
				"categories": tech.Categories,
			},
			Tags:      append([]string{"http", "technology"}, tech.Categories...),
			Timestamp: time.Now(),
		})
	}
}

// analyzeSecurityHeadersFindings analyse les headers de sécurité et crée les findings
func (hs *HTTPScanner) analyzeSecurityHeadersFindings(result *models.ModuleResult, httpResult *models.HTTPResult, targetURL string) {
	security := httpResult.Security

	// HSTS manquant
	if security.HSTS != nil && !security.HSTS.Present {
		result.AddFinding(models.Finding{
			ID:          "http-missing-hsts",
			Type:        models.FindingTypeMisconfiguration,
			Severity:    models.SeverityMedium,
			Title:       "Missing HSTS Header",
			Description: "The Strict-Transport-Security header is missing, which could allow downgrade attacks",
			Target:      targetURL,
			Remediation: "Add the Strict-Transport-Security header to enforce HTTPS connections",
			Tags:        []string{"http", "security-headers", "hsts"},
			Timestamp:   time.Now(),
		})
	}

	// CSP manquant
	if security.CSP != nil && !security.CSP.Present {
		result.AddFinding(models.Finding{
			ID:          "http-missing-csp",
			Type:        models.FindingTypeMisconfiguration,
			Severity:    models.SeverityMedium,
			Title:       "Missing Content Security Policy",
			Description: "The Content-Security-Policy header is missing, which could allow XSS attacks",
			Target:      targetURL,
			Remediation: "Implement a Content Security Policy to prevent XSS attacks",
			Tags:        []string{"http", "security-headers", "csp", "xss"},
			Timestamp:   time.Now(),
		})
	}

	// X-Frame-Options manquant
	if security.XFrameOptions != nil && !security.XFrameOptions.Present {
		result.AddFinding(models.Finding{
			ID:          "http-missing-x-frame-options",
			Type:        models.FindingTypeMisconfiguration,
			Severity:    models.SeverityMedium,
			Title:       "Missing X-Frame-Options Header",
			Description: "The X-Frame-Options header is missing, which could allow clickjacking attacks",
			Target:      targetURL,
			Remediation: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
			Tags:        []string{"http", "security-headers", "clickjacking"},
			Timestamp:   time.Now(),
		})
	}
}

// analyzeSSLFindings analyse SSL/TLS et crée les findings
func (hs *HTTPScanner) analyzeSSLFindings(result *models.ModuleResult, ssl *models.SSLResult, targetURL string) {
	// Certificat expiré
	if ssl.Certificate != nil && ssl.Certificate.IsExpired {
		result.AddFinding(models.Finding{
			ID:          "ssl-expired-certificate",
			Type:        models.FindingTypeVulnerability,
			Severity:    models.SeverityHigh,
			Title:       "Expired SSL Certificate",
			Description: fmt.Sprintf("The SSL certificate expired on %s", ssl.Certificate.NotAfter.Format("2006-01-02")),
			Target:      targetURL,
			Evidence: map[string]interface{}{
				"not_after": ssl.Certificate.NotAfter,
				"subject":   ssl.Certificate.Subject,
			},
			Remediation: "Renew the SSL certificate before it expires",
			Tags:        []string{"ssl", "certificate", "expired"},
			Timestamp:   time.Now(),
		})
	}

	// Version TLS obsolète
	for _, vuln := range ssl.Vulnerabilities {
		if strings.Contains(vuln, "Outdated TLS") {
			result.AddFinding(models.Finding{
				ID:          "ssl-outdated-tls",
				Type:        models.FindingTypeVulnerability,
				Severity:    models.SeverityMedium,
				Title:       "Outdated TLS Version",
				Description: "The server supports outdated TLS versions that may be vulnerable",
				Target:      targetURL,
				Evidence: map[string]interface{}{
					"tls_version": ssl.Version,
				},
				Remediation: "Disable TLS 1.0 and 1.1, use TLS 1.2 or higher",
				Tags:        []string{"ssl", "tls", "outdated"},
				Timestamp:   time.Now(),
			})
		}
	}
}
