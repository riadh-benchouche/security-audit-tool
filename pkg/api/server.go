package api

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/riadh-benchouche/security-audit-tool/pkg/core"
	"github.com/riadh-benchouche/security-audit-tool/pkg/models"
	"github.com/riadh-benchouche/security-audit-tool/pkg/scanner"
)

// Server représente le serveur web de l'application
type Server struct {
	app     *fiber.App
	logger  *core.StructuredLogger
	scanner *scanner.Manager
}

// APIResponse représente une réponse API standardisée
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ScanRequest représente une demande de scan
type ScanRequest struct {
	Target  string                 `json:"target" validate:"required"`
	Modules []string               `json:"modules" validate:"required"`
	Options map[string]interface{} `json:"options,omitempty"`
}

// NewServer crée une nouvelle instance du serveur
func NewServer() *Server {
	// Configuration Fiber
	app := fiber.New(fiber.Config{
		AppName:               "Security Audit Tool API v1.0",
		ServerHeader:          "SecurityAudit",
		DisableStartupMessage: false,
		ErrorHandler:          errorHandler,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
	})

	logger := core.NewStructuredLogger("api-server")
	scanManager := scanner.NewManager()

	server := &Server{
		app:     app,
		logger:  logger,
		scanner: scanManager,
	}

	// Configuration des middlewares
	server.setupMiddlewares()

	// Configuration des routes
	server.setupRoutes()

	return server
}

// setupMiddlewares configure les middlewares Fiber
func (s *Server) setupMiddlewares() {
	// Logger middleware
	s.app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error}\n",
		TimeFormat: "15:04:05",
		TimeZone:   "Local",
	}))

	// Recover middleware pour gérer les panics
	s.app.Use(recover.New())

	// Helmet pour la sécurité des headers
	s.app.Use(helmet.New(helmet.Config{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         31536000,
		ReferrerPolicy:     "strict-origin-when-cross-origin",
	}))

	// CORS
	s.app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	// Rate limiting
	s.app.Use(limiter.New(limiter.Config{
		Max:        100, // 100 requêtes par minute
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.Get("x-forwarded-for", c.IP())
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(429).JSON(APIResponse{
				Success: false,
				Error:   "Rate limit exceeded. Please try again later.",
			})
		},
	}))
}

// setupRoutes configure les routes de l'API
func (s *Server) setupRoutes() {
	// Route de base
	s.app.Get("/", s.handleRoot)

	// Routes de l'API v1
	api := s.app.Group("/api/v1")

	// Health check
	api.Get("/health", s.handleHealth)

	// Routes de scan
	scans := api.Group("/scans")
	scans.Post("/", s.handleStartScan)
	scans.Get("/:id", s.handleGetScan)
	scans.Get("/", s.handleListScans)

	// Routes des modules
	modules := api.Group("/modules")
	modules.Get("/", s.handleListModules)
	modules.Get("/:name", s.handleGetModule)

	// Routes des rapports
	reports := api.Group("/reports")
	reports.Get("/:id", s.handleGetReport)
	reports.Get("/:id/download", s.handleDownloadReport)

	// Servir les fichiers statiques (frontend)
	s.app.Static("/", "./web/static")

	// Fallback pour SPA (Single Page Application)
	s.app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendFile("./web/static/index.html")
	})
}

// Start démarre le serveur sur le port spécifié
func (s *Server) Start(addr string) error {
	s.logger.Infof("Démarrage du serveur sur %s", addr)
	return s.app.Listen(addr)
}

// Shutdown arrête proprement le serveur
func (s *Server) Shutdown() error {
	s.logger.Info("Arrêt du serveur...")
	return s.app.Shutdown()
}

// Handlers

// handleRoot gère la route racine
func (s *Server) handleRoot(c *fiber.Ctx) error {
	return c.JSON(APIResponse{
		Success: true,
		Message: "Security Audit Tool API",
		Data: map[string]interface{}{
			"version": "1.0.0",
			"status":  "running",
			"time":    time.Now().UTC(),
		},
	})
}

// handleHealth gère le health check
func (s *Server) handleHealth(c *fiber.Ctx) error {
	return c.JSON(APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"uptime":    time.Since(time.Now()).String(), // À implémenter proprement
		},
	})
}

// handleStartScan gère le démarrage d'un nouveau scan
func (s *Server) handleStartScan(c *fiber.Ctx) error {
	var req ScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(APIResponse{
			Success: false,
			Error:   "Invalid request body",
		})
	}

	// Validation basique
	if req.Target == "" {
		return c.Status(400).JSON(APIResponse{
			Success: false,
			Error:   "Target is required",
		})
	}

	if len(req.Modules) == 0 {
		req.Modules = []string{"network"} // Module par défaut
	}

	s.logger.WithFields(map[string]interface{}{
		"target":  req.Target,
		"modules": req.Modules,
	}).Info("Démarrage d'un nouveau scan")

	// Configurer le scanner
	for _, module := range req.Modules {
		switch module {
		case "network":
			s.scanner.AddScanner(scanner.NewNetworkScanner())
		case "http":
			s.scanner.AddScanner(scanner.NewHTTPScanner())
		default:
			s.logger.Warnf("Module inconnu ignoré: %s", module)
		}
	}

	// Lancer le scan (pour l'instant synchrone, à améliorer avec des jobs async)
	results, err := s.scanner.Scan(req.Target)
	if err != nil {
		s.logger.Errorf("Erreur lors du scan: %v", err)
		return c.Status(500).JSON(APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Scan failed: %v", err),
		})
	}

	return c.JSON(APIResponse{
		Success: true,
		Message: "Scan completed successfully",
		Data:    results,
	})
}

// handleGetScan récupère les résultats d'un scan spécifique
func (s *Server) handleGetScan(c *fiber.Ctx) error {
	scanID := c.Params("id")

	// TODO: Implémenter la récupération depuis une base de données ou cache
	return c.Status(501).JSON(APIResponse{
		Success: false,
		Error:   fmt.Sprintf("Scan retrieval not yet implemented for ID: %s", scanID),
	})
}

// handleListScans liste tous les scans
func (s *Server) handleListScans(c *fiber.Ctx) error {
	// TODO: Implémenter la liste des scans depuis une base de données
	return c.JSON(APIResponse{
		Success: true,
		Data:    []models.ScanResult{}, // Liste vide pour l'instant
	})
}

// handleListModules liste les modules disponibles
func (s *Server) handleListModules(c *fiber.Ctx) error {
	modules := []map[string]interface{}{
		{
			"name":        "network",
			"description": "Network port scanning and service detection",
			"version":     "1.0.0",
			"enabled":     true,
		},
		{
			"name":        "http",
			"description": "HTTP security headers and SSL analysis",
			"version":     "1.0.0",
			"enabled":     true,
		},
		{
			"name":        "ssl",
			"description": "SSL/TLS certificate and configuration analysis",
			"version":     "1.0.0",
			"enabled":     false, // Pas encore implémenté
		},
	}

	return c.JSON(APIResponse{
		Success: true,
		Data:    modules,
	})
}

// handleGetModule récupère les informations d'un module spécifique
func (s *Server) handleGetModule(c *fiber.Ctx) error {
	moduleName := c.Params("name")

	// TODO: Implémenter la récupération des détails du module
	return c.JSON(APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"name":        moduleName,
			"description": "Module details not yet implemented",
		},
	})
}

// handleGetReport récupère un rapport de scan
func (s *Server) handleGetReport(c *fiber.Ctx) error {
	reportID := c.Params("id")

	// TODO: Implémenter la génération/récupération de rapport
	return c.Status(501).JSON(APIResponse{
		Success: false,
		Error:   fmt.Sprintf("Report generation not yet implemented for ID: %s", reportID),
	})
}

// handleDownloadReport télécharge un rapport au format spécifié
func (s *Server) handleDownloadReport(c *fiber.Ctx) error {
	reportID := c.Params("id")
	format := c.Query("format", "json")

	// TODO: Implémenter le téléchargement de rapport
	return c.Status(501).JSON(APIResponse{
		Success: false,
		Error:   fmt.Sprintf("Report download not yet implemented for ID: %s, format: %s", reportID, format),
	})
}

// errorHandler gère les erreurs globales
func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		message = e.Message
	}

	return c.Status(code).JSON(APIResponse{
		Success: false,
		Error:   message,
	})
}
