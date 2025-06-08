package commands

import (
	"github.com/riadh-benchouche/security-audit-tool/internal/domain/entities"
)

// StartScanCommand represents the command to start a scan
type StartScanCommand struct {
	Target    string                 `json:"target" validate:"required"`
	Modules   []string               `json:"modules" validate:"required,min=1"`
	CreatedBy string                 `json:"created_by"`
	Options   map[string]interface{} `json:"options"`
}

// StartScanResult represents the result of starting a scan
type StartScanResult struct {
	Scan    *entities.Scan `json:"scan"`
	ScanID  string         `json:"scan_id"`
	Status  string         `json:"status"`
	Message string         `json:"message,omitempty"`
}
