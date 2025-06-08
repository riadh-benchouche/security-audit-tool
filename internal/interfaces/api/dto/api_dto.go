package dto

// API DTOs pour la future interface REST
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type ScanStartRequest struct {
	Target  string   `json:"target"`
	Modules []string `json:"modules"`
}

type ScanStatusResponse struct {
	ScanID   string `json:"scan_id"`
	Status   string `json:"status"`
	Progress int    `json:"progress"`
}
