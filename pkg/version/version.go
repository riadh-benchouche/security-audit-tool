package version

import "runtime"

var (
	// Ces variables sont injectées lors du build
	Version   = "2.0.0"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// Info retourne les informations de version
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get retourne les informations de version
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
