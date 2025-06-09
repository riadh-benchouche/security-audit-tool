package http

import (
	"net/http"
	"regexp"
	"strings"
)

// TechnologyDetector handles technology detection
type TechnologyDetector struct {
	patterns map[string]Technology
}

// NewTechnologyDetector creates a new technology detector
func NewTechnologyDetector() *TechnologyDetector {
	return &TechnologyDetector{
		patterns: TechnologyPatterns,
	}
}

// DetectTechnologies detects web technologies from headers and content
func (td *TechnologyDetector) DetectTechnologies(headers http.Header, body string) []Technology {
	technologies := make([]Technology, 0)
	detected := make(map[string]bool) // Prevent duplicates

	// Detection based on headers
	if server := headers.Get("Server"); server != "" {
		tech := GetServerTechnology(server)
		if tech != nil && !detected[tech.Name] {
			technologies = append(technologies, *tech)
			detected[tech.Name] = true
		}
	}

	if powered := headers.Get("X-Powered-By"); powered != "" && !detected[powered] {
		technologies = append(technologies, Technology{
			Name:       powered,
			Categories: []string{"Web Server Extension"},
			Method:     "header",
			Confidence: 90,
		})
		detected[powered] = true
	}

	// Detection based on content
	bodyTech := td.detectFromBody(body)
	for _, tech := range bodyTech {
		if !detected[tech.Name] {
			technologies = append(technologies, tech)
			detected[tech.Name] = true
		}
	}

	return technologies
}

// detectFromBody detects technologies from HTML content
func (td *TechnologyDetector) detectFromBody(body string) []Technology {
	technologies := make([]Technology, 0)
	bodyLower := strings.ToLower(body)

	// Pattern matching
	for pattern, tech := range td.patterns {
		if strings.Contains(bodyLower, pattern) {
			tech.Confidence = 70 // Lower confidence for content detection
			technologies = append(technologies, tech)
		}
	}

	// Version detection for specific technologies
	technologies = td.detectVersions(body, technologies)

	return technologies
}

// detectVersions detects versions for known technologies
func (td *TechnologyDetector) detectVersions(body string, technologies []Technology) []Technology {
	for i := range technologies {
		switch technologies[i].Name {
		case "WordPress":
			if version := td.detectWordPressVersion(body); version != "" {
				technologies[i].Version = version
				technologies[i].Confidence = 85
			}
		case "jQuery":
			if version := td.detectjQueryVersion(body); version != "" {
				technologies[i].Version = version
				technologies[i].Confidence = 90
			}
		}
	}
	return technologies
}

// detectWordPressVersion detects WordPress version
func (td *TechnologyDetector) detectWordPressVersion(body string) string {
	// Try to find WordPress version in meta-generator
	versionRegex := regexp.MustCompile(`<meta name="generator" content="WordPress ([0-9\.]+)"`)
	matches := versionRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// detectjQueryVersion detects jQuery version
func (td *TechnologyDetector) detectjQueryVersion(body string) string {
	// Try to find jQuery version in a script source
	versionRegex := regexp.MustCompile(`jquery[/-]([0-9\.]+)`)
	matches := versionRegex.FindStringSubmatch(strings.ToLower(body))
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
