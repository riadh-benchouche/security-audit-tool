# 🛡️ Security Audit Tool

<div align="center">

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-0.2.0-blue?style=for-the-badge)

**A modern and extensible security audit tool built with Go and Vue.js frontend**

[🚀 Installation](#-installation) • [📖 Usage](#-usage) • [🔧 Configuration](#-configuration) • [📊 Examples](#-examples) • [🤝 Contributing](#-contributing)

</div>

## ✨ Features

### 🔍 **Security Scanners**
- **🌐 Network Scanner**: Port detection, service identification, and banner grabbing
- **🔒 HTTP Scanner**: Security headers analysis and SSL/TLS validation
- **🚀 Parallel Scanning**: Optimized performance with goroutines
- **🎯 Technology Detection**: Automatic stack identification

### 📊 **Security Analysis**
- **🏆 Automatic Scoring**: A-F grades with detailed justifications
- **🔴 Vulnerability Detection**: Classification by severity levels
- **💡 Recommendations**: Detailed remediation guidance
- **📈 Metrics**: Response times and comprehensive statistics

### 🛠️ **Interface & API**
- **⚡ REST API**: High-performance Fiber web server
- **🖥️ Intuitive CLI**: Complete command-line interface
- **🎨 Web Interface**: Modern Vue.js dashboard (in development)
- **📄 Multi-format Output**: JSON, HTML, XML, CSV, Text

### ⚙️ **Architecture**
- **🧩 Modular Design**: Extensible plugin system
- **📝 Structured Logging**: Detailed traces with Logrus
- **🔧 Flexible Configuration**: YAML files, environment variables
- **🏗️ Production Ready**: Robust error handling and monitoring

## 🚀 Installation

### Prerequisites
- **Go 1.21+** for compilation
- **Node.js 18+** for web interface (optional)

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/riadh-benchouche/security-audit-tool.git
cd security-audit-tool

# Install dependencies
go mod tidy

# Build
make build
# or
go build -o build/security-audit cmd/main.go
```

### Installation with Make

```bash
make help          # See all available commands
make build         # Build the project
make install       # Install to $GOPATH/bin
make test          # Run tests
make clean         # Clean generated files
```

## 📖 Usage

### 🔧 CLI (Command Line Interface)

```bash
# Show help
./build/security-audit --help

# Simple network scan
./build/security-audit scan -t google.com -m network

# HTTP scan with security analysis
./build/security-audit scan -t https://httpbin.org -m http

# Complete scan with output
./build/security-audit scan -t github.com -m network,http -o github-audit.json

# Scan with custom configuration
./build/security-audit scan -t example.com --config custom.yaml -v

# Generate HTML report
./build/security-audit scan -t target.com -m http -o report.html
```

### 🌐 REST API

```bash
# Start API server
./build/security-audit server

# API available at http://localhost:8080
```

#### Main Endpoints

```bash
# Health check
curl http://localhost:8080/api/v1/health

# List available modules
curl http://localhost:8080/api/v1/modules

# Start scan via API
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "httpbin.org",
    "modules": ["network", "http"]
  }'

# Get scan results
curl http://localhost:8080/api/v1/scans/{id}
```

### 🎯 Web Interface (In Development)

```bash
# Start Vue.js frontend
cd web/frontend/security-audit-ui
npm install
npm run dev

# Interface available at http://localhost:5173
```

## 🔧 Configuration

### Default Configuration

```yaml
# security-audit.yaml
scan:
  timeout: 300
  threads: 10
  modules: ["network", "http"]

network:
  ports: [21, 22, 23, 25, 53, 80, 443, 3389, 8080]
  tcp_timeout: 5
  max_threads: 50

http:
  follow_redirects: true
  max_redirects: 5
  timeout: 30
  ssl_check: true

log_level: "info"
```

### Environment Variables

```bash
export SECAUDIT_LOG_LEVEL=debug
export SECAUDIT_SCAN_TIMEOUT=600
export SECAUDIT_HTTP_TIMEOUT=30
```

## 📊 Examples

### Network Scan Results
```json
{
  "target": "google.com",
  "summary": {
    "total_findings": 3,
    "score": 100,
    "grade": "A"
  },
  "results": [{
    "module": "network",
    "findings": [
      {
        "title": "Open port 443/tcp",
        "severity": "info",
        "description": "Port 443 is open (web service)"
      }
    ]
  }]
}
```

### HTTP Scan Results
```json
{
  "target": "https://httpbin.org",
  "summary": {
    "total_findings": 6,
    "score": 85,
    "grade": "B"
  },
  "results": [{
    "module": "http",
    "findings": [
      {
        "title": "Missing HSTS Header",
        "severity": "medium",
        "remediation": "Add Strict-Transport-Security header"
      }
    ]
  }]
}
```

## 🏗️ Architecture

```
security-audit-tool/
├── cmd/                    # CLI entry point
├── pkg/
│   ├── core/              # Configuration, logging, output
│   ├── scanner/           # Scan modules (network, http)
│   ├── models/            # Data structures
│   └── api/               # Web server and REST API
├── web/
│   ├── frontend/          # Vue.js application
│   └── static/            # Static assets
├── configs/               # Default configurations
├── examples/              # Usage examples
├── build/                 # Compiled binaries
├── results/               # Scan results
└── docs/                  # Documentation
```

## 🔍 Available Modules

### 🌐 Network Scanner
- **Port scanning** TCP with service detection
- **Banner grabbing** to identify versions
- **Basic OS detection**
- **Security checks** for insecure protocols

### 🔒 HTTP Scanner
- **Security headers**: HSTS, CSP, X-Frame-Options, etc.
- **SSL/TLS analysis**: Certificates, versions, vulnerabilities
- **Technology detection**: Servers, frameworks, CMS
- **Performance**: Response times, redirections

## 📈 Roadmap

### ✅ Version 0.2.0 (Current)
- [x] Complete CLI with Cobra
- [x] Network and HTTP scanners
- [x] REST API with Fiber
- [x] Multi-format output
- [x] Modular architecture

### 🚧 Version 0.3.0 (In Progress)
- [ ] Vue.js web interface
- [ ] Dashboard with charts
- [ ] Background scanning
- [ ] Results database

### 🔮 Version 0.4.0 (Planned)
- [ ] Advanced SSL/TLS scanner
- [ ] DNS and WHOIS modules
- [ ] PDF reports
- [ ] Slack/Discord notifications
- [ ] Automated testing
- [ ] Docker and Kubernetes

## 🧪 Testing

```bash
# Run all tests
make test

# Tests with coverage
make test-coverage

# Integration tests
go test -v ./... -tags=integration

# Benchmarks
go test -bench=. ./pkg/scanner/
```

## 🤝 Contributing

Contributions are welcome!

### Quick Start for Contributors

```bash
# Fork and clone
git clone https://github.com/riadh-benchouche/security-audit-tool.git
cd security-audit-tool

# Create feature branch
git checkout -b feature/amazing-feature

# Develop and test
make test
make build

# Commit and push
git commit -m "✨ Add amazing feature"
git push origin feature/amazing-feature

# Create Pull Request
```

### Guidelines

- 📝 **Code Style**: `gofmt` and `golint`
- 🧪 **Testing**: Coverage > 80%
- 📖 **Documentation**: GoDoc comments
- 🔒 **Security**: No secrets in code
- 🏷️ **Commits**: Conventional format

## 🙏 Acknowledgments

- **[Nmap](https://nmap.org/)** for network scanning inspiration
- **[OWASP](https://owasp.org/)** for security guidelines
- **[Nuclei](https://github.com/projectdiscovery/nuclei)** for modular architecture
- **[Fiber](https://gofiber.io/)** for the high-performance web framework

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/riadh-benchouche/security-audit-tool/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/riadh-benchouche/security-audit-tool/discussions)
- 📧 **Contact**: riadh.benchouche@example.com

---

<div align="center">

**⭐ Star this project if you find it helpful! ⭐**

Made with ❤️ by [Riadh Benchouche](https://github.com/riadh-benchouche)

</div>