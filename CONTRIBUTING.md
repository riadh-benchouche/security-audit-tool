# 🤝 Contributing Guide

Thank you for your interest in contributing to Security Audit Tool! This guide will help you get started.

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR-USERNAME/security-audit-tool.git
cd security-audit-tool

# Add the original repository as upstream remote
git remote add upstream https://github.com/riadh-benchouche/security-audit-tool.git

# Install dependencies
go mod tidy
```

### 2. Create a Branch

```bash
# Create a branch for your feature/fix
git checkout -b feature/my-new-feature
# or
git checkout -b fix/bug-fix
```

### 3. Develop

```bash
# Make your changes
# Test regularly
make test
make build

# Check code style
go fmt ./...
go vet ./...
```

### 4. Commit and Push

```bash
# Commit with clear message
git commit -m "✨ Add new security scanner module"

# Push to your fork
git push origin feature/my-new-feature
```

### 5. Pull Request

- Go to GitHub and create a Pull Request
- Describe your changes clearly
- Link any resolved issues

## 📝 Code Standards

### Go Style
- Use `gofmt` for formatting
- Follow standard Go conventions
- Add GoDoc comments for public functions
- Handle errors properly

### Well-commented code example
```go
// NetworkScanner implements network scanning to detect
// open ports and identify services.
type NetworkScanner struct {
    logger  *core.StructuredLogger
    timeout time.Duration
}

// Scan executes a network scan on the specified target and returns
// results with open ports and detected services.
func (ns *NetworkScanner) Scan(target string) (*models.ModuleResult, error) {
    // Implementation...
}
```

### Testing
- Write tests for all new functionality
- Maintain coverage > 80%
- Use descriptive test names

```go
func TestNetworkScanner_ScanValidTarget(t *testing.T) {
    scanner := NewNetworkScanner()
    result, err := scanner.Scan("httpbin.org")
    
    assert.NoError(t, err)
    assert.NotNil(t, result)
    assert.Equal(t, "network", result.Module)
}
```

## 🏗️ Architecture

### Package Structure
```
pkg/
├── core/       # Core functionality (config, logging, output)
├── scanner/    # Scan modules
├── models/     # Data structures
└── api/        # Web server and endpoints
```

### Adding a New Scanner

1. **Create file** `pkg/scanner/my_scanner.go`
2. **Implement interface** `Scanner`
3. **Add tests** `pkg/scanner/my_scanner_test.go`
4. **Update manager** in `scanner/manager.go`

```go
type MyScanner struct {
    logger *core.StructuredLogger
}

func NewMyScanner() *MyScanner {
    return &MyScanner{
        logger: core.NewStructuredLogger("my-scanner"),
    }
}

func (ms *MyScanner) Name() string {
    return "my-scanner"
}

func (ms *MyScanner) Scan(target string) (*models.ModuleResult, error) {
    // Implementation...
}
```

## 🧪 Testing

### Running Tests
```bash
# All tests
make test

# Tests with coverage
make test-coverage

# Specific tests
go test ./pkg/scanner/

# Integration tests
go test -tags=integration ./...
```

### Test Types

1. **Unit tests**: Test isolated functions
2. **Integration tests**: Test module interactions
3. **End-to-end tests**: Test complete application

## 📋 Contribution Types

### 🐛 Bug Fixes
- Reproduce the bug
- Write a failing test
- Fix the code
- Verify test passes

### ✨ New Features
- Discuss in an issue first
- Follow existing architecture
- Add comprehensive tests
- Update documentation

### 📖 Documentation
- README, usage guides
- Code comments
- Practical examples
- Tutorials

### 🔧 Optimizations
- Improve performance
- Reduce memory usage
- Optimize algorithms

## 🏷️ Commit Convention

Use conventional format:

```
type(scope): description

[optional body]

[optional footer]
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting (no code change)
- `refactor`: Refactoring without functionality change
- `test`: Adding or modifying tests
- `chore`: Maintenance (build, dependencies)

### Examples
```
feat(scanner): add DNS scanner module
fix(http): handle timeout errors properly
docs(readme): update installation instructions
test(network): add tests for port scanning
```

## 🔍 Code Review

### For Reviewers
- Check logic and security
- Ensure tests pass
- Validate code style
- Review documentation

### For Contributors
- Respond to comments quickly
- Make requested changes
- Keep branch updated with main

## 🎯 Best Practices

### Security
- Never commit secrets/keys
- Validate all user inputs
- Handle errors properly
- Use appropriate timeouts

### Performance
- Profile code when necessary
- Avoid memory leaks
- Optimize I/O operations
- Use concurrency when appropriate

### Maintainability
- Readable and well-structured code
- Short and focused functions
- Explicit variable names
- Avoid code duplication

## 🆘 Help

### Resources
- [Go Documentation](https://golang.org/doc/)
- [Go Testing Guide](https://golang.org/doc/tutorial/add-a-test)
- [Effective Go](https://golang.org/doc/effective_go)

### Contact
- Create an issue for questions
- Use GitHub discussions
- Contact maintainers

---

Thank you for contributing to Security Audit Tool! 🙏