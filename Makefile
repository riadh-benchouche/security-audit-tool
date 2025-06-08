.PHONY: build test clean install run help

# Variables
APP_NAME=security-audit
BUILD_DIR=build
VERSION?=2.0.0

# Build
build:
	@echo "🔨 Building $(APP_NAME)..."
	@go mod tidy
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/security-audit
	@echo "✅ Build completed: $(BUILD_DIR)/$(APP_NAME)"

# Test
test:
	@echo "🧪 Running tests..."
	@go test ./...
	@echo "✅ Tests completed"

# Clean
clean:
	@echo "🧹 Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf results/*
	@echo "✅ Cleaned"

# Install
install: build
	@echo "📦 Installing $(APP_NAME)..."
	@cp $(BUILD_DIR)/$(APP_NAME) /usr/local/bin/
	@echo "✅ Installed to /usr/local/bin/$(APP_NAME)"

# Run quick test
run: build
	@echo "🚀 Running quick test..."
	@./$(BUILD_DIR)/$(APP_NAME) modules health

# Help
help:
	@echo "Available commands:"
	@echo "  build    - Build the application"
	@echo "  test     - Run tests" 
	@echo "  clean    - Clean build artifacts"
	@echo "  install  - Install to system"
	@echo "  run      - Build and run quick test"
