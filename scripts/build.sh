#!/bin/bash
# Script de build automatique
echo "🔨 Building Security Audit Tool..."
go mod tidy
go build -o build/security-audit ./cmd/security-audit
echo "✅ Build completed: build/security-audit"
