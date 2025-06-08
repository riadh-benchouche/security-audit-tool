#!/bin/bash
# Script de test automatique  
echo "🧪 Running tests..."
go test ./...
echo "🚀 Running integration tests..."
./build/security-audit modules health
./build/security-audit scan -t httpbin.org -m network --config configs/fast-config.yaml
echo "✅ Tests completed!"
