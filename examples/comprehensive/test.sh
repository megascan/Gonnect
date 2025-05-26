#!/bin/bash

# Test script for Gonnect Comprehensive Example

echo "🧪 Testing Gonnect Comprehensive Example..."

# Build the application
echo "📦 Building application..."
go build . || exit 1

# Start the server in background
echo "🚀 Starting server..."
./comprehensive &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test health endpoint
echo "🔍 Testing health endpoint..."
curl -s http://localhost:8080/health | grep -q "ok" && echo "✅ Health check passed" || echo "❌ Health check failed"

# Test status endpoint
echo "🔍 Testing status endpoint..."
curl -s http://localhost:8080/status | grep -q "running" && echo "✅ Status check passed" || echo "❌ Status check failed"

# Test auth status endpoint
echo "🔍 Testing auth status endpoint..."
curl -s http://localhost:8080/api/auth/status | grep -q "authenticated" && echo "✅ Auth status check passed" || echo "❌ Auth status check failed"

# Test home page
echo "🔍 Testing home page..."
curl -s http://localhost:8080/ | grep -q "github.com/megascan/Gonnect" && echo "✅ Home page check passed" || echo "❌ Home page check failed"

# Stop the server
echo "🛑 Stopping server..."
kill $SERVER_PID

echo "✨ Tests completed!" 