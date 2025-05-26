# Installation

This guide will help you install Gonnect and set up your development environment.

## Prerequisites

Before installing Gonnect, ensure you have:

- **Go 1.19 or later** - [Download Go](https://golang.org/dl/)
- **Git** - For cloning repositories
- **A text editor or IDE** - VS Code, GoLand, or your preferred editor

### Verify Go Installation

```bash
go version
# Should output: go version go1.21.x ...
```

## Installation Methods

### Method 1: Go Module (Recommended)

Add Gonnect to your existing Go project:

```bash
# Initialize a new Go module (if not already done)
go mod init your-app-name

# Add Gonnect dependency
go get github.com/megascan/gonnect

# Verify installation
go mod tidy
```

### Method 2: Clone and Build

For development or contributing:

```bash
# Clone the repository
git clone https://github.com/megascan/gonnect.git
cd gonnect

# Download dependencies
go mod download

# Verify everything builds
go build ./...

# Run tests
go test ./...
```

## Quick Verification

Create a simple test file to verify installation:

```go
// main.go
package main

import (
    "fmt"
    "gonnect"
)

func main() {
    auth := gonnect.New("http://localhost:8080")
    fmt.Println("Gonnect installed successfully!")
    fmt.Printf("Base URL: %s\n", auth.GetBaseURL())
}
```

Run the test:

```bash
go run main.go
# Output: Gonnect installed successfully!
#         Base URL: http://localhost:8080
```

## Try the Interactive Demo

The fastest way to see Gonnect in action:

```bash
# Clone the repository
git clone https://github.com/megascan/gonnect.git
cd gonnect/examples/api

# Run the interactive demo
go run main.go

# Open your browser to http://localhost:8080
```

You'll see a beautiful demo page where you can test OAuth flows with Google and GitHub (no setup required for demo).

## Development Environment Setup

### Recommended VS Code Extensions

If using VS Code, install these extensions:

- **Go** (by Google) - Official Go language support
- **Go Test Explorer** - Visual test runner
- **REST Client** - Test API endpoints
- **Thunder Client** - Alternative API testing

### Environment Variables

Create a `.env` file for your OAuth credentials:

```bash
# .env
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Optional: JWT secret for API mode
JWT_SECRET=your-super-secret-jwt-key

# Optional: CORS settings
CORS_ORIGIN=http://localhost:3000
```

### Load Environment Variables

Add this to your Go application:

```go
package main

import (
    "log"
    "os"
    
    "github.com/joho/godotenv"
    "gonnect"
)

func main() {
    // Load .env file
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }
    
    auth := gonnect.New("http://localhost:8080")
    
    // Configure providers from environment
    if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
        auth.Google(clientID, os.Getenv("GOOGLE_CLIENT_SECRET"))
    }
    
    if clientID := os.Getenv("GITHUB_CLIENT_ID"); clientID != "" {
        auth.GitHub(clientID, os.Getenv("GITHUB_CLIENT_SECRET"))
    }
    
    // ... rest of your app
}
```

Install the godotenv package:

```bash
go get github.com/joho/godotenv
```

## Project Structure

Recommended project structure for a Gonnect application:

```
your-app/
├── main.go              # Application entry point
├── handlers/            # HTTP handlers
│   ├── auth.go         # Authentication handlers
│   ├── dashboard.go    # Protected routes
│   └── api.go          # API endpoints
├── middleware/          # Custom middleware
│   └── auth.go         # Authentication middleware
├── templates/           # HTML templates (if using)
├── static/             # Static assets
├── .env                # Environment variables
├── .env.example        # Example environment file
├── go.mod              # Go module file
├── go.sum              # Go module checksums
└── README.md           # Project documentation
```

## Common Dependencies

Depending on your use case, you might want these additional packages:

```bash
# Environment variables
go get github.com/joho/godotenv

# HTML templates (if building web app)
go get html/template

# JSON handling
go get encoding/json

# HTTP routing (optional - Gonnect works with net/http)
go get github.com/gorilla/mux
go get github.com/gin-gonic/gin

# Database (if needed)
go get gorm.io/gorm
go get gorm.io/driver/postgres
go get gorm.io/driver/mysql
```

## Troubleshooting Installation

### Common Issues

**1. "package gonnect is not in GOROOT"**
```bash
# Ensure you're using Go modules
go mod init your-app
go get github.com/megascan/gonnect
```

**2. "cannot find module providing package"**
```bash
# Update Go modules
go mod tidy
go mod download
```

**3. "permission denied" on Linux/macOS**
```bash
# Ensure Go workspace permissions
sudo chown -R $USER:$USER $GOPATH
```

**4. Proxy issues in corporate environments**
```bash
# Configure Go proxy
export GOPROXY=direct
export GOSUMDB=off
```

### Verify Installation

Run this comprehensive check:

```bash
# Check Go version
go version

# Check module status
go list -m all | grep gonnect

# Build test
go build -v ./...

# Run tests
go test -v ./...
```

## Next Steps

Now that Gonnect is installed:

1. **[Quick Start](quick-start.md)** - Build your first OAuth app
2. **[Interactive Demo](interactive-demo.md)** - Explore the live demo
3. **[OAuth Setup](../guides/oauth-setup/)** - Configure OAuth providers
4. **[Integration Patterns](../guides/integration-patterns/)** - Choose your architecture

## Getting Help

- **Documentation**: [docs/README.md](../README.md)
- **Examples**: [examples/](../../examples/)
- **Issues**: [GitHub Issues](https://github.com/megascan/gonnect/issues)
- **Discussions**: [GitHub Discussions](https://github.com/megascan/gonnect/discussions) 