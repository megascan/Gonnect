# Quick Start

Get up and running with Gonnect OAuth authentication in 5 minutes! This guide will walk you through creating your first OAuth-enabled Go application.

## 🚀 5-Minute Setup

### Step 1: Install Gonnect

```bash
# Create a new Go project
mkdir my-oauth-app
cd my-oauth-app
go mod init my-oauth-app

# Install Gonnect
go get github.com/megascan/gonnect
```

### Step 2: Create Your First OAuth App

Create `main.go`:

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    
    "gonnect"
)

func main() {
    // Initialize Gonnect
    auth := gonnect.New("http://localhost:8080")
    
    // Add OAuth providers (using demo credentials)
    auth.Google("demo-client-id", "demo-client-secret")
    auth.GitHub("demo-client-id", "demo-client-secret")
    
    // Mount OAuth handlers
    http.Handle("/auth/", auth.Handler())
    
    // Protected route with middleware
    http.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
    
    // Public home page
    http.HandleFunc("/", homeHandler)
    
    fmt.Println("🚀 Server starting on http://localhost:8080")
    fmt.Println("📱 Try logging in with Google or GitHub!")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    html := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>My OAuth App</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; text-align: center; }
            .btn { display: inline-block; padding: 12px 24px; margin: 10px; text-decoration: none; 
                   border-radius: 5px; color: white; font-weight: bold; }
            .google { background: #4285f4; }
            .github { background: #333; }
        </style>
    </head>
    <body>
        <h1>🔐 My OAuth App</h1>
        <p>Choose your login method:</p>
        <a href="/auth/google" class="btn google">Login with Google</a>
        <a href="/auth/github" class="btn github">Login with GitHub</a>
    </body>
    </html>`
    
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(html))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user
    user := gonnect.GetUser(r)
    
    html := fmt.Sprintf(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; }
            .user-card { background: #f5f5f5; padding: 20px; border-radius: 10px; }
            .avatar { width: 64px; height: 64px; border-radius: 50%%; }
        </style>
    </head>
    <body>
        <h1>🎉 Welcome to your Dashboard!</h1>
        <div class="user-card">
            <img src="%s" alt="Avatar" class="avatar">
            <h2>%s</h2>
            <p><strong>Email:</strong> %s</p>
            <p><strong>ID:</strong> %s</p>
        </div>
        <p><a href="/auth/logout">Logout</a></p>
    </body>
    </html>`, user.AvatarURL, user.Name, user.Email, user.ID)
    
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(html))
}
```

### Step 3: Run Your App

```bash
go run main.go
```

Open your browser to `http://localhost:8080` and try the OAuth flow!

> **Note**: The demo uses placeholder credentials. For real OAuth, you'll need to set up OAuth applications with providers (see [OAuth Setup guides](../guides/oauth-setup/)).

## 🎯 What Just Happened?

Your app now has:

1. **OAuth Authentication** - Users can log in with Google or GitHub
2. **Protected Routes** - `/dashboard` requires authentication
3. **User Information** - Access to user profile data
4. **Session Management** - Automatic session handling
5. **Logout Functionality** - Built-in logout endpoint

## 🔧 Real OAuth Setup (5 more minutes)

To use real OAuth providers instead of demo credentials:

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Set redirect URI: `http://localhost:8080/auth/google/callback`

### GitHub OAuth Setup

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `http://localhost:8080/auth/github/callback`

### Update Your Code

Replace the demo credentials:

```go
// Replace these lines:
auth.Google("demo-client-id", "demo-client-secret")
auth.GitHub("demo-client-id", "demo-client-secret")

// With your real credentials:
auth.Google("your-google-client-id", "your-google-client-secret")
auth.GitHub("your-github-client-id", "your-github-client-secret")
```

## 🚀 Try the Interactive Demo

Want to see a more advanced example? Try our interactive demo:

```bash
# Clone the repository
git clone https://github.com/megascan/gonnect.git
cd gonnect/examples/api

# Run the demo
go run main.go

# Open http://localhost:8080
```

The demo includes:
- 🎨 Beautiful UI with real-time OAuth testing
- 📡 JSON API endpoints
- 👤 User profile management
- 🧪 Interactive API testing tools

## 📚 Next Steps

### Choose Your Integration Pattern

**Traditional Web App**
```go
// Use middleware for server-rendered pages
http.Handle("/protected", auth.RequireAuth(handler))
```

**API-First (React/Next.js)**
```go
// Manual authentication for APIs
user, err := auth.ValidateRequest(r)
if err != nil {
    http.Error(w, "Unauthorized", 401)
    return
}
```

**Comprehensive Web App**
```go
// Multiple providers with advanced features
auth.Google(googleID, googleSecret)
auth.GitHub(githubID, githubSecret)
auth.Discord(discordID, discordSecret)
auth.Microsoft(msID, msSecret)
```

### Explore Examples

- **[Basic Example](../examples/basic-example.md)** - Simple web application
- **[API Example](../examples/api-example.md)** - JSON API with demo
- **[Comprehensive Example](../examples/comprehensive-example.md)** - Full-featured app

### Learn More

- **[OAuth Provider Setup](../guides/oauth-setup/)** - Configure all 14 providers
- **[Integration Patterns](../guides/integration-patterns/)** - Architecture patterns
- **[API Reference](../api-reference/)** - Complete API documentation

## 🔧 Common Patterns

### Environment Variables

```go
import "os"

func main() {
    auth := gonnect.New("http://localhost:8080")
    
    // Load from environment
    if googleID := os.Getenv("GOOGLE_CLIENT_ID"); googleID != "" {
        auth.Google(googleID, os.Getenv("GOOGLE_CLIENT_SECRET"))
    }
}
```

### Multiple Providers

```go
auth := gonnect.New("http://localhost:8080")

// Add multiple providers
auth.Google(googleID, googleSecret)
auth.GitHub(githubID, githubSecret)
auth.Discord(discordID, discordSecret)
auth.Microsoft(msID, msSecret)
```

### Custom Scopes

```go
// Request specific permissions
auth.Google(clientID, clientSecret, "email", "profile", "openid")
auth.GitHub(clientID, clientSecret, "user:email", "read:user")
```

### API Mode with JWT

```go
auth := gonnect.New("http://localhost:8080")
auth.EnableJWT("your-secret-key")  // For stateless APIs
auth.EnableCORS()                  // For frontend integration
```

## 🐛 Troubleshooting

### Common Issues

**"Invalid redirect URI"**
- Check your OAuth app settings
- Ensure redirect URI matches exactly: `http://localhost:8080/auth/{provider}/callback`

**"User not found in context"**
- Make sure you're using `auth.RequireAuth()` middleware
- Check that the route is protected

**"CORS errors"**
- Enable CORS: `auth.EnableCORS()`
- Or set specific origins: `auth.SetCORSOrigins("http://localhost:3000")`

### Debug Mode

```go
auth := gonnect.New("http://localhost:8080")
auth.SetDebug(true)  // Enable debug logging
```

## 🎉 You're Ready!

Congratulations! You now have a working OAuth application. Here's what to explore next:

1. **Add more providers** - [OAuth Setup guides](../guides/oauth-setup/)
2. **Deploy to production** - [Deployment guide](../guides/deployment/)
3. **Build an API** - [API-First pattern](../guides/integration-patterns/api-first.md)
4. **Integrate with React** - [React integration](../guides/integration-patterns/react-frontend.md)

## 💡 Pro Tips

- **Start with the interactive demo** to understand OAuth flows
- **Use environment variables** for credentials (never commit secrets!)
- **Test with multiple providers** to ensure compatibility
- **Read the provider setup guides** for production-ready configuration
- **Check out the examples** for advanced patterns

---

**Need help?** Check the [FAQ](../troubleshooting/faq.md) or [open an issue](https://github.com/megascan/gonnect/issues)! 