# Gonnect

**Gonnect** is the all-in-one authentication library for Go—your single solution for integrating a wide range of OAuth2, OpenID Connect, and social login providers. With Gonnect, you can effortlessly add authentication support for platforms like Google, Microsoft, Discord, Steam, GitHub, Facebook, and many more. Gonnect is designed for simplicity, extensibility, and security, making it the ultimate choice for modern Go applications.

---

## Features

- **Universal Provider Support**: Seamlessly integrate dozens of popular auth providers including Google, Microsoft, Discord, Steam, GitHub, Facebook, Twitter, LinkedIn, Amazon, GitLab, Yahoo, Yandex, Dropbox, and more.
- **Multiple Integration Patterns**: Choose from middleware-based, API-first, or comprehensive web application patterns.
- **Modern Frontend Support**: Built-in CORS and JWT support for React, Vue, Angular, and other SPA frameworks.
- **Interactive Demo**: Complete HTML demo page showing real-world OAuth integration.
- **Plug-and-Play Middleware**: Drop-in authentication middleware for traditional web applications.
- **Custom Provider Extensibility**: Easily add support for custom or less common providers.
- **Secure by Default**: Built-in best practices for token handling, session management, and user data protection.
- **Unified API**: Consistent, easy-to-use API for all providers—no more juggling multiple SDKs.
- **Flexible Configuration**: Fine-tune authentication flows, token lifetimes, and user validation logic to fit your app's needs.

---

## Why Gonnect?

- **All the Auth You'll Ever Need**: One package, every major provider.
- **Go-Native**: Designed from the ground up for idiomatic Go development.
- **Battle-Tested Patterns**: Inspired by proven solutions in the Go ecosystem.
- **Multiple Examples**: Basic, comprehensive, and API-first examples included.
- **Interactive Demo**: Try it live with the included HTML demo page.
- **Open Source**: Community-driven and extensible.

---

## Quick Start

Try Gonnect immediately with our interactive demo:

```bash
# Clone and run the API example
git clone https://github.com/megascan/gonnect
cd gonnect/examples/api
go run main.go

# Open http://localhost:8080 in your browser
# Click "Login with Google" or "Login with GitHub" to test OAuth flow
```

---

## Example Usage

### 1. Basic Web Application (with Middleware)

```go
package main

import (
    "log"
    "net/http"
    
    "gonnect"
)

func main() {
    // Simple setup with sensible defaults
    auth := gonnect.New("http://localhost:8080")
    
    // Add providers with method chaining (Go-idiomatic)
    auth.Google("your-client-id", "your-client-secret", "email", "profile")
    auth.GitHub("your-client-id", "your-client-secret", "user:email")
    auth.Discord("your-client-id", "your-client-secret", "identify", "email")
    
    // Mount auth handlers
    http.Handle("/auth/", auth.Handler())
    
    // Protect routes with middleware
    http.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
    http.Handle("/profile", auth.RequireAuth(profileHandler))
    
    // Optional auth (user info available if logged in)
    http.Handle("/", auth.OptionalAuth(homeHandler))
    
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    user := gonnect.GetUser(r) // Extract user from context
    w.Write([]byte("Hello " + user.Name + "!"))
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    user := gonnect.GetUser(r)
    // user.ID, user.Email, user.Name, user.AvatarURL available
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    if user := gonnect.GetUser(r); user != nil {
        w.Write([]byte("Welcome back, " + user.Name))
    } else {
        w.Write([]byte(`<a href="/auth/google">Login with Google</a>`))
    }
}

### 2. API-First Usage (React/Next.js + Go Backend)

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"
    
    "gonnect"
)

func main() {
    // Setup for API backend
    auth := gonnect.New("http://localhost:8080")
    auth.Google("client-id", "client-secret", "email", "profile")
    auth.GitHub("client-id", "client-secret", "user:email")
    
    // Enable JWT tokens for stateless auth
    auth.EnableJWT("your-jwt-secret")
    auth.EnableCORS() // For React frontend
    
    // OAuth flow endpoints (handled by Gonnect)
    http.Handle("/auth/", auth.Handler())
    
    // API endpoints for frontend
    http.HandleFunc("/api/auth/providers", func(w http.ResponseWriter, r *http.Request) {
        providers := auth.ListProviders()
        providerURLs := make(map[string]string)
        for _, provider := range providers {
            providerURLs[provider] = fmt.Sprintf("http://localhost:8080/auth/%s", provider)
        }
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "data": map[string]interface{}{"providers": providerURLs},
        })
    })
    
    // Get current user (for React to check auth status)
    http.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
        user, err := auth.ValidateRequest(r) // Checks JWT or session
        if err != nil {
            http.Error(w, `{"error":"unauthorized"}`, 401)
            return
        }
        
        json.NewEncoder(w).Encode(map[string]interface{}{
            "success": true,
            "data": user,
            "message": "User information retrieved",
        })
    })
    
    // Serve demo HTML page
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/" {
            http.ServeFile(w, r, "index.html")
        } else {
            http.NotFound(w, r)
        }
    })
    
    log.Println("API server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### 3. React Frontend Example

```typescript
// React component using the Go API
import { useState, useEffect } from 'react';

interface User {
  id: string;
  name: string;
  email: string;
  avatar_url: string;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [providers, setProviders] = useState<Record<string, string>>({});

  useEffect(() => {
    // Load available providers
    fetch('/api/auth/providers', { credentials: 'include' })
      .then(res => res.json())
      .then(data => setProviders(data.data?.providers || {}));

    // Check if user is already authenticated
    fetch('/api/user', { credentials: 'include' })
      .then(res => res.ok ? res.json() : null)
      .then(data => setUser(data?.data || null))
      .finally(() => setLoading(false));
  }, []);

  const loginWith = (provider: string) => {
    window.location.href = `/auth/${provider}`;
  };

  const logout = () => {
    fetch('/api/auth/logout', { method: 'POST', credentials: 'include' })
      .then(() => setUser(null));
  };

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      {user ? (
        <div>
          <h1>Welcome, {user.name}!</h1>
          <img src={user.avatar_url} alt="Avatar" />
          <p>Email: {user.email}</p>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <div>
          <h1>Please login</h1>
          {Object.entries(providers).map(([name, url]) => (
            <button key={name} onClick={() => loginWith(name)}>
              Login with {name.charAt(0).toUpperCase() + name.slice(1)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
```

---

## Examples

Gonnect includes three complete examples to get you started:

### 📁 `examples/basic/`
Simple web application with HTML templates and middleware-based authentication.
```bash
cd examples/basic
go run main.go
# Visit http://localhost:8080
```

### 📁 `examples/comprehensive/`
Full-featured web application with user dashboard, profile management, and multiple OAuth providers.
```bash
cd examples/comprehensive
go run main.go
# Visit http://localhost:8080
```

### 📁 `examples/api/`
**🌟 Interactive Demo** - Pure JSON API with HTML demo page. Perfect for React/Next.js frontends.
```bash
cd examples/api
go run main.go
# Visit http://localhost:8080 for interactive demo
```

The API example includes:
- 🎨 Beautiful HTML demo page with real-time OAuth testing
- 📡 RESTful JSON API endpoints
- 🔄 Live API response viewer
- 👤 User profile management
- 🧪 Interactive API testing tools
- 📱 Mobile-responsive design

---

## Supported Providers

✅ **Currently Implemented:**
- **Google** - OAuth2 with OpenID Connect
- **GitHub** - OAuth2 with user info
- **Discord** - OAuth2 with user identification
- **Microsoft** - OAuth2 with OpenID Connect
- **Apple** - OAuth2 with Sign in with Apple
- **Facebook** - OAuth2 with Graph API
- **Twitter** - OAuth2 with API v2
- **LinkedIn** - OAuth2 with profile access
- **Steam** - OpenID 2.0 authentication
- **Amazon** - OAuth2 with Login with Amazon
- **GitLab** - OAuth2 with OpenID Connect
- **Yahoo** - OAuth2 with OpenID Connect
- **Yandex** - OAuth2 with user info
- **Dropbox** - OAuth2 with account info

🚧 **Coming Soon:**
- Slack, Reddit, Twitch, Spotify, and more!

Each provider includes:
- 🔐 Secure OAuth2/OpenID implementation
- 👤 Standardized user profile data
- 🎯 Sensible default scopes
- ⚙️ Customizable scope configuration

---

## Getting Started

### 1. Try the Interactive Demo
```bash
git clone https://github.com/megascan/gonnect
cd gonnect/examples/api
go run main.go
# Open http://localhost:8080 and test OAuth with Google/GitHub
```

### 2. Install Gonnect
```bash
go get github.com/megascan/gonnect
```

### 3. Set Up OAuth Providers
Register your application with OAuth providers:

**Google OAuth:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth2 credentials
5. Set redirect URI: `http://localhost:8080/auth/google/callback`

**GitHub OAuth:**
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `http://localhost:8080/auth/github/callback`

### 4. Configure Environment Variables
```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
```

### 5. Start Building
Choose your integration pattern:
- **Basic Web App**: Use `examples/basic/` as a starting point
- **Full Web App**: Use `examples/comprehensive/` for advanced features  
- **API + Frontend**: Use `examples/api/` for React/Vue/Angular apps

---

## Project Structure

```
gonnect/
├── examples/
│   ├── basic/           # Simple web app with middleware
│   ├── comprehensive/   # Full-featured web application  
│   └── api/            # JSON API + HTML demo (⭐ Try this first!)
├── providers/          # Individual OAuth provider implementations
│   ├── google/
│   ├── github/
│   ├── discord/
│   └── ...
├── internal/
│   ├── coretypes/      # Core type definitions
│   ├── crypto/         # Cryptographic utilities
│   └── utils/          # Helper utilities
├── gonnect.go          # Main library interface
├── handlers.go         # HTTP handlers
├── middleware.go       # Authentication middleware
└── session.go          # Session management
```

## Contributing

Gonnect is open to contributions! Here's how you can help:

### 🔌 Add New Providers
1. Create a new provider in `providers/newprovider/`
2. Implement the `Provider` interface
3. Add method to `providers.go`
4. Test with the examples
5. Submit a pull request

### 📚 Improve Documentation
- Fix typos or unclear explanations
- Add more usage examples
- Improve code comments

### 🐛 Report Issues
- Use the GitHub issue tracker
- Include minimal reproduction code
- Specify Go version and OS

### 💡 Suggest Features
- Open an issue with your idea
- Explain the use case
- Consider backward compatibility

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Gonnect** — All the auth you'll ever need, in Go. 🚀

⭐ **Star this repo** if Gonnect helps you build better Go applications!