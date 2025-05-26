# Gonnect

**Gonnect** is the all-in-one authentication library for Go-your single solution for integrating a wide range of OAuth2, OpenID Connect, and social login providers. With Gonnect, you can effortlessly add authentication support for platforms like Google, Microsoft, Discord, Steam, GitHub, Facebook, and many more. Gonnect is designed for simplicity, extensibility, and security, making it the ultimate choice for modern Go applications.

---

## Features

- **Universal Provider Support**: Seamlessly integrate dozens of popular auth providers including Google, Microsoft, Discord, Steam, GitHub, Facebook, Twitter, LinkedIn, and more.
- **Plug-and-Play Middleware**: Drop-in authentication middleware for your favorite Go web frameworks.
- **Custom Provider Extensibility**: Easily add support for custom or less common providers.
- **Secure by Default**: Built-in best practices for token handling, session management, and user data protection.
- **Unified API**: Consistent, easy-to-use API for all providers-no more juggling multiple SDKs.
- **Flexible Configuration**: Fine-tune authentication flows, token lifetimes, and user validation logic to fit your app's needs.

---

## Why Gonnect?

- **All the Auth You'll Ever Need**: One package, every major provider.
- **Go-Native**: Designed from the ground up for idiomatic Go development.
- **Battle-Tested Patterns**: Inspired by proven solutions in the Go ecosystem[2][3][5].
- **Open Source**: Community-driven and extensible.

---

## Example Usage

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/megascan/gonnect"
)

func main() {
    // Simple setup with sensible defaults
    auth := gonnect.New("http://localhost:8080")
    
    // Add providers with method chaining (Go-idiomatic)
    auth.Google("your-client-id", "your-client-secret", "email", "profile")
    auth.GitHub("your-client-id", "your-client-secret", "user:email")
    auth.Discord("your-client-id", "your-client-secret", "identify", "email")
    
    // Optional: customize behavior
    auth.SetSecret("your-32-byte-secret-key") // auto-generated if not set
    auth.SetSessionName("myapp_session")
    auth.OnSuccess("/dashboard")
    auth.OnFailure("/login")
    
    // Mount auth handlers
    http.Handle("/auth/", auth.Handler())
    
    // Protect routes
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
    // user.Provider() returns "google", "github", etc.
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    if user := gonnect.GetUser(r); user != nil {
        w.Write([]byte("Welcome back, " + user.Name))
    } else {
        w.Write([]byte(`<a href="/auth/google">Login with Google</a>`))
    }
}

### API-First Usage (React/Next.js + Go Backend)

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"
    
    "github.com/megascan/gonnect"
)

func main() {
    // Setup for API backend
    auth := gonnect.New("http://localhost:8080")
    auth.Google("client-id", "client-secret", "email", "profile")
    auth.GitHub("client-id", "client-secret", "user:email")
    
    // Enable JWT tokens for stateless auth
    auth.EnableJWT("your-jwt-secret")
    auth.EnableCORS() // For React frontend
    
    // API endpoints for frontend
    http.HandleFunc("/api/auth/google", auth.GetAuthURL("google"))
    http.HandleFunc("/api/auth/google/callback", auth.HandleCallback("google"))
    http.HandleFunc("/api/auth/github", auth.GetAuthURL("github"))
    http.HandleFunc("/api/auth/github/callback", auth.HandleCallback("github"))
    
    // Get current user (for React to check auth status)
    http.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
        user, err := auth.ValidateRequest(r) // Checks JWT or session
        if err != nil {
            http.Error(w, `{"error":"unauthorized"}`, 401)
            return
        }
        
        json.NewEncoder(w).Encode(map[string]interface{}{
            "user": user,
            "authenticated": true,
        })
    })
    
    // Protected API endpoint
    http.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
        user, err := auth.ValidateRequest(r)
        if err != nil {
            http.Error(w, `{"error":"unauthorized"}`, 401)
            return
        }
        
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "Hello " + user.Name,
            "data": "secret data",
        })
    })
    
    log.Println("API server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### React Frontend Example

```typescript
// React component using the Go API
import { useState, useEffect } from 'react';

interface User {
  id: string;
  name: string;
  email: string;
  avatarURL: string;
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is already authenticated
    fetch('/api/user', { credentials: 'include' })
      .then(res => res.ok ? res.json() : null)
      .then(data => setUser(data?.user || null))
      .finally(() => setLoading(false));
  }, []);

  const loginWithGoogle = () => {
    // Get auth URL from Go backend
    fetch('/api/auth/google')
      .then(res => res.json())
      .then(data => window.location.href = data.authURL);
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
          <img src={user.avatarURL} alt="Avatar" />
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <div>
          <h1>Please login</h1>
          <button onClick={loginWithGoogle}>Login with Google</button>
        </div>
      )}
    </div>
  );
}
```

### Advanced Configuration

```go
// For advanced use cases, use the Config struct
auth := gonnect.NewWithConfig(gonnect.Config{
    BaseURL:      "https://myapp.com",
    SecretKey:    []byte("your-32-byte-secret-key"),
    SessionStore: myCustomSessionStore, // implement gonnect.SessionStore
    TokenStore:   myCustomTokenStore,   // implement gonnect.TokenStore
    JWTSecret:    []byte("jwt-secret"),
    EnableCORS:   true,
    Logger:       myLogger,
})

// Custom provider (for less common OAuth providers)
auth.AddProvider("custom", gonnect.ProviderConfig{
    ClientID:     "client-id",
    ClientSecret: "client-secret", 
    AuthURL:      "https://provider.com/oauth/authorize",
    TokenURL:     "https://provider.com/oauth/token",
    UserInfoURL:  "https://provider.com/api/user",
    Scopes:       []string{"read:user"},
})
```

---

## Supported Providers

- Google
- Microsoft
- Discord
- Steam
- GitHub
- Facebook
- Twitter
- LinkedIn
- Slack
- Reddit
- Twitch
- And many more!

---

## Getting Started

1. Install Gonnect:
   ```sh
   go get github.com/megascan/gonnect
   ```
2. Register your application with your chosen auth providers and obtain client credentials.
3. Configure Gonnect in your Go application.
4. Protect your routes and start authenticating users!

---

## Contributing

Gonnect is open to contributions! If you want to add a new provider, improve documentation, or suggest features, feel free to open an issue or submit a pull request.

---

**Gonnect**-all the auth you'll ever need, in Go.