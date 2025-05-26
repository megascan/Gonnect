# Core API Reference

This document provides a comprehensive reference for Gonnect's core API.

## Table of Contents

- [Gonnect Instance](#gonnect-instance)
- [Provider Methods](#provider-methods)
- [Authentication Methods](#authentication-methods)
- [Middleware](#middleware)
- [Configuration](#configuration)
- [Types](#types)
- [Error Handling](#error-handling)

## Gonnect Instance

### `New(baseURL string) *Gonnect`

Creates a new Gonnect instance with the specified base URL.

**Parameters:**
- `baseURL` (string): The base URL of your application (e.g., "http://localhost:8080")

**Returns:**
- `*Gonnect`: A new Gonnect instance

**Example:**
```go
auth := gonnect.New("http://localhost:8080")
```

### `GetBaseURL() string`

Returns the base URL configured for the Gonnect instance.

**Returns:**
- `string`: The base URL

**Example:**
```go
baseURL := auth.GetBaseURL()
fmt.Println(baseURL) // "http://localhost:8080"
```

## Provider Methods

### `Google(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Google OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Google OAuth client ID
- `clientSecret` (string): Google OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "openid", "profile", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Google("client-id", "client-secret", "openid", "profile", "email")
```

### `GitHub(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds GitHub OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): GitHub OAuth client ID
- `clientSecret` (string): GitHub OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "user:email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.GitHub("client-id", "client-secret", "user:email", "public_repo")
```

### `Discord(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Discord OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Discord OAuth client ID
- `clientSecret` (string): Discord OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "identify", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Discord("client-id", "client-secret", "identify", "email", "guilds")
```

### `Microsoft(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Microsoft OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Microsoft OAuth client ID
- `clientSecret` (string): Microsoft OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "openid", "profile", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Microsoft("client-id", "client-secret", "openid", "profile", "email")
```

### `Apple(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Apple Sign In provider with method chaining.

**Parameters:**
- `clientID` (string): Apple OAuth client ID
- `clientSecret` (string): Apple OAuth client secret (JWT)
- `scopes` (...string): Optional OAuth scopes (defaults to "name", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Apple("client-id", "jwt-secret", "name", "email")
```

### `Facebook(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Facebook Login provider with method chaining.

**Parameters:**
- `clientID` (string): Facebook OAuth client ID
- `clientSecret` (string): Facebook OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "email", "public_profile")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Facebook("client-id", "client-secret", "email", "public_profile")
```

### `Twitter(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Twitter OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Twitter OAuth client ID
- `clientSecret` (string): Twitter OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "users.read", "tweet.read")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Twitter("client-id", "client-secret", "users.read", "tweet.read")
```

### `LinkedIn(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds LinkedIn OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): LinkedIn OAuth client ID
- `clientSecret` (string): LinkedIn OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "r_liteprofile", "r_emailaddress")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.LinkedIn("client-id", "client-secret", "r_liteprofile", "r_emailaddress")
```

### `Steam() *Gonnect`

Adds Steam OpenID provider with method chaining.

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Steam()
```

### `Amazon(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Amazon Login provider with method chaining.

**Parameters:**
- `clientID` (string): Amazon OAuth client ID
- `clientSecret` (string): Amazon OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "profile")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Amazon("client-id", "client-secret", "profile")
```

### `GitLab(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds GitLab OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): GitLab OAuth client ID
- `clientSecret` (string): GitLab OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "openid", "profile", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.GitLab("client-id", "client-secret", "openid", "profile", "email")
```

### `Yahoo(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Yahoo OIDC provider with method chaining.

**Parameters:**
- `clientID` (string): Yahoo OAuth client ID
- `clientSecret` (string): Yahoo OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "openid", "profile", "email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Yahoo("client-id", "client-secret", "openid", "profile", "email")
```

### `Yandex(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Yandex OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Yandex OAuth client ID
- `clientSecret` (string): Yandex OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "login:info", "login:email")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Yandex("client-id", "client-secret", "login:info", "login:email")
```

### `Dropbox(clientID, clientSecret string, scopes ...string) *Gonnect`

Adds Dropbox OAuth provider with method chaining.

**Parameters:**
- `clientID` (string): Dropbox OAuth client ID
- `clientSecret` (string): Dropbox OAuth client secret
- `scopes` (...string): Optional OAuth scopes (defaults to "account_info.read")

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.Dropbox("client-id", "client-secret", "account_info.read")
```

## Authentication Methods

### `Handler() http.Handler`

Returns an HTTP handler that handles OAuth authentication flows for all configured providers.

**Returns:**
- `http.Handler`: Handler for OAuth routes

**Example:**
```go
http.Handle("/auth/", auth.Handler())
```

**Handled Routes:**
- `GET /auth/{provider}` - Initiates OAuth flow
- `GET /auth/{provider}/callback` - Handles OAuth callback
- `POST /auth/logout` - Logs out the user

### `ValidateRequest(r *http.Request) (*User, error)`

Validates an HTTP request and returns the authenticated user if valid.

**Parameters:**
- `r` (*http.Request): The HTTP request to validate

**Returns:**
- `*User`: The authenticated user
- `error`: Error if authentication failed

**Example:**
```go
user, err := auth.ValidateRequest(r)
if err != nil {
    http.Error(w, "Unauthorized", 401)
    return
}
fmt.Printf("User: %s\n", user.Name)
```

### `GetUser(r *http.Request) *User`

Gets the authenticated user from the request context. Returns nil if not authenticated.

**Parameters:**
- `r` (*http.Request): The HTTP request

**Returns:**
- `*User`: The authenticated user or nil

**Example:**
```go
user := gonnect.GetUser(r)
if user != nil {
    fmt.Printf("User: %s\n", user.Name)
}
```

## Middleware

### `RequireAuth(next http.Handler) http.Handler`

Middleware that requires authentication. Redirects unauthenticated users to login.

**Parameters:**
- `next` (http.Handler): The next handler in the chain

**Returns:**
- `http.Handler`: Middleware handler

**Example:**
```go
http.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
```

### `OptionalAuth(next http.Handler) http.Handler`

Middleware that optionally checks for authentication but doesn't require it.

**Parameters:**
- `next` (http.Handler): The next handler in the chain

**Returns:**
- `http.Handler`: Middleware handler

**Example:**
```go
http.Handle("/profile", auth.OptionalAuth(profileHandler))
```

## Configuration

### `SetDebug(debug bool) *Gonnect`

Enables or disables debug logging.

**Parameters:**
- `debug` (bool): Whether to enable debug logging

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.SetDebug(true)
```

### `SetSessionStore(store SessionStore) *Gonnect`

Sets a custom session store implementation.

**Parameters:**
- `store` (SessionStore): Custom session store

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.SetSessionStore(myCustomStore)
```

### `SetTokenStore(store TokenStore) *Gonnect`

Sets a custom token store implementation.

**Parameters:**
- `store` (TokenStore): Custom token store

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.SetTokenStore(myCustomTokenStore)
```

### `EnableJWT(secret string) *Gonnect`

Enables JWT token authentication with the specified secret.

**Parameters:**
- `secret` (string): JWT signing secret

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.EnableJWT("your-secret-key")
```

### `EnableCORS() *Gonnect`

Enables CORS headers for cross-origin requests.

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.EnableCORS()
```

### `SetCORSOrigins(origins ...string) *Gonnect`

Sets specific allowed CORS origins.

**Parameters:**
- `origins` (...string): Allowed origins

**Returns:**
- `*Gonnect`: The Gonnect instance for method chaining

**Example:**
```go
auth.SetCORSOrigins("http://localhost:3000", "https://myapp.com")
```

## Types

### `User`

Represents an authenticated user.

```go
type User struct {
    ID        string `json:"id"`         // Provider-specific user ID
    Email     string `json:"email"`      // User's email address
    Name      string `json:"name"`       // User's full name
    FirstName string `json:"first_name"` // User's first name
    LastName  string `json:"last_name"`  // User's last name
    AvatarURL string `json:"avatar_url"` // URL to user's profile picture
    Provider  string `json:"provider"`   // OAuth provider name
}
```

### `Token`

Represents an OAuth token.

```go
type Token struct {
    AccessToken  string    `json:"access_token"`  // OAuth access token
    RefreshToken string    `json:"refresh_token"` // OAuth refresh token
    TokenType    string    `json:"token_type"`    // Token type (usually "Bearer")
    Expiry       time.Time `json:"expiry"`        // Token expiration time
}
```

### `SessionStore`

Interface for custom session storage.

```go
type SessionStore interface {
    Get(sessionID string) (*User, error)
    Set(sessionID string, user *User) error
    Delete(sessionID string) error
}
```

### `TokenStore`

Interface for custom token storage.

```go
type TokenStore interface {
    Get(userID string) (*Token, error)
    Set(userID string, token *Token) error
    Delete(userID string) error
}
```

## Error Handling

### Common Errors

**`ErrNotAuthenticated`**
- Returned when a user is not authenticated
- HTTP Status: 401 Unauthorized

**`ErrInvalidProvider`**
- Returned when an invalid provider is specified
- HTTP Status: 400 Bad Request

**`ErrInvalidToken`**
- Returned when a token is invalid or expired
- HTTP Status: 401 Unauthorized

**`ErrProviderError`**
- Returned when the OAuth provider returns an error
- HTTP Status: 400 Bad Request

### Error Handling Example

```go
user, err := auth.ValidateRequest(r)
if err != nil {
    switch err {
    case gonnect.ErrNotAuthenticated:
        http.Error(w, "Please log in", 401)
    case gonnect.ErrInvalidToken:
        http.Error(w, "Invalid token", 401)
    default:
        http.Error(w, "Authentication error", 500)
    }
    return
}
```

## Method Chaining

Gonnect supports method chaining for configuration:

```go
auth := gonnect.New("http://localhost:8080").
    SetDebug(true).
    EnableCORS().
    Google(googleID, googleSecret).
    GitHub(githubID, githubSecret).
    Discord(discordID, discordSecret)
```

## Thread Safety

Gonnect instances are thread-safe after configuration. You can safely use the same instance across multiple goroutines for handling requests.

## Next Steps

- **[Provider API Reference](providers.md)** - Provider-specific methods
- **[Middleware Reference](middleware.md)** - Authentication middleware
- **[Types Reference](types.md)** - Type definitions
- **[Error Reference](errors.md)** - Error handling 