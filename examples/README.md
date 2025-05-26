# Gonnect Examples

This directory contains various examples demonstrating how to use the Gonnect authentication library.

## 📁 Available Examples

### 1. **Basic Example** (`basic/`)
A simple web application demonstrating:
- OAuth2 authentication with multiple providers
- Session-based authentication
- Protected routes
- User profile display
- Automatic redirect after login

### 2. **API Example** (`api/`)
RESTful API server showcasing:
- JWT token authentication
- API endpoints with JSON responses
- Token validation middleware
- CORS support for frontend integration

### 3. **Comprehensive Example** (`comprehensive/`)
Advanced web application featuring:
- Multiple OAuth providers
- Custom token storage
- User profile management
- Admin interface
- API and web authentication
- Advanced middleware usage

### 4. **Debug Example** (`debug/`)
Debugging tool for troubleshooting authentication issues:
- Detailed logging of authentication flow
- Session debugging
- Clear success/failure pages
- Request/response inspection

## 🚀 Quick Start

### Prerequisites
1. Go 1.21 or later
2. OAuth2 credentials from your chosen providers

### Running an Example

1. **Navigate to an example directory:**
   ```bash
   cd examples/basic
   ```

2. **Set up OAuth2 credentials (optional for demo):**
   ```bash
   # GitHub OAuth
   export GITHUB_CLIENT_ID=your_github_client_id
   export GITHUB_CLIENT_SECRET=your_github_client_secret
   
   # Google OAuth
   export GOOGLE_CLIENT_ID=your_google_client_id
   export GOOGLE_CLIENT_SECRET=your_google_client_secret
   
   # Discord OAuth
   export DISCORD_CLIENT_ID=your_discord_client_id
   export DISCORD_CLIENT_SECRET=your_discord_client_secret
   
   # Microsoft OAuth
   export MICROSOFT_CLIENT_ID=your_microsoft_client_id
   export MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
   ```

3. **Run the example:**
   ```bash
   go run main.go
   ```

4. **Visit the application:**
   ```
   http://localhost:8080
   ```

## 🔐 Authentication Flow

### How Gonnect Authentication Works

1. **User clicks login button** → Redirects to `/auth/{provider}`
2. **Gonnect redirects to OAuth provider** → User authenticates with provider
3. **Provider redirects back** → To `/auth/{provider}/callback` with authorization code
4. **Gonnect exchanges code for token** → Gets user information from provider
5. **Session is created** → User data stored in session
6. **User is redirected** → To success URL (configured with `OnSuccess()`)

### Default Redirect Behavior

- **Success redirect:** `/` (home page) by default
- **Failure redirect:** `/login` by default
- **Customizable:** Use `auth.OnSuccess("/dashboard")` and `auth.OnFailure("/error")`

### Example Flow in Basic Example

1. User visits `/` → Shows login page (if not authenticated)
2. User clicks "Login with GitHub" → Redirects to `/auth/github`
3. After successful authentication → Redirects to `/protected` (configured success URL)
4. If user visits `/` while authenticated → Automatically redirects to `/protected`

## 🐛 Troubleshooting

### Common Issues

#### 1. **"User doesn't get redirected after login"**

**Symptoms:**
- Authentication succeeds but user stays on callback URL
- User sees blank page or error after OAuth callback

**Solutions:**
- Check that `OnSuccess()` is configured: `auth.OnSuccess("/dashboard")`
- Verify the success URL route exists and is properly handled
- Check server logs for redirect errors
- Use the debug example to trace the flow

**Example fix:**
```go
auth.OnSuccess("/protected")  // Make sure this route exists!

// Make sure you have this route:
http.Handle("/protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Your protected page handler
})))
```

#### 2. **"OAuth callback fails with invalid credentials"**

**Symptoms:**
- Error: "invalid client credentials"
- Authentication fails immediately

**Solutions:**
- Verify OAuth2 credentials are correct
- Check redirect URLs in OAuth provider settings
- Ensure callback URL matches: `http://localhost:8080/auth/{provider}/callback`
- Use environment variables for credentials (don't hardcode)

#### 3. **"Session not persisting between requests"**

**Symptoms:**
- User appears logged in on one page but not on another
- `gonnect.GetUser(r)` returns `nil` unexpectedly

**Solutions:**
- Check session configuration
- Verify cookies are being set correctly
- Check for HTTPS requirements in production
- Use debug example to inspect session data

#### 4. **"CORS errors in frontend applications"**

**Symptoms:**
- Browser console shows CORS errors
- API requests fail from frontend

**Solutions:**
```go
auth.EnableCORS()  // Enable CORS support
```

### Debugging Tips

1. **Enable debug logging:**
   ```go
   auth.WithLogger(gonnect.NewSimpleLogger(true))
   ```

2. **Use the debug example:**
   ```bash
   cd examples/debug
   go run main.go
   ```

3. **Check session data:**
   Visit `/debug/session` in the debug example

4. **Inspect browser cookies:**
   - Open browser dev tools
   - Check Application/Storage → Cookies
   - Look for session cookie

5. **Check OAuth provider settings:**
   - Verify redirect URLs
   - Check client ID/secret
   - Ensure correct scopes

## 🔧 Configuration Examples

### Basic Configuration
```go
auth := gonnect.New("http://localhost:8080")
auth.GitHub("client-id", "client-secret", "user:email")
auth.OnSuccess("/dashboard")
auth.OnFailure("/login")
```

### Advanced Configuration
```go
auth := gonnect.New("http://localhost:8080")
auth.GitHub("client-id", "client-secret", "user:email")
auth.Google("client-id", "client-secret", "openid", "profile", "email")
auth.SetSessionName("my_app_session")
auth.OnSuccess("/dashboard")
auth.OnFailure("/login?error=auth_failed")
auth.WithLogger(gonnect.NewSimpleLogger(true))
auth.EnableJWT("jwt-secret-key")
auth.EnableCORS()
```

### Environment Variables
```bash
# Required for production
export GITHUB_CLIENT_ID=your_github_client_id
export GITHUB_CLIENT_SECRET=your_github_client_secret
export GOOGLE_CLIENT_ID=your_google_client_id
export GOOGLE_CLIENT_SECRET=your_google_client_secret

# Optional configuration
export BASE_URL=https://yourdomain.com
export PORT=8080
export JWT_SECRET=your-jwt-secret
export SESSION_NAME=your_app_session
```

## 📚 Provider Setup Guides

### GitHub OAuth Setup
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Set Authorization callback URL: `http://localhost:8080/auth/github/callback`
4. Copy Client ID and Client Secret

### Google OAuth Setup
1. Go to Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID
3. Add authorized redirect URI: `http://localhost:8080/auth/google/callback`
4. Copy Client ID and Client Secret

### Discord OAuth Setup
1. Go to Discord Developer Portal → Applications
2. Create New Application
3. Go to OAuth2 → General
4. Add redirect: `http://localhost:8080/auth/discord/callback`
5. Copy Client ID and Client Secret

### Microsoft OAuth Setup
1. Go to Azure Portal → App registrations
2. Register new application
3. Add redirect URI: `http://localhost:8080/auth/microsoft/callback`
4. Copy Application (client) ID and create Client Secret

## 🔗 Useful Links

- [Gonnect Documentation](../docs/)
- [OAuth2 Specification](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect](https://openid.net/connect/)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [Google OAuth Documentation](https://developers.google.com/identity/protocols/oauth2)

## 💡 Tips for Production

1. **Use HTTPS:** OAuth2 requires HTTPS in production
2. **Secure secrets:** Use environment variables or secret management
3. **Configure proper redirect URLs:** Match your production domain
4. **Enable logging:** For debugging authentication issues
5. **Set session security:** Configure secure cookies and session timeouts
6. **Implement CSRF protection:** Gonnect includes built-in CSRF protection
7. **Use JWT for APIs:** Enable JWT for stateless API authentication

## 🤝 Contributing

Found an issue with the examples? Please open an issue or submit a pull request! 