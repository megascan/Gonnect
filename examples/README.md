# Gonnect Examples

This directory contains example applications demonstrating how to use the Gonnect authentication library.

## Basic Example

The `basic/` directory contains a simple web application that demonstrates:

- Setting up Gonnect with multiple OAuth providers
- Protecting routes with authentication middleware
- Optional authentication (user info available if logged in)
- Session management
- API endpoints for SPA/frontend integration

### Running the Basic Example

1. **Navigate to the example directory:**
   ```bash
   cd examples/basic
   ```

2. **Run with default settings (mock providers):**
   ```bash
   go run main.go
   ```

3. **Run with real OAuth providers (recommended for testing):**
   ```bash
   # Google OAuth
   export GOOGLE_CLIENT_ID=your_google_client_id
   export GOOGLE_CLIENT_SECRET=your_google_client_secret
   
   # GitHub OAuth (optional)
   export GITHUB_CLIENT_ID=your_github_client_id
   export GITHUB_CLIENT_SECRET=your_github_client_secret
   
   # Discord OAuth (optional)
   export DISCORD_CLIENT_ID=your_discord_client_id
   export DISCORD_CLIENT_SECRET=your_discord_client_secret
   
   # Microsoft OAuth (optional)
   export MICROSOFT_CLIENT_ID=your_microsoft_client_id
   export MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret
   
   go run main.go
   ```

4. **Visit the application:**
   - Main page: http://localhost:8080
   - Protected page: http://localhost:8080/protected
   - API endpoint: http://localhost:8080/api/user
   - Health check: http://localhost:8080/health

### Setting up OAuth Providers

#### Google OAuth

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" and create an OAuth 2.0 Client ID
5. Set the authorized redirect URI to: `http://localhost:8080/auth/google/callback`
6. Copy the Client ID and Client Secret

#### GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Set Authorization callback URL to: `http://localhost:8080/auth/github/callback`
4. Copy the Client ID and Client Secret

#### Discord OAuth

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to OAuth2 settings
4. Add redirect URI: `http://localhost:8080/auth/discord/callback`
5. Copy the Client ID and Client Secret

#### Microsoft OAuth

1. Go to [Azure App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click "New registration"
3. Set redirect URI to: `http://localhost:8080/auth/microsoft/callback`
4. Go to "Certificates & secrets" to create a client secret
5. Copy the Application (client) ID and Client Secret

### Features Demonstrated

#### Traditional Web App Flow
- User visits the home page
- Clicks "Login with Google" (or other provider)
- Gets redirected to the OAuth provider
- After authentication, returns to the app with user info
- User can access protected pages
- Session persists across requests

#### API/SPA Flow
- Frontend can call `/api/auth/google` to get the auth URL
- User completes OAuth flow
- Frontend can call `/api/user` to get user info
- Supports both session cookies and JWT tokens

#### Middleware Usage
```go
// Require authentication
http.Handle("/protected", auth.RequireAuth(protectedHandler))

// Optional authentication
http.Handle("/optional", auth.OptionalAuth(optionalHandler))

// Get user from context
func handler(w http.ResponseWriter, r *http.Request) {
    user := gonnect.GetUser(r)
    if user != nil {
        // User is authenticated
    }
}
```

#### Provider Configuration
```go
auth := gonnect.New("http://localhost:8080")

// Method chaining for easy setup
auth.Google(clientID, clientSecret, "openid", "profile", "email")
auth.GitHub(clientID, clientSecret, "user:email")
auth.Discord(clientID, clientSecret, "identify", "email")

// Configuration options
auth.SetSessionName("my_session")
auth.OnSuccess("/dashboard")
auth.OnFailure("/login")
auth.WithLogger(gonnect.NewSimpleLogger(true))
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_URL` | Base URL of your application | `http://localhost:8080` |
| `PORT` | Port to run the server on | `8080` |
| `GOOGLE_CLIENT_ID` | Google OAuth Client ID | (empty - uses mock) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Client Secret | (empty - uses mock) |
| `GITHUB_CLIENT_ID` | GitHub OAuth Client ID | (empty - uses mock) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth Client Secret | (empty - uses mock) |
| `DISCORD_CLIENT_ID` | Discord OAuth Client ID | (empty - uses mock) |
| `DISCORD_CLIENT_SECRET` | Discord OAuth Client Secret | (empty - uses mock) |
| `MICROSOFT_CLIENT_ID` | Microsoft OAuth Client ID | (empty - uses mock) |
| `MICROSOFT_CLIENT_SECRET` | Microsoft OAuth Client Secret | (empty - uses mock) |

## Next Steps

- Check out the main README.md for more configuration options
- Look at the technical documentation in TECHNICAL.md
- Explore the provider implementations in the `providers/` directory
- Try integrating Gonnect into your own application

## Troubleshooting

### Common Issues

1. **"Provider not found" error**
   - Make sure you've configured the provider before mounting the auth handlers
   - Check that the provider name in the URL matches the configured name

2. **"Invalid state parameter" error**
   - This is a CSRF protection feature
   - Make sure cookies are enabled in your browser
   - Check that your BASE_URL matches the actual URL you're visiting

3. **OAuth redirect URI mismatch**
   - Ensure the redirect URI in your OAuth provider settings matches exactly
   - Format: `{BASE_URL}/auth/{provider}/callback`
   - Example: `http://localhost:8080/auth/google/callback`

4. **Session not persisting**
   - Check that cookies are enabled
   - Ensure you're using HTTPS in production
   - Verify the session secret key is set properly

### Debug Mode

Enable debug logging to see what's happening:

```go
auth.WithLogger(gonnect.NewSimpleLogger(true))
```

This will show detailed logs of the authentication flow, including:
- OAuth redirects
- Token exchanges
- Session creation/validation
- Error details 