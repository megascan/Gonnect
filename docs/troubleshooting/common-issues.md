# Common Issues

This guide covers the most frequently encountered issues when using Gonnect and their solutions.

## Table of Contents

- [OAuth Configuration Issues](#oauth-configuration-issues)
- [Authentication Errors](#authentication-errors)
- [Session Management Issues](#session-management-issues)
- [CORS and Frontend Issues](#cors-and-frontend-issues)
- [Provider-Specific Issues](#provider-specific-issues)
- [Development Environment Issues](#development-environment-issues)
- [Production Deployment Issues](#production-deployment-issues)

## OAuth Configuration Issues

### "Invalid redirect URI" / "redirect_uri_mismatch"

**Symptoms:**
- Error during OAuth flow
- User redirected to error page
- OAuth provider shows "redirect URI mismatch"

**Causes:**
- Redirect URI in provider settings doesn't match your application
- Protocol mismatch (http vs https)
- Port number differences
- Path differences

**Solutions:**

1. **Check exact URL match:**
   ```
   Provider setting: http://localhost:8080/auth/google/callback
   Gonnect expects:  http://localhost:8080/auth/google/callback
   ```

2. **Verify protocol:**
   ```bash
   # Development (HTTP)
   http://localhost:8080/auth/{provider}/callback
   
   # Production (HTTPS)
   https://yourdomain.com/auth/{provider}/callback
   ```

3. **Check port numbers:**
   ```bash
   # If your app runs on port 3000
   http://localhost:3000/auth/{provider}/callback
   ```

4. **Verify provider configuration:**
   - Google: Google Cloud Console → Credentials
   - GitHub: Settings → Developer settings → OAuth Apps
   - Discord: Discord Developer Portal → Applications

### "Invalid client credentials" / "Unauthorized client"

**Symptoms:**
- OAuth flow fails immediately
- "Invalid client" error from provider
- Authentication doesn't start

**Causes:**
- Wrong client ID or client secret
- Environment variables not loaded
- Typos in credentials

**Solutions:**

1. **Verify credentials:**
   ```go
   // Debug: Print credentials (remove in production!)
   fmt.Printf("Client ID: %s\n", os.Getenv("GOOGLE_CLIENT_ID"))
   fmt.Printf("Client Secret: %s\n", os.Getenv("GOOGLE_CLIENT_SECRET"))
   ```

2. **Check environment variables:**
   ```bash
   # Verify .env file exists and is loaded
   cat .env
   
   # Check if variables are set
   echo $GOOGLE_CLIENT_ID
   ```

3. **Ensure proper loading:**
   ```go
   import "github.com/joho/godotenv"
   
   func init() {
       if err := godotenv.Load(); err != nil {
           log.Fatal("Error loading .env file")
       }
   }
   ```

### "Application not found" / "Client not found"

**Symptoms:**
- OAuth provider says application doesn't exist
- 404 errors during OAuth flow

**Causes:**
- OAuth application was deleted
- Wrong client ID
- Application not approved/published

**Solutions:**

1. **Verify application exists:**
   - Check provider's developer console
   - Ensure application is active
   - Verify client ID matches

2. **Check application status:**
   - Some providers require app approval
   - Ensure app is published/live
   - Check for suspension notices

## Authentication Errors

### "User not found in context" / `GetUser()` returns nil

**Symptoms:**
- `gonnect.GetUser(r)` returns nil
- Protected routes don't work
- User appears logged in but context is empty

**Causes:**
- Missing authentication middleware
- Context key mismatch
- Session not properly stored

**Solutions:**

1. **Use authentication middleware:**
   ```go
   // Correct: Use middleware
   http.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
   
   // Incorrect: No middleware
   http.HandleFunc("/dashboard", dashboardHandler)
   ```

2. **Check middleware order:**
   ```go
   // Correct order
   http.Handle("/auth/", auth.Handler())
   http.Handle("/dashboard", auth.RequireAuth(dashboardHandler))
   ```

3. **Verify session storage:**
   ```go
   // Enable debug mode to see session operations
   auth.SetDebug(true)
   ```

### "Session expired" / "Invalid session"

**Symptoms:**
- Users randomly logged out
- Session doesn't persist
- "Please log in" errors

**Causes:**
- Session timeout
- Server restart (in-memory sessions)
- Cookie issues

**Solutions:**

1. **Use persistent session store:**
   ```go
   // Instead of default in-memory store
   auth.SetSessionStore(myDatabaseStore)
   ```

2. **Check cookie settings:**
   ```go
   // Ensure cookies are properly configured
   // Gonnect handles this automatically, but check browser dev tools
   ```

3. **Verify session duration:**
   ```go
   // Sessions last 24 hours by default
   // Check if users are inactive longer than that
   ```

### "Token expired" / "Invalid token"

**Symptoms:**
- JWT authentication fails
- API requests return 401
- Token validation errors

**Causes:**
- JWT token expired
- Wrong JWT secret
- Token format issues

**Solutions:**

1. **Check JWT secret:**
   ```go
   // Ensure same secret used for signing and verification
   auth.EnableJWT(os.Getenv("JWT_SECRET"))
   ```

2. **Verify token format:**
   ```bash
   # JWT should have 3 parts separated by dots
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
   ```

3. **Handle token refresh:**
   ```go
   // Implement token refresh logic for expired tokens
   user, err := auth.ValidateRequest(r)
   if err == gonnect.ErrInvalidToken {
       // Redirect to login or refresh token
   }
   ```

## Session Management Issues

### Sessions not persisting across server restarts

**Symptoms:**
- All users logged out after server restart
- Sessions lost during deployment

**Causes:**
- Using default in-memory session store
- No persistent storage

**Solutions:**

1. **Implement persistent session store:**
   ```go
   type DatabaseSessionStore struct {
       db *sql.DB
   }
   
   func (s *DatabaseSessionStore) Get(sessionID string) (*gonnect.User, error) {
       // Implement database retrieval
   }
   
   func (s *DatabaseSessionStore) Set(sessionID string, user *gonnect.User) error {
       // Implement database storage
   }
   
   func (s *DatabaseSessionStore) Delete(sessionID string) error {
       // Implement database deletion
   }
   
   auth.SetSessionStore(&DatabaseSessionStore{db: db})
   ```

2. **Use Redis for sessions:**
   ```go
   // Example Redis session store
   type RedisSessionStore struct {
       client *redis.Client
   }
   
   auth.SetSessionStore(&RedisSessionStore{client: redisClient})
   ```

### Multiple sessions for same user

**Symptoms:**
- User can log in multiple times
- Conflicting session data
- Security concerns

**Causes:**
- No session deduplication
- Multiple devices/browsers

**Solutions:**

1. **Implement session deduplication:**
   ```go
   // Custom session store that enforces single session per user
   func (s *CustomSessionStore) Set(sessionID string, user *gonnect.User) error {
       // Delete existing sessions for this user
       s.DeleteUserSessions(user.ID)
       // Set new session
       return s.setSession(sessionID, user)
   }
   ```

## CORS and Frontend Issues

### CORS errors in browser console

**Symptoms:**
- "Access to fetch blocked by CORS policy"
- API requests fail from frontend
- Preflight request errors

**Causes:**
- CORS not enabled
- Wrong CORS origins
- Missing CORS headers

**Solutions:**

1. **Enable CORS:**
   ```go
   auth.EnableCORS()
   ```

2. **Set specific origins:**
   ```go
   auth.SetCORSOrigins("http://localhost:3000", "https://myapp.com")
   ```

3. **Check preflight requests:**
   ```go
   // Gonnect handles OPTIONS requests automatically
   // Ensure your frontend sends proper headers
   ```

### Frontend can't access cookies

**Symptoms:**
- Session cookies not sent
- Authentication state not maintained
- CORS credentials issues

**Causes:**
- Missing credentials in fetch requests
- SameSite cookie issues
- HTTPS/HTTP mismatch

**Solutions:**

1. **Include credentials in requests:**
   ```javascript
   fetch('/api/user', {
       credentials: 'include'  // Important for cookies
   })
   ```

2. **Check cookie settings:**
   ```go
   // Gonnect sets appropriate cookie flags
   // For HTTPS, cookies are automatically secure
   ```

### React/Next.js integration issues

**Symptoms:**
- OAuth redirects don't work in SPA
- State management issues
- Routing conflicts

**Causes:**
- Client-side routing conflicts
- State not synchronized
- Redirect handling issues

**Solutions:**

1. **Use API-first pattern:**
   ```javascript
   // Instead of redirecting, use API endpoints
   const response = await fetch('/api/auth/status', {
       credentials: 'include'
   });
   ```

2. **Handle OAuth redirects properly:**
   ```javascript
   // In your OAuth callback component
   useEffect(() => {
       // Check if user is now authenticated
       checkAuthStatus();
   }, []);
   ```

## Provider-Specific Issues

### Google OAuth issues

**"This app isn't verified"**
- Add test users to OAuth consent screen
- Go through Google's verification process
- Use internal user type for testing

**"Access blocked"**
- Check OAuth consent screen configuration
- Verify scopes are approved
- Ensure app is published

### GitHub OAuth issues

**"Application suspended"**
- Check email for GitHub notifications
- Review terms of service compliance
- Contact GitHub support if needed

**Rate limiting**
- GitHub has strict rate limits
- Implement proper error handling
- Consider GitHub Apps for higher limits

### Discord OAuth issues

**"Invalid OAuth2 redirect_uri"**
- Discord is very strict about redirect URIs
- Must match exactly including trailing slashes
- Check for URL encoding issues

## Development Environment Issues

### Port conflicts

**Symptoms:**
- "Port already in use" errors
- Cannot start development server
- OAuth redirects to wrong port

**Solutions:**

1. **Check for running processes:**
   ```bash
   # Find process using port 8080
   lsof -i :8080
   netstat -tulpn | grep 8080
   ```

2. **Use different port:**
   ```go
   // Change port in your application
   log.Fatal(http.ListenAndServe(":8081", nil))
   ```

3. **Update OAuth redirect URIs:**
   ```
   http://localhost:8081/auth/{provider}/callback
   ```

### Environment variable issues

**Symptoms:**
- Credentials not loaded
- "Environment variable not set" errors
- OAuth fails with invalid credentials

**Solutions:**

1. **Verify .env file location:**
   ```bash
   # .env should be in project root
   ls -la .env
   ```

2. **Check .env format:**
   ```bash
   # No spaces around =
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   ```

3. **Verify loading:**
   ```go
   if err := godotenv.Load(); err != nil {
       log.Printf("No .env file found: %v", err)
   }
   ```

## Production Deployment Issues

### HTTPS certificate issues

**Symptoms:**
- OAuth redirects fail in production
- "Insecure redirect URI" errors
- SSL/TLS errors

**Solutions:**

1. **Ensure HTTPS is properly configured:**
   ```bash
   # Test SSL certificate
   curl -I https://yourdomain.com
   ```

2. **Update OAuth redirect URIs:**
   ```
   https://yourdomain.com/auth/{provider}/callback
   ```

3. **Check certificate validity:**
   ```bash
   # Check certificate expiration
   openssl s_client -connect yourdomain.com:443 -servername yourdomain.com
   ```

### Environment variable management

**Symptoms:**
- Credentials not available in production
- "Invalid client" errors in production
- Environment variables not set

**Solutions:**

1. **Use proper secret management:**
   ```bash
   # Docker
   docker run -e GOOGLE_CLIENT_ID=value myapp
   
   # Kubernetes
   kubectl create secret generic oauth-secrets \
     --from-literal=google-client-id=value
   ```

2. **Verify environment in production:**
   ```go
   // Add health check endpoint
   func healthCheck(w http.ResponseWriter, r *http.Request) {
       status := map[string]bool{
           "google_configured": os.Getenv("GOOGLE_CLIENT_ID") != "",
           "github_configured": os.Getenv("GITHUB_CLIENT_ID") != "",
       }
       json.NewEncoder(w).Encode(status)
   }
   ```

### Load balancer / proxy issues

**Symptoms:**
- OAuth callbacks fail behind load balancer
- Session affinity issues
- Redirect URI mismatches

**Solutions:**

1. **Configure proper headers:**
   ```nginx
   # Nginx configuration
   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;
   ```

2. **Use session affinity:**
   ```yaml
   # Kubernetes ingress
   nginx.ingress.kubernetes.io/affinity: "cookie"
   ```

## Debug Mode

Enable debug mode to get detailed logging:

```go
auth := gonnect.New("http://localhost:8080")
auth.SetDebug(true)
```

This will log:
- OAuth flow steps
- Session operations
- Token validation
- Provider responses
- Error details

## Getting Help

If you're still experiencing issues:

1. **Check the logs** with debug mode enabled
2. **Review the [FAQ](faq.md)** for quick answers
3. **Search [GitHub Issues](https://github.com/megascan/gonnect/issues)**
4. **Open a new issue** with:
   - Gonnect version
   - Go version
   - Provider being used
   - Error messages
   - Minimal reproduction code

## Next Steps

- **[Debugging Guide](debugging.md)** - Advanced debugging techniques
- **[FAQ](faq.md)** - Frequently asked questions
- **[Migration Guide](migration.md)** - Upgrading from other libraries 