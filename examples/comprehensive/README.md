# Gonnect Comprehensive Example

This is a comprehensive example demonstrating all features of the Gonnect OAuth authentication library.

## Features Demonstrated

### 🔐 Authentication Features
- **Multiple OAuth Providers**: Google, GitHub, Discord, Microsoft, Apple, Facebook, Twitter, LinkedIn, Steam, Amazon, GitLab, Yahoo, Yandex, Dropbox
- **JWT Token Authentication**: For API endpoints and stateless authentication
- **Session-based Authentication**: For traditional web applications
- **Custom Token Storage**: Advanced token management with user profiles
- **CORS Support**: For frontend integration

### 🌐 Web Application Features
- **Protected Routes**: Dashboard, Profile, Settings, Admin pages
- **Optional Authentication**: Pages that work with or without login
- **User Profile Management**: Extended user information and preferences
- **Admin Dashboard**: User management and statistics
- **Error Handling**: Comprehensive error pages and API responses

### 🔌 API Features
- **RESTful API Endpoints**: JSON responses for frontend integration
- **Authentication Status**: Check if user is authenticated
- **User Profile API**: Get and update user information
- **Token Information**: View token status and expiry
- **Admin APIs**: User management and statistics
- **Health Checks**: Service status and monitoring

### 🛠️ Advanced Features
- **Custom Middleware**: RequireAuth and OptionalAuth
- **Logging**: Comprehensive request and authentication logging
- **Configuration**: Environment-based configuration
- **Template System**: Modular HTML templates
- **Statistics**: User login tracking and provider analytics

## Quick Start

### 1. Set Environment Variables

```bash
# Required: Base URL for your application
export BASE_URL="http://localhost:8080"

# Optional: Server configuration
export PORT="8080"
export JWT_SECRET="your-super-secret-jwt-key-change-this-in-production"
export CORS_ORIGIN="*"
export DEBUG="true"

# OAuth Provider Credentials (configure as needed)
export GOOGLE_CLIENT_ID="your_google_client_id"
export GOOGLE_CLIENT_SECRET="your_google_client_secret"

export GITHUB_CLIENT_ID="your_github_client_id"
export GITHUB_CLIENT_SECRET="your_github_client_secret"

export DISCORD_CLIENT_ID="your_discord_client_id"
export DISCORD_CLIENT_SECRET="your_discord_client_secret"

export MICROSOFT_CLIENT_ID="your_microsoft_client_id"
export MICROSOFT_CLIENT_SECRET="your_microsoft_client_secret"

# Additional providers...
export APPLE_CLIENT_ID="your_apple_client_id"
export APPLE_CLIENT_SECRET="your_apple_client_secret"

export FACEBOOK_CLIENT_ID="your_facebook_client_id"
export FACEBOOK_CLIENT_SECRET="your_facebook_client_secret"

export TWITTER_CLIENT_ID="your_twitter_client_id"
export TWITTER_CLIENT_SECRET="your_twitter_client_secret"

export LINKEDIN_CLIENT_ID="your_linkedin_client_id"
export LINKEDIN_CLIENT_SECRET="your_linkedin_client_secret"

export AMAZON_CLIENT_ID="your_amazon_client_id"
export AMAZON_CLIENT_SECRET="your_amazon_client_secret"

export GITLAB_CLIENT_ID="your_gitlab_client_id"
export GITLAB_CLIENT_SECRET="your_gitlab_client_secret"

export YAHOO_CLIENT_ID="your_yahoo_client_id"
export YAHOO_CLIENT_SECRET="your_yahoo_client_secret"

export YANDEX_CLIENT_ID="your_yandex_client_id"
export YANDEX_CLIENT_SECRET="your_yandex_client_secret"

export DROPBOX_CLIENT_ID="your_dropbox_client_id"
export DROPBOX_CLIENT_SECRET="your_dropbox_client_secret"
```

### 2. Run the Application

```bash
cd examples/comprehensive
go run main.go
```

### 3. Access the Application

- **Home Page**: http://localhost:8080
- **Dashboard**: http://localhost:8080/dashboard (requires login)
- **Admin Panel**: http://localhost:8080/admin (requires login)
- **API Status**: http://localhost:8080/api/auth/status
- **Health Check**: http://localhost:8080/health

## Application Structure

### Web Routes

| Route | Description | Auth Required |
|-------|-------------|---------------|
| `/` | Home page with login options | No |
| `/dashboard` | User dashboard | Yes |
| `/profile` | User profile management | Yes |
| `/settings` | User settings | Yes |
| `/admin` | Admin dashboard | Yes |
| `/admin/users` | User management | Yes |
| `/about` | About page | No |
| `/privacy` | Privacy policy | No |
| `/optional` | Optional auth example | No |

### API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/auth/status` | GET | Check authentication status | No |
| `/api/user` | GET | Get current user info | Yes |
| `/api/user/profile` | GET/PUT | Get/update user profile | Yes |
| `/api/user/tokens` | GET | Get user token information | Yes |
| `/api/admin/users` | GET | List all users | Yes |
| `/api/admin/stats` | GET | Get system statistics | Yes |
| `/health` | GET | Health check | No |
| `/status` | GET | Service status | No |

### Authentication Routes

All OAuth providers are available under `/auth/{provider}`:

- `/auth/google` - Google OAuth
- `/auth/github` - GitHub OAuth
- `/auth/discord` - Discord OAuth
- `/auth/microsoft` - Microsoft OAuth
- `/auth/apple` - Apple OAuth
- `/auth/facebook` - Facebook OAuth
- `/auth/twitter` - Twitter OAuth
- `/auth/linkedin` - LinkedIn OAuth
- `/auth/steam` - Steam OpenID
- `/auth/amazon` - Amazon OAuth
- `/auth/gitlab` - GitLab OAuth
- `/auth/yahoo` - Yahoo OAuth
- `/auth/yandex` - Yandex OAuth
- `/auth/dropbox` - Dropbox OAuth

## Custom Token Store

The example includes a custom token store that provides:

- **User Profiles**: Extended user information beyond basic OAuth data
- **Login Tracking**: Track login count and last login time
- **Provider Management**: Track which providers each user has used
- **Preferences**: Store user preferences and settings
- **Statistics**: Generate usage statistics and analytics

## API Usage Examples

### Check Authentication Status

```bash
curl http://localhost:8080/api/auth/status
```

### Get User Information (with JWT)

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/user
```

### Update User Profile

```bash
curl -X PUT \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -d '{"name":"New Name","preferences":{"theme":"dark"}}' \
     http://localhost:8080/api/user/profile
```

### Get System Statistics

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/admin/stats
```

## Frontend Integration

The application supports both traditional web authentication and modern API-based authentication:

### Traditional Web Flow
1. User visits `/auth/{provider}`
2. Redirected to OAuth provider
3. Returns to `/auth/{provider}/callback`
4. Session created, redirected to dashboard

### API Flow
1. Frontend calls `/api/auth/{provider}` to get auth URL
2. User completes OAuth flow
3. Frontend calls `/api/auth/{provider}/callback`
4. Receives JWT token for API authentication

## Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Base URL for OAuth callbacks |
| `PORT` | `8080` | Server port |
| `JWT_SECRET` | `your-super-secret...` | JWT signing secret |
| `CORS_ORIGIN` | `*` | CORS allowed origins |
| `DEBUG` | `true` | Enable debug logging |

## Security Features

- **CSRF Protection**: State parameter validation
- **JWT Security**: Signed tokens with expiration
- **Session Security**: Secure session management
- **CORS Configuration**: Configurable cross-origin requests
- **Error Handling**: Secure error messages without information leakage

## Monitoring and Health Checks

### Health Check Endpoint
```bash
curl http://localhost:8080/health
```

Returns:
```json
{
  "status": "ok",
  "timestamp": 1640995200,
  "providers": 13,
  "users": 5
}
```

### Service Status
```bash
curl http://localhost:8080/status
```

Returns detailed service information including enabled features and provider list.

## Development Tips

1. **Testing Multiple Providers**: You don't need to configure all providers - the app works with any subset
2. **Debug Mode**: Set `DEBUG=true` for detailed logging
3. **JWT Testing**: Use the `/api/auth/status` endpoint to test JWT authentication
4. **Custom Templates**: Modify the template constants in `main.go` for custom UI
5. **Database Integration**: Replace `CustomTokenStore` with database-backed storage for production

## Production Considerations

1. **Security**: Change the default JWT secret
2. **CORS**: Configure specific origins instead of `*`
3. **HTTPS**: Use HTTPS in production
4. **Database**: Implement persistent storage for tokens and user data
5. **Logging**: Implement structured logging
6. **Monitoring**: Add metrics and monitoring
7. **Rate Limiting**: Implement rate limiting for API endpoints

## Troubleshooting

### Common Issues

1. **Provider Not Configured**: Check environment variables for client ID/secret
2. **Callback URL Mismatch**: Ensure OAuth app callback URLs match your BASE_URL
3. **JWT Issues**: Verify JWT_SECRET is set and consistent
4. **CORS Errors**: Check CORS_ORIGIN configuration for frontend integration

### Debug Mode

Enable debug mode with `DEBUG=true` to see detailed logs:
- OAuth flow steps
- Session management
- Token storage operations
- Request/response details

This comprehensive example demonstrates the full capabilities of the Gonnect library and serves as a reference for building production OAuth applications. 