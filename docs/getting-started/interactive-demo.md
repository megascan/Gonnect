# Interactive Demo

Experience Gonnect's full capabilities with our interactive demo - a beautiful web interface that showcases real-time OAuth authentication, API testing, and user management.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/megascan/gonnect.git
cd gonnect/examples/api

# Run the demo
go run main.go

# Open your browser to http://localhost:8080
```

That's it! The demo runs with built-in demo credentials, so you can test OAuth flows immediately.

## 🎨 What You'll See

The interactive demo provides a comprehensive showcase of Gonnect's features:

### 🏠 Landing Page
- **Beautiful modern UI** with responsive design
- **Real-time authentication status** display
- **Provider selection** with branded login buttons
- **Live API response viewer** showing JSON responses

### 🔐 OAuth Providers
Test authentication with multiple providers:
- **Google OAuth** - Full OpenID Connect flow
- **GitHub OAuth** - Developer-friendly authentication
- **Discord OAuth** - Gaming community integration
- **Microsoft OAuth** - Enterprise authentication
- **And 10 more providers!**

### 👤 User Management
After logging in, explore:
- **User profile display** with avatar, name, and email
- **Profile editing** with real-time updates
- **Session management** and logout functionality
- **Token information** (access tokens, expiry, etc.)

### 🧪 API Testing Tools
Interactive tools to test the API:
- **Health check** endpoint testing
- **Authentication status** verification
- **Provider listing** and configuration
- **User data** retrieval and updates
- **Real-time response viewer** with timestamps

## 🔧 Demo Features

### Authentication Flow
1. **Provider Selection** - Choose from 14 OAuth providers
2. **OAuth Redirect** - Seamless redirect to provider
3. **Callback Handling** - Automatic token exchange
4. **User Creation** - Profile data extraction
5. **Session Management** - Secure session storage

### API Endpoints
The demo exposes a complete REST API:

```
GET  /api/auth/providers     # List available providers
GET  /api/auth/status        # Check authentication status
POST /api/auth/logout        # Logout current user
GET  /api/user               # Get user information
GET  /api/user/profile       # Get detailed profile
PUT  /api/user/profile       # Update user profile
GET  /api/health             # API health check
GET  /api/docs               # API documentation
```

### Frontend Features
- **Responsive Design** - Works on desktop and mobile
- **Real-time Updates** - Live status and response display
- **Error Handling** - Graceful error messages
- **Loading States** - Visual feedback during operations
- **CORS Support** - Ready for frontend integration

## 🎯 Learning Objectives

Use the demo to understand:

### OAuth Flow Mechanics
- **Authorization URLs** - How OAuth redirects work
- **State Parameters** - CSRF protection in action
- **Token Exchange** - Authorization code to access token
- **User Info Retrieval** - Profile data extraction

### API Integration Patterns
- **Session-based Auth** - Traditional web app pattern
- **JWT Tokens** - Stateless API authentication
- **CORS Handling** - Cross-origin request support
- **Error Responses** - Proper HTTP status codes

### User Experience
- **Seamless Login** - One-click OAuth authentication
- **Profile Management** - User data handling
- **Session Persistence** - Login state maintenance
- **Logout Flow** - Clean session termination

## 🔍 Code Exploration

The demo is built with clean, well-documented code:

### Backend Structure
```
examples/api/
├── main.go           # Main server with all endpoints
├── index.html        # Interactive demo frontend
├── README.md         # API documentation
└── USAGE.md          # Step-by-step usage guide
```

### Key Code Patterns

**OAuth Setup**
```go
auth := gonnect.New("http://localhost:8080")
auth.Google("client-id", "client-secret")
auth.GitHub("client-id", "client-secret")
```

**API Authentication**
```go
user, err := auth.ValidateRequest(r)
if err != nil {
    http.Error(w, `{"error":"unauthorized"}`, 401)
    return
}
```

**CORS Configuration**
```go
w.Header().Set("Access-Control-Allow-Origin", "*")
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

## 🧪 Testing Scenarios

### Basic OAuth Flow
1. Click "Login with Google"
2. Complete OAuth on Google
3. Return to demo with user info
4. Explore user profile data

### API Testing
1. Use "Check Auth Status" button
2. Test "Get User Info" endpoint
3. Try "Update Profile" functionality
4. Monitor responses in real-time

### Error Handling
1. Try accessing protected endpoints without login
2. Test invalid API requests
3. Observe error messages and status codes

### Multiple Providers
1. Logout from current provider
2. Login with different provider
3. Compare user data structures
4. Test provider-specific features

## 🔧 Customization

### Add Your OAuth Credentials

Replace demo credentials with real ones:

```go
// In main.go, replace:
auth.Google("demo-google-client-id", "demo-google-client-secret")

// With your credentials:
auth.Google(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"))
```

### Environment Variables

Create `.env` file:
```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Add More Providers

```go
// Add additional providers
auth.Discord(discordID, discordSecret)
auth.Microsoft(msID, msSecret)
auth.Apple(appleID, appleSecret)
```

## 📱 Mobile Testing

The demo is fully responsive and works great on mobile:

1. **Open on mobile browser** - `http://your-ip:8080`
2. **Test touch interactions** - Tap login buttons
3. **Verify responsive design** - UI adapts to screen size
4. **Test OAuth redirects** - Mobile OAuth flows

## 🚀 Production Deployment

The demo can be deployed to production:

### Docker Deployment
```bash
# Build Docker image
docker build -t gonnect-demo .

# Run container
docker run -p 8080:8080 \
  -e GOOGLE_CLIENT_ID=your-id \
  -e GOOGLE_CLIENT_SECRET=your-secret \
  gonnect-demo
```

### Environment Configuration
```bash
export BASE_URL=https://your-domain.com
export PORT=8080
export JWT_SECRET=your-jwt-secret
```

## 🎓 Next Steps

After exploring the demo:

1. **[Quick Start](quick-start.md)** - Build your own OAuth app
2. **[OAuth Setup](../guides/oauth-setup/)** - Configure real providers
3. **[API Integration](../guides/integration-patterns/api-first.md)** - Build APIs
4. **[React Integration](../guides/integration-patterns/react-frontend.md)** - Frontend apps

## 💡 Pro Tips

### Demo Best Practices
- **Try multiple providers** to see data differences
- **Test error scenarios** to understand error handling
- **Monitor network tab** to see API requests
- **Check console logs** for debug information

### Learning Approach
- **Start with Google/GitHub** - Easiest to set up
- **Explore API responses** - Understand data structures
- **Test edge cases** - Logout, refresh, back button
- **Read the code** - Learn implementation patterns

### Development Insights
- **Session vs JWT** - Compare authentication methods
- **CORS configuration** - Understand cross-origin setup
- **Error handling** - See proper API error responses
- **User data mapping** - How providers differ

## 🔗 Related Resources

- **[API Documentation](../api-reference/)** - Complete API reference
- **[Provider Setup](../guides/oauth-setup/)** - OAuth configuration guides
- **[Integration Patterns](../guides/integration-patterns/)** - Architecture patterns
- **[Troubleshooting](../troubleshooting/)** - Common issues and solutions

---

**Ready to build?** The interactive demo shows you everything Gonnect can do. Now it's time to [create your own OAuth application](quick-start.md)! 