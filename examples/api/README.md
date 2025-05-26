# Gonnect API Example

This example demonstrates how to use Gonnect as a pure JSON API without middleware. Perfect for React/Next.js frontends, mobile apps, or any client that needs to handle authentication via API calls.

## Features

- **Pure JSON API**: All responses are JSON, no HTML templates
- **No Middleware**: Manual authentication checks using `ValidateRequest()`
- **JWT Support**: Stateless authentication with JWT tokens
- **CORS Enabled**: Ready for frontend integration
- **RESTful Design**: Clean API endpoints following REST principles
- **Comprehensive Error Handling**: Proper HTTP status codes and error messages
- **Self-Documenting**: Built-in API documentation endpoint

## Quick Start

1. **Set Environment Variables** (optional, defaults provided):
```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"
export JWT_SECRET="your-super-secret-jwt-key"
export BASE_URL="http://localhost:8080"
export PORT="8080"
```

2. **Run the API**:
```bash
cd examples/api
go run main.go
```

3. **Visit the API documentation**:
```
http://localhost:8080/api/docs
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/auth/providers` | Get available OAuth providers |
| `GET` | `/api/auth/status` | Check authentication status |
| `POST` | `/api/auth/logout` | Logout user |

### OAuth Flow

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/{provider}` | Start OAuth flow (e.g., `/auth/google`) |
| `GET` | `/auth/{provider}/callback` | OAuth callback (handled automatically) |

### Protected Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/user` | Get authenticated user info |
| `GET` | `/api/user/profile` | Get user profile |
| `PUT` | `/api/user/profile` | Update user profile |

### Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | API health check |
| `GET` | `/api/docs` | API documentation |

## Usage Examples

### 1. Get Available Providers

```bash
curl http://localhost:8080/api/auth/providers
```

**Response:**
```json
{
  "success": true,
  "data": {
    "providers": {
      "google": "http://localhost:8080/auth/google",
      "github": "http://localhost:8080/auth/github"
    }
  },
  "message": "Available OAuth providers"
}
```

### 2. Check Authentication Status

```bash
curl http://localhost:8080/api/auth/status
```

**Response (not authenticated):**
```json
{
  "success": true,
  "data": {
    "authenticated": false
  },
  "message": "Authentication status"
}
```

**Response (authenticated):**
```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "user": {
      "id": "123456789",
      "email": "user@example.com",
      "name": "John Doe",
      "avatar_url": "https://example.com/avatar.jpg"
    },
    "expires_at": "2024-01-02T15:04:05Z"
  },
  "message": "Authentication status"
}
```

### 3. Get User Information (Protected)

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/user
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "123456789",
    "email": "user@example.com",
    "name": "John Doe",
    "username": "johndoe",
    "avatar_url": "https://example.com/avatar.jpg",
    "locale": "en"
  },
  "message": "User information retrieved"
}
```

### 4. Update User Profile (Protected)

```bash
curl -X PUT \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     -d '{"theme": "dark", "notifications": false}' \
     http://localhost:8080/api/user/profile
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123456789",
      "email": "user@example.com",
      "name": "John Doe"
    },
    "updates": {
      "theme": "dark",
      "notifications": false
    },
    "message": "Profile updated successfully"
  },
  "message": "Profile updated"
}
```

### 5. Logout

```bash
curl -X POST http://localhost:8080/api/auth/logout
```

**Response:**
```json
{
  "success": true,
  "message": "Successfully logged out"
}
```

## Frontend Integration

### React/Next.js Example

```javascript
// API client
class GonnectAPI {
  constructor(baseURL = 'http://localhost:8080') {
    this.baseURL = baseURL;
    this.token = localStorage.getItem('auth_token');
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    if (this.token) {
      config.headers.Authorization = `Bearer ${this.token}`;
    }

    const response = await fetch(url, config);
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.error || 'API request failed');
    }
    
    return data.data;
  }

  // Get available OAuth providers
  async getProviders() {
    return this.request('/api/auth/providers');
  }

  // Check authentication status
  async getAuthStatus() {
    return this.request('/api/auth/status');
  }

  // Get user information
  async getUser() {
    return this.request('/api/user');
  }

  // Update user profile
  async updateProfile(data) {
    return this.request('/api/user/profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // Logout
  async logout() {
    const result = await this.request('/api/auth/logout', {
      method: 'POST',
    });
    localStorage.removeItem('auth_token');
    return result;
  }

  // Start OAuth flow
  startOAuth(provider) {
    window.location.href = `${this.baseURL}/auth/${provider}`;
  }
}

// Usage in React component
function LoginButton() {
  const api = new GonnectAPI();
  const [providers, setProviders] = useState({});

  useEffect(() => {
    api.getProviders().then(setProviders);
  }, []);

  return (
    <div>
      {Object.entries(providers.providers || {}).map(([name, url]) => (
        <button
          key={name}
          onClick={() => api.startOAuth(name)}
          className="btn btn-primary"
        >
          Login with {name}
        </button>
      ))}
    </div>
  );
}
```

## Authentication Flow

1. **Frontend calls** `/api/auth/providers` to get available OAuth providers
2. **User clicks** on a provider button
3. **Frontend redirects** to `/auth/{provider}` (e.g., `/auth/google`)
4. **User completes** OAuth flow with the provider
5. **Gonnect handles** the callback and creates a session/JWT
6. **User is redirected** back to your frontend with authentication
7. **Frontend can now** make authenticated API calls using the session or JWT token

## Error Handling

All API responses follow a consistent format:

**Success Response:**
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error message describing what went wrong"
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad Request (invalid JSON, missing parameters)
- `401` - Unauthorized (authentication required)
- `405` - Method Not Allowed
- `500` - Internal Server Error

## Configuration

The API can be configured using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Base URL for OAuth callbacks |
| `PORT` | `8080` | Server port |
| `JWT_SECRET` | `your-super-secret-jwt-key-change-this-in-production` | JWT signing secret |
| `DEBUG` | `true` | Enable debug logging |
| `GOOGLE_CLIENT_ID` | (demo value) | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | (demo value) | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | (demo value) | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | (demo value) | GitHub OAuth client secret |

## Security Notes

1. **Change the JWT secret** in production
2. **Use HTTPS** in production
3. **Validate all inputs** on your frontend
4. **Store JWT tokens securely** (consider httpOnly cookies for web apps)
5. **Implement token refresh** for long-lived applications
6. **Set appropriate CORS origins** instead of `*` in production

## Differences from Middleware Example

| Feature | API Example | Middleware Example |
|---------|-------------|-------------------|
| **Authentication** | Manual `ValidateRequest()` calls | Automatic middleware |
| **Responses** | Always JSON | HTML templates |
| **Error Handling** | JSON error responses | HTTP redirects |
| **Frontend Integration** | Perfect for SPAs/mobile | Traditional web apps |
| **Flexibility** | High (manual control) | Medium (automatic) |
| **Complexity** | Higher (more code) | Lower (less code) |

This API example gives you complete control over authentication while providing a clean JSON interface for modern frontend applications. 