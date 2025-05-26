# Google OAuth Setup

This guide will walk you through setting up Google OAuth for your Gonnect application.

## Overview

Google OAuth 2.0 allows users to sign in with their Google accounts. It supports OpenID Connect for identity verification and provides access to Google APIs.

**What you'll need:**
- A Google account
- Access to Google Cloud Console
- Your application's redirect URI

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click **"Select a project"** dropdown at the top
3. Click **"New Project"**
4. Enter your project name (e.g., "My OAuth App")
5. Select your organization (if applicable)
6. Click **"Create"**

## Step 2: Enable Google+ API

1. In the Google Cloud Console, ensure your project is selected
2. Go to **APIs & Services** → **Library**
3. Search for **"Google+ API"**
4. Click on **"Google+ API"**
5. Click **"Enable"**

> **Note**: Google+ API is required for basic profile information even though Google+ is deprecated.

## Step 3: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Choose **"External"** user type (unless you have a Google Workspace)
3. Click **"Create"**

### Fill out the OAuth consent screen:

**App Information:**
- **App name**: Your application name
- **User support email**: Your email address
- **App logo**: (Optional) Upload your app logo

**App domain** (Optional but recommended):
- **Application home page**: `http://localhost:8080` (for development)
- **Application privacy policy link**: Your privacy policy URL
- **Application terms of service link**: Your terms of service URL

**Authorized domains:**
- Add `localhost` for development
- Add your production domain for production

**Developer contact information:**
- Add your email address

4. Click **"Save and Continue"**

### Scopes (Step 2):
1. Click **"Add or Remove Scopes"**
2. Select these scopes:
   - `../auth/userinfo.email`
   - `../auth/userinfo.profile`
   - `openid`
3. Click **"Update"**
4. Click **"Save and Continue"**

### Test Users (Step 3):
1. Click **"Add Users"**
2. Add email addresses of users who can test your app
3. Click **"Save and Continue"**

### Summary (Step 4):
1. Review your settings
2. Click **"Back to Dashboard"**

## Step 4: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **"Create Credentials"** → **"OAuth client ID"**
3. Choose **"Web application"** as the application type
4. Enter a name for your OAuth client (e.g., "Gonnect Web Client")

### Configure Authorized Redirect URIs:

**For Development:**
```
http://localhost:8080/auth/google/callback
```

**For Production:**
```
https://yourdomain.com/auth/google/callback
```

5. Click **"Create"**

## Step 5: Get Your Credentials

After creating the OAuth client, you'll see a dialog with:
- **Client ID**: A long string ending in `.apps.googleusercontent.com`
- **Client Secret**: A shorter secret string

**Important**: Copy these values immediately and store them securely.

## Step 6: Configure Gonnect

Add Google OAuth to your Gonnect application:

```go
package main

import (
    "os"
    "github.com/megascan/Gonnect"
)

func main() {
    auth := gonnect.New("http://localhost:8080")
    
    // Add Google OAuth
    auth.Google(
        os.Getenv("GOOGLE_CLIENT_ID"),
        os.Getenv("GOOGLE_CLIENT_SECRET"),
        "openid", "profile", "email", // Optional: custom scopes
    )
    
    // ... rest of your application
}
```

## Step 7: Environment Variables

Create a `.env` file in your project root:

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
```

Load environment variables in your application:

```go
import (
    "github.com/joho/godotenv"
    "log"
)

func init() {
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found")
    }
}
```

## Available Scopes

Google OAuth supports many scopes. Common ones for Gonnect:

| Scope | Description |
|-------|-------------|
| `openid` | OpenID Connect authentication |
| `profile` | Basic profile information |
| `email` | Email address |
| `https://www.googleapis.com/auth/userinfo.profile` | Full profile access |
| `https://www.googleapis.com/auth/userinfo.email` | Email access |

### Default Scopes

If you don't specify scopes, Gonnect uses these defaults:
```go
[]string{"openid", "profile", "email"}
```

### Custom Scopes Example

```go
auth.Google(clientID, clientSecret, 
    "openid", 
    "profile", 
    "email",
    "https://www.googleapis.com/auth/calendar.readonly", // Calendar access
)
```

## User Data Structure

Google returns this user information:

```go
type User struct {
    ID        string `json:"id"`         // Google user ID
    Email     string `json:"email"`      // Email address
    Name      string `json:"name"`       // Full name
    FirstName string `json:"given_name"` // First name
    LastName  string `json:"family_name"`// Last name
    AvatarURL string `json:"picture"`    // Profile picture URL
    Verified  bool   `json:"email_verified"` // Email verification status
}
```

## Testing Your Setup

1. Start your Gonnect application
2. Navigate to `http://localhost:8080/auth/google`
3. You should be redirected to Google's OAuth consent screen
4. Sign in with your Google account
5. Grant permissions to your application
6. You should be redirected back to your application with user data

## Production Considerations

### Domain Verification

For production apps:
1. Verify your domain in Google Search Console
2. Add verified domains to your OAuth consent screen
3. Update redirect URIs to use HTTPS

### App Verification

Google may require app verification for:
- Apps requesting sensitive scopes
- Apps with many users
- Apps in production

### Security Best Practices

1. **Use HTTPS in production**
2. **Validate the `state` parameter** (Gonnect does this automatically)
3. **Store client secrets securely** (environment variables, not in code)
4. **Regularly rotate client secrets**
5. **Monitor OAuth usage** in Google Cloud Console

## Troubleshooting

### Common Issues

**"Error 400: redirect_uri_mismatch"**
- Check that your redirect URI exactly matches what's configured in Google Cloud Console
- Ensure you're using the correct protocol (http vs https)
- Verify the port number matches

**"Error 403: access_denied"**
- User denied permission
- Check if user is added to test users (for unverified apps)

**"Error 400: invalid_client"**
- Check your client ID and client secret
- Ensure they're correctly loaded from environment variables

**"This app isn't verified"**
- Add test users to your OAuth consent screen
- Or go through Google's app verification process

### Debug Mode

Enable debug logging in Gonnect:

```go
auth := gonnect.New("http://localhost:8080")
auth.SetDebug(true) // Enable debug logging
auth.Google(clientID, clientSecret)
```

## Advanced Configuration

### Custom Redirect URI

```go
// Custom callback path
auth := gonnect.New("http://localhost:8080")
auth.SetCallbackPath("/custom/callback") // Default: /auth/{provider}/callback
auth.Google(clientID, clientSecret)
```

### Additional Parameters

```go
// Add custom OAuth parameters
auth.Google(clientID, clientSecret, "openid", "profile", "email")
// Gonnect automatically handles:
// - state parameter for CSRF protection
// - response_type=code for authorization code flow
// - access_type=offline for refresh tokens (if needed)
```

## Next Steps

- **[GitHub OAuth Setup](github.md)** - Add GitHub authentication
- **[Integration Patterns](../integration-patterns/)** - Choose your architecture
- **[API Reference](../../api-reference/)** - Explore Gonnect's API
- **[Troubleshooting](../../troubleshooting/)** - Common issues and solutions

## Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OpenID Connect](https://openid.net/connect/)
- [Google API Scopes](https://developers.google.com/identity/protocols/oauth2/scopes) 