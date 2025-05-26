# GitHub OAuth Setup

This guide will walk you through setting up GitHub OAuth for your Gonnect application.

## Overview

GitHub OAuth allows users to sign in with their GitHub accounts. It's popular among developers and provides access to GitHub's API for repository and user data.

**What you'll need:**
- A GitHub account
- Access to GitHub Developer Settings
- Your application's redirect URI

## Step 1: Create a GitHub OAuth App

1. Go to [GitHub.com](https://github.com) and sign in
2. Click your profile picture in the top-right corner
3. Select **"Settings"** from the dropdown
4. In the left sidebar, click **"Developer settings"**
5. Click **"OAuth Apps"** in the left sidebar
6. Click **"New OAuth App"**

## Step 2: Configure Your OAuth App

Fill out the OAuth App registration form:

### Application Details

**Application name:**
```
My Gonnect App
```

**Homepage URL:**
```
http://localhost:8080
```
(Use your production URL for production apps)

**Application description:** (Optional)
```
OAuth authentication using Gonnect
```

**Authorization callback URL:**
```
http://localhost:8080/auth/github/callback
```

> **Important**: The callback URL must exactly match what Gonnect expects. For production, use `https://yourdomain.com/auth/github/callback`

### Click "Register application"

## Step 3: Get Your Credentials

After registering, you'll see your OAuth app details:

- **Client ID**: A 20-character string (e.g., `Iv1.a1b2c3d4e5f6g7h8`)
- **Client Secret**: Click **"Generate a new client secret"** to create one

**Important**: Copy both values immediately and store them securely. The client secret is only shown once.

## Step 4: Configure Gonnect

Add GitHub OAuth to your Gonnect application:

```go
package main

import (
    "os"
    "github.com/megascan/Gonnect"
)

func main() {
    auth := gonnect.New("http://localhost:8080")
    
    // Add GitHub OAuth
    auth.GitHub(
        os.Getenv("GITHUB_CLIENT_ID"),
        os.Getenv("GITHUB_CLIENT_SECRET"),
        "user:email", // Optional: custom scopes
    )
    
    // ... rest of your application
}
```

## Step 5: Environment Variables

Create a `.env` file in your project root:

```bash
GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
GITHUB_CLIENT_SECRET=your-client-secret-here
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

GitHub OAuth supports various scopes for different levels of access:

| Scope | Description |
|-------|-------------|
| `user` | Read/write access to profile info |
| `user:email` | Read access to user email addresses |
| `user:follow` | Follow/unfollow other users |
| `public_repo` | Read/write access to public repositories |
| `repo` | Full access to private and public repositories |
| `repo:status` | Read/write access to commit status |
| `delete_repo` | Delete repositories |
| `notifications` | Read notifications |
| `gist` | Write access to gists |
| `read:repo_hook` | Read repository hooks |
| `write:repo_hook` | Write repository hooks |
| `admin:repo_hook` | Admin access to repository hooks |
| `read:org` | Read organization membership |
| `write:org` | Write organization membership |
| `admin:org` | Admin organization access |

### Default Scopes

If you don't specify scopes, Gonnect uses these defaults:
```go
[]string{"user:email"}
```

### Custom Scopes Example

```go
auth.GitHub(clientID, clientSecret, 
    "user:email",     // Email access
    "public_repo",    // Public repository access
    "read:org",       // Organization membership
)
```

## User Data Structure

GitHub returns this user information:

```go
type User struct {
    ID        string `json:"id"`         // GitHub user ID
    Login     string `json:"login"`      // Username
    Email     string `json:"email"`      // Primary email
    Name      string `json:"name"`       // Full name
    AvatarURL string `json:"avatar_url"` // Profile picture URL
    HTMLURL   string `json:"html_url"`   // Profile page URL
    Company   string `json:"company"`    // Company name
    Blog      string `json:"blog"`       // Blog/website URL
    Location  string `json:"location"`   // Location
    Bio       string `json:"bio"`        // Biography
    PublicRepos int  `json:"public_repos"` // Number of public repos
    Followers   int  `json:"followers"`    // Number of followers
    Following   int  `json:"following"`    // Number of following
}
```

## Testing Your Setup

1. Start your Gonnect application
2. Navigate to `http://localhost:8080/auth/github`
3. You should be redirected to GitHub's authorization page
4. Click **"Authorize [your-app-name]"**
5. You should be redirected back to your application with user data

## Production Considerations

### HTTPS Requirements

GitHub requires HTTPS for production OAuth apps:
- Update your Homepage URL to use `https://`
- Update your Authorization callback URL to use `https://`

### App Verification

For apps that will be used by many users:
1. Add a detailed description
2. Upload an app logo
3. Provide terms of service and privacy policy URLs
4. Consider GitHub App instead of OAuth App for better integration

### Security Best Practices

1. **Use HTTPS in production**
2. **Validate the `state` parameter** (Gonnect does this automatically)
3. **Store client secrets securely** (environment variables, not in code)
4. **Regularly rotate client secrets**
5. **Use minimal required scopes**
6. **Monitor OAuth usage** in GitHub settings

## Troubleshooting

### Common Issues

**"The redirect_uri MUST match the registered callback URL for this application"**
- Check that your callback URL exactly matches what's configured in GitHub
- Ensure you're using the correct protocol (http vs https)
- Verify the port number and path match exactly

**"Bad verification code"**
- This usually indicates a timing issue or the code was already used
- Ensure your server time is correct
- Check for duplicate requests

**"Incorrect client credentials"**
- Verify your client ID and client secret
- Ensure they're correctly loaded from environment variables
- Check for extra spaces or characters

**"Application suspended"**
- Your OAuth app may have been suspended by GitHub
- Check your email for notifications from GitHub
- Review GitHub's terms of service

### Debug Mode

Enable debug logging in Gonnect:

```go
auth := gonnect.New("http://localhost:8080")
auth.SetDebug(true) // Enable debug logging
auth.GitHub(clientID, clientSecret)
```

## Advanced Configuration

### GitHub Enterprise

For GitHub Enterprise Server:

```go
// Configure for GitHub Enterprise
auth := gonnect.New("http://localhost:8080")
auth.SetGitHubBaseURL("https://github.your-company.com") // Enterprise URL
auth.GitHub(clientID, clientSecret)
```

### Custom User Agent

```go
// Set custom user agent for API requests
auth.SetUserAgent("MyApp/1.0")
auth.GitHub(clientID, clientSecret)
```

### Rate Limiting

GitHub has rate limits for OAuth apps:
- 5,000 requests per hour per authenticated user
- 60 requests per hour for unauthenticated requests

Gonnect handles rate limiting automatically, but you can monitor usage:

```go
// Check rate limit status
user, err := auth.ValidateRequest(r)
if err != nil {
    // Handle rate limit errors
}
```

## GitHub Apps vs OAuth Apps

Consider using GitHub Apps instead of OAuth Apps for:

### GitHub Apps (Recommended for most use cases)
- **Better security**: Fine-grained permissions
- **Higher rate limits**: 15,000 requests per hour
- **Installation-based**: Install on specific repositories
- **Webhook support**: Built-in webhook handling

### OAuth Apps (Good for user authentication)
- **User-centric**: Acts on behalf of users
- **Simpler setup**: Easier to configure
- **Broader access**: Can access all user's repositories (with permission)

## Migrating to GitHub Apps

If you need GitHub App functionality:

1. Create a GitHub App in Developer Settings
2. Generate a private key
3. Use a GitHub App library alongside Gonnect for OAuth
4. Handle installation webhooks separately

## Next Steps

- **[Discord OAuth Setup](discord.md)** - Add Discord authentication
- **[Integration Patterns](../integration-patterns/)** - Choose your architecture
- **[API Reference](../../api-reference/)** - Explore Gonnect's API
- **[Troubleshooting](../../troubleshooting/)** - Common issues and solutions

## Resources

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [GitHub Developer Settings](https://github.com/settings/developers)
- [GitHub API Documentation](https://docs.github.com/en/rest)
- [GitHub Apps vs OAuth Apps](https://docs.github.com/en/developers/apps/getting-started-with-apps/about-apps) 