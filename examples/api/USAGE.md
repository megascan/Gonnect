# How to Use the Gonnect API Demo

This guide shows you how to test the Gonnect API using the included HTML demo page.

## Quick Start

1. **Start the API server**:
   ```bash
   cd examples/api
   go run main.go
   ```

2. **Open your browser** and visit:
   ```
   http://localhost:8080
   ```

3. **You'll see the demo page** with sections for:
   - Authentication status
   - OAuth provider login buttons
   - User information (when logged in)
   - Profile management
   - API testing tools

## How to Test the OAuth Flow

### Step 1: Check Available Providers
- The page automatically loads available OAuth providers
- You'll see buttons like "Login with Google" and "Login with GitHub"
- If no buttons appear, check that your environment variables are set

### Step 2: Login with OAuth
- Click on any provider button (e.g., "Login with Google")
- You'll be redirected to the provider's login page
- Complete the OAuth flow with your credentials
- You'll be redirected back to the demo page

### Step 3: View Your Information
- After successful login, you'll see:
  - ✅ Authentication status showing your name
  - Your user profile with avatar, email, and ID
  - Profile management section
  - API response showing the authentication data

### Step 4: Test API Features
- **Refresh User Info**: Updates your displayed information
- **Get Profile**: Loads your profile settings
- **Update Profile**: Change theme, notifications, language
- **Health Check**: Tests the API health endpoint
- **API Docs**: Views the API documentation
- **Logout**: Clears your session

## Understanding the API Responses

Every API call shows the raw JSON response in the "Last API Response" section:

```json
{
  "success": true,
  "data": {
    "authenticated": true,
    "user": {
      "id": "123456789",
      "email": "user@example.com",
      "name": "John Doe"
    }
  },
  "message": "Authentication status"
}
```

## Environment Variables

The demo works with these OAuth providers (set environment variables to enable):

```bash
# Google OAuth
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"

# GitHub OAuth  
export GITHUB_CLIENT_ID="your-github-client-id"
export GITHUB_CLIENT_SECRET="your-github-client-secret"

# Discord OAuth
export DISCORD_CLIENT_ID="your-discord-client-id"
export DISCORD_CLIENT_SECRET="your-discord-client-secret"

# Microsoft OAuth
export MICROSOFT_CLIENT_ID="your-microsoft-client-id"
export MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"
```

## Demo Features

### 🔍 Authentication Status
- Shows if you're logged in or not
- Displays user name and session expiry
- Auto-refreshes when you login/logout

### 🚀 OAuth Login
- Dynamic provider buttons based on configuration
- Handles the complete OAuth flow
- Redirects back to the demo page after authentication

### 👤 User Information
- Shows your profile data from the OAuth provider
- Displays avatar, name, email, ID, username, locale
- Refreshable user information

### ⚙️ Profile Management
- Simulated profile settings (theme, notifications, language)
- Demonstrates PUT requests to update data
- Shows how to handle form data in API calls

### 🧪 API Testing
- Health check endpoint
- API documentation endpoint
- Real-time response display
- Error handling demonstration

### 📡 Response Viewer
- Shows all API responses in real-time
- Formatted JSON with timestamps
- HTTP status codes
- Scrollable response history

## Browser Developer Tools

Open your browser's developer tools (F12) to see:
- Network requests to the API
- Console logs for debugging
- CORS headers in action
- Session cookies being set

## Troubleshooting

### No OAuth Providers Showing
- Check that environment variables are set
- Restart the server after setting variables
- Check the console for error messages

### CORS Errors
- Make sure you're accessing via `http://localhost:8080`
- Don't use `127.0.0.1` or other addresses
- Check that the API server is running

### Authentication Not Working
- Clear your browser cookies
- Check that OAuth credentials are valid
- Verify redirect URLs match your OAuth app settings

### API Calls Failing
- Check the "Last API Response" section for error details
- Verify the API server is running on port 8080
- Check browser console for JavaScript errors

## Next Steps

This demo shows you how to:
1. **Integrate Gonnect** into your frontend application
2. **Handle OAuth flows** with redirects
3. **Make authenticated API calls** using sessions
4. **Display user information** from OAuth providers
5. **Handle errors** gracefully in your UI

You can use this HTML page as a starting point for your own frontend application, or adapt the JavaScript code for React, Vue, Angular, or any other framework. 