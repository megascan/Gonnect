// Package main demonstrates basic usage of the Gonnect authentication library
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/megascan/gonnect"
)

// HTML templates for the example
const indexTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Gonnect Example</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .user-info { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .login-buttons a { 
            display: inline-block; 
            margin: 10px; 
            padding: 10px 20px; 
            background: #007cba; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
        }
        .login-buttons a:hover { background: #005a87; }
    </style>
</head>
<body>
    <h1>Gonnect Authentication Example</h1>
    
    {{if .User}}
        <div class="user-info">
            <h2>Welcome, {{.User.Name}}!</h2>
            <p><strong>Email:</strong> {{.User.Email}}</p>
            <p><strong>ID:</strong> {{.User.ID}}</p>
            {{if .User.AvatarURL}}
                <p><img src="{{.User.AvatarURL}}" alt="Avatar" style="width: 50px; height: 50px; border-radius: 25px;"></p>
            {{end}}
            <p><a href="/auth/logout">Logout</a></p>
        </div>
    {{else}}
        <p>Please login to continue:</p>
        <div class="login-buttons">
            <a href="/auth/google">Login with Google</a>
            <a href="/auth/github">Login with GitHub</a>
            <a href="/auth/discord">Login with Discord</a>
            <a href="/auth/microsoft">Login with Microsoft</a>
        </div>
    {{end}}
    
    <hr>
    <h3>Available Providers:</h3>
    <ul>
        {{range .Providers}}
            <li>{{.}}</li>
        {{end}}
    </ul>
</body>
</html>
`

const protectedTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Gonnect Example</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .protected { background: #e8f5e8; padding: 20px; border-radius: 5px; border: 2px solid #4caf50; }
        .user-info { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 15px; padding: 8px 16px; background: #007cba; color: white; text-decoration: none; border-radius: 3px; }
        .nav a:hover { background: #005a87; }
        .logout { background: #dc3545 !important; }
        .logout:hover { background: #c82333 !important; }
    </style>
</head>
<body>
    <h1>🎉 Welcome to Your Dashboard!</h1>
    
    <div class="protected">
        <h2>🔒 You are successfully authenticated!</h2>
        <p>Hello {{.User.Name}}, welcome to the protected area!</p>
    </div>
    
    <div class="user-info">
        <h3>Your Profile Information:</h3>
        <p><strong>Name:</strong> {{.User.Name}}</p>
        <p><strong>Email:</strong> {{.User.Email}}</p>
        <p><strong>User ID:</strong> {{.User.ID}}</p>
        {{if .User.AvatarURL}}
            <p><strong>Avatar:</strong> <img src="{{.User.AvatarURL}}" alt="Avatar" style="width: 40px; height: 40px; border-radius: 20px; vertical-align: middle;"></p>
        {{end}}
        {{if .User.Username}}
            <p><strong>Username:</strong> {{.User.Username}}</p>
        {{end}}
        {{if .User.Locale}}
            <p><strong>Locale:</strong> {{.User.Locale}}</p>
        {{end}}
    </div>
    
    <div class="nav">
        <a href="/optional">Optional Auth Example</a>
        <a href="/api/user">API User Info</a>
        <a href="/health">Health Check</a>
        <a href="/auth/logout" class="logout">Logout</a>
    </div>
    
    <hr>
    <p><small>💡 This page is automatically shown when you log in. If you visit the home page (/) while logged in, you'll be redirected here.</small></p>
</body>
</html>
`

func main() {
	// Get configuration from environment variables
	baseURL := getEnv("BASE_URL", "http://localhost:8080")

	// Provider credentials
	googleClientID := getEnv("GOOGLE_CLIENT_ID", "507461363744-sie2cc8q911bj4el2g1ehpav5fk9u3gk.apps.googleusercontent.com")
	googleClientSecret := getEnv("GOOGLE_CLIENT_SECRET", "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")
	githubClientID := getEnv("GITHUB_CLIENT_ID", "Iv23litRAeVESRlz8vw0")
	githubClientSecret := getEnv("GITHUB_CLIENT_SECRET", "e66c69d69f1df460ec02a7b4406a8a0a1ab8e2a9")
	discordClientID := getEnv("DISCORD_CLIENT_ID", "1376581354724266084")
	discordClientSecret := getEnv("DISCORD_CLIENT_SECRET", "CbA_yP1i_9JsHWF5eCqvz-xh6vgWd9E6")
	microsoftClientID := getEnv("MICROSOFT_CLIENT_ID", "")
	microsoftClientSecret := getEnv("MICROSOFT_CLIENT_SECRET", "")

	// Create Gonnect instance
	auth := gonnect.New(baseURL)

	// Configure providers (only if credentials are provided)
	providersConfigured := 0

	if googleClientID != "" && googleClientSecret != "" {
		auth.Google(googleClientID, googleClientSecret, "openid", "profile", "email")
		log.Println("✓ Google OAuth configured")
		providersConfigured++
	} else {
		log.Println("⚠ Google OAuth not configured (missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET)")
	}

	if githubClientID != "" && githubClientSecret != "" {
		auth.GitHub(githubClientID, githubClientSecret, "user:email")
		log.Println("✓ GitHub OAuth configured")
		providersConfigured++
	} else {
		log.Println("⚠ GitHub OAuth not configured (missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET)")
	}

	if discordClientID != "" && discordClientSecret != "" {
		auth.Discord(discordClientID, discordClientSecret, "identify", "email", "guilds")
		log.Println("✓ Discord OAuth configured")
		providersConfigured++
	} else {
		log.Println("⚠ Discord OAuth not configured (missing DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET)")
	}

	if microsoftClientID != "" && microsoftClientSecret != "" {
		auth.Microsoft(microsoftClientID, microsoftClientSecret, "openid", "profile", "email")
		log.Println("✓ Microsoft OAuth configured")
		providersConfigured++
	} else {
		log.Println("⚠ Microsoft OAuth not configured (missing MICROSOFT_CLIENT_ID or MICROSOFT_CLIENT_SECRET)")
	}

	if providersConfigured == 0 {
		log.Println("⚠ No OAuth providers configured! Adding demo providers for testing...")
		// Add demo providers for testing the interface
		auth.GitHub("demo-github-id", "demo-github-secret", "user:email")
		auth.Discord("demo-discord-id", "demo-discord-secret", "identify", "email")
		auth.Microsoft("demo-microsoft-id", "demo-microsoft-secret")
	}

	// Configure Gonnect
	auth.SetSessionName("gonnect_example_session")
	auth.OnSuccess("/protected") // Redirect to protected page after successful login
	auth.OnFailure("/")
	auth.WithLogger(gonnect.NewSimpleLogger(true))

	// Parse templates
	indexTmpl := template.Must(template.New("index").Parse(indexTemplate))
	protectedTmpl := template.Must(template.New("protected").Parse(protectedTemplate))

	// Routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)

		fmt.Println("user", user)

		// If user is logged in, redirect to protected page
		if user != nil {
			http.Redirect(w, r, "/protected", http.StatusFound)
			return
		}

		// Show login page for non-authenticated users
		data := struct {
			User      *gonnect.User
			Providers []string
		}{
			User:      user,
			Providers: auth.ListProviders(),
		}
		indexTmpl.Execute(w, data)

	})

	// Protected route
	http.Handle("/protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)
		data := struct {
			User *gonnect.User
		}{
			User: user,
		}
		protectedTmpl.Execute(w, data)
	})))

	// Optional auth route (user info available if logged in)
	http.Handle("/optional", auth.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)
		if user != nil {
			fmt.Fprintf(w, "Hello %s! You are logged in.", user.Name)
		} else {
			fmt.Fprintf(w, "Hello anonymous user! <a href='/auth/google'>Login</a>")
		}
	})))

	// Mount auth handlers
	http.Handle("/auth/", auth.Handler())

	// API example endpoints
	http.HandleFunc("/api/user", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.ValidateRequest(r)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user":{"id":"%s","name":"%s","email":"%s"}}`,
			user.ID, user.Name, user.Email)
	})

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","providers":%d}`, len(auth.ListProviders()))
	})

	// Start server
	port := getEnv("PORT", "8080")
	log.Printf("🚀 Gonnect example server starting on port %s", port)
	log.Printf("📍 Visit: %s", baseURL)
	log.Printf("🔒 Protected page: %s/protected", baseURL)
	log.Printf("📊 Health check: %s/health", baseURL)

	if providersConfigured == 0 {
		log.Println("\n💡 To test with real OAuth providers, set environment variables:")
		log.Println("   # Google OAuth")
		log.Println("   export GOOGLE_CLIENT_ID=your_google_client_id")
		log.Println("   export GOOGLE_CLIENT_SECRET=your_google_client_secret")
		log.Println("   # GitHub OAuth")
		log.Println("   export GITHUB_CLIENT_ID=your_github_client_id")
		log.Println("   export GITHUB_CLIENT_SECRET=your_github_client_secret")
		log.Println("   # Discord OAuth")
		log.Println("   export DISCORD_CLIENT_ID=your_discord_client_id")
		log.Println("   export DISCORD_CLIENT_SECRET=your_discord_client_secret")
		log.Println("   # Microsoft OAuth")
		log.Println("   export MICROSOFT_CLIENT_ID=your_microsoft_client_id")
		log.Println("   export MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret")
		log.Println("   go run main.go")
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// getEnv gets an environment variable with a fallback default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
