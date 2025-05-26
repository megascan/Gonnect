// Package main demonstrates comprehensive usage of the Gonnect authentication library
// This example showcases:
// - Multiple OAuth providers (Google, GitHub, Discord, Microsoft, Apple, Facebook, etc.)
// - JWT token authentication for APIs
// - Session-based authentication for web
// - Custom token storage
// - Middleware usage (RequireAuth, OptionalAuth)
// - API endpoints with JSON responses
// - CORS support for frontend integration
// - Error handling and logging
// - User profile management
// - Token refresh functionality
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/megascan/gonnect"
)

// UserProfile represents extended user information
type UserProfile struct {
	*gonnect.User
	LastLogin   time.Time              `json:"last_login"`
	LoginCount  int                    `json:"login_count"`
	Providers   []string               `json:"providers"`
	Preferences map[string]interface{} `json:"preferences"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// CustomTokenStore implements a more sophisticated token storage
type CustomTokenStore struct {
	tokens map[string]map[string]gonnect.Token // userID -> provider -> token
	users  map[string]*UserProfile             // userID -> profile
}

// NewCustomTokenStore creates a new custom token store
func NewCustomTokenStore() *CustomTokenStore {
	return &CustomTokenStore{
		tokens: make(map[string]map[string]gonnect.Token),
		users:  make(map[string]*UserProfile),
	}
}

// StoreToken stores a token and updates user profile
func (c *CustomTokenStore) StoreToken(ctx context.Context, userID string, provider string, token gonnect.Token) error {
	if c.tokens[userID] == nil {
		c.tokens[userID] = make(map[string]gonnect.Token)
	}
	c.tokens[userID][provider] = token

	// Update user profile
	if profile, exists := c.users[userID]; exists {
		profile.LastLogin = time.Now()
		profile.LoginCount++
		profile.UpdatedAt = time.Now()

		// Add provider if not already present
		providerExists := false
		for _, p := range profile.Providers {
			if p == provider {
				providerExists = true
				break
			}
		}
		if !providerExists {
			profile.Providers = append(profile.Providers, provider)
		}
	}

	log.Printf("Token stored for user %s via provider %s", userID, provider)
	return nil
}

// GetToken retrieves a token for a user and provider
func (c *CustomTokenStore) GetToken(ctx context.Context, userID string, provider string) (gonnect.Token, error) {
	if userTokens, exists := c.tokens[userID]; exists {
		if token, exists := userTokens[provider]; exists {
			return token, nil
		}
	}
	return gonnect.Token{}, gonnect.NewError(gonnect.ErrTypeToken, "token not found")
}

// DeleteToken removes a token for a user and provider
func (c *CustomTokenStore) DeleteToken(ctx context.Context, userID string, provider string) error {
	if userTokens, exists := c.tokens[userID]; exists {
		delete(userTokens, provider)
		if len(userTokens) == 0 {
			delete(c.tokens, userID)
		}
	}
	return nil
}

// RefreshToken refreshes a token for a user and provider
func (c *CustomTokenStore) RefreshToken(ctx context.Context, userID string, provider string) (gonnect.Token, error) {
	// In a real implementation, this would call the provider's refresh endpoint
	return c.GetToken(ctx, userID, provider)
}

// CreateUserProfile creates or updates a user profile
func (c *CustomTokenStore) CreateUserProfile(user *gonnect.User, provider string) *UserProfile {
	profile, exists := c.users[user.ID]
	if !exists {
		profile = &UserProfile{
			User:        user,
			LastLogin:   time.Now(),
			LoginCount:  1,
			Providers:   []string{provider},
			Preferences: make(map[string]interface{}),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		c.users[user.ID] = profile
		log.Printf("Created new user profile for %s (%s)", user.Name, user.ID)
	} else {
		// Update existing profile
		profile.User = user
		profile.LastLogin = time.Now()
		profile.LoginCount++
		profile.UpdatedAt = time.Now()
		log.Printf("Updated user profile for %s (%s)", user.Name, user.ID)
	}
	return profile
}

// GetUserProfile retrieves a user profile
func (c *CustomTokenStore) GetUserProfile(userID string) (*UserProfile, bool) {
	profile, exists := c.users[userID]
	return profile, exists
}

// ListUsers returns all user profiles
func (c *CustomTokenStore) ListUsers() []*UserProfile {
	var profiles []*UserProfile
	for _, profile := range c.users {
		profiles = append(profiles, profile)
	}
	return profiles
}

// Application represents our web application
type Application struct {
	auth       *gonnect.Gonnect
	tokenStore *CustomTokenStore
	templates  map[string]*template.Template
	config     *Config
}

// Config holds application configuration
type Config struct {
	BaseURL    string
	Port       string
	JWTSecret  string
	CORSOrigin string
	Debug      bool
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		BaseURL:    getEnv("BASE_URL", "http://localhost:8080"),
		Port:       getEnv("PORT", "8080"),
		JWTSecret:  getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
		CORSOrigin: getEnv("CORS_ORIGIN", "*"),
		Debug:      getEnv("DEBUG", "true") == "true",
	}
}

func main() {
	config := LoadConfig()

	// Create custom token store
	tokenStore := NewCustomTokenStore()

	// Create Gonnect instance with comprehensive configuration
	auth := gonnect.New(config.BaseURL)

	// Configure all available providers
	configureProviders(auth, config)

	// Configure Gonnect with advanced options
	auth.SetSessionName("gonnect_comprehensive_session")
	auth.OnSuccess("/dashboard")
	auth.OnFailure("/?error=auth_failed")
	auth.WithLogger(gonnect.NewSimpleLogger(config.Debug))
	auth.WithTokenStore(tokenStore)
	auth.EnableJWT(config.JWTSecret)
	auth.EnableCORS()

	// Create application instance
	app := &Application{
		auth:       auth,
		tokenStore: tokenStore,
		templates:  loadTemplates(),
		config:     config,
	}

	// Setup routes
	app.setupRoutes()

	// Start server
	log.Printf("🚀 Gonnect Comprehensive Example starting on port %s", config.Port)
	log.Printf("📍 Visit: %s", config.BaseURL)
	log.Printf("🔒 Dashboard: %s/dashboard", config.BaseURL)
	log.Printf("📊 Admin: %s/admin", config.BaseURL)
	log.Printf("🔌 API: %s/api/", config.BaseURL)

	if config.Debug {
		log.Println("🐛 Debug mode enabled")
	}

	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

// configureProviders sets up all OAuth providers
func configureProviders(auth *gonnect.Gonnect, config *Config) {
	providersConfigured := 0

	// Google OAuth
	if clientID, clientSecret := getEnv("GOOGLE_CLIENT_ID", "507461363744-sie2cc8q911bj4el2g1ehpav5fk9u3gk.apps.googleusercontent.com"), getEnv("GOOGLE_CLIENT_SECRET", "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"); clientID != "" && clientSecret != "" {
		auth.Google(clientID, clientSecret, "openid", "profile", "email")
		log.Println("✓ Google OAuth configured")
		providersConfigured++
	}

	// GitHub OAuth
	if clientID, clientSecret := getEnv("GITHUB_CLIENT_ID", "Iv23litRAeVESRlz8vw0"), getEnv("GITHUB_CLIENT_SECRET", "e66c69d69f1df460ec02a7b4406a8a0a1ab8e2a9"); clientID != "" && clientSecret != "" {
		auth.GitHub(clientID, clientSecret, "user:email", "read:user")
		log.Println("✓ GitHub OAuth configured")
		providersConfigured++
	}

	// Discord OAuth
	if clientID, clientSecret := getEnv("DISCORD_CLIENT_ID", ""), getEnv("DISCORD_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Discord(clientID, clientSecret, "identify", "email", "guilds")
		log.Println("✓ Discord OAuth configured")
		providersConfigured++
	}

	// Microsoft OAuth
	if clientID, clientSecret := getEnv("MICROSOFT_CLIENT_ID", ""), getEnv("MICROSOFT_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Microsoft(clientID, clientSecret, "openid", "profile", "email", "User.Read")
		log.Println("✓ Microsoft OAuth configured")
		providersConfigured++
	}

	// Apple OAuth
	if clientID, clientSecret := getEnv("APPLE_CLIENT_ID", ""), getEnv("APPLE_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Apple(clientID, clientSecret, "name", "email")
		log.Println("✓ Apple OAuth configured")
		providersConfigured++
	}

	// Facebook OAuth
	if clientID, clientSecret := getEnv("FACEBOOK_CLIENT_ID", ""), getEnv("FACEBOOK_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Facebook(clientID, clientSecret, "email", "public_profile")
		log.Println("✓ Facebook OAuth configured")
		providersConfigured++
	}

	// Twitter OAuth
	if clientID, clientSecret := getEnv("TWITTER_CLIENT_ID", ""), getEnv("TWITTER_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Twitter(clientID, clientSecret, "users.read", "tweet.read")
		log.Println("✓ Twitter OAuth configured")
		providersConfigured++
	}

	// LinkedIn OAuth
	if clientID, clientSecret := getEnv("LINKEDIN_CLIENT_ID", ""), getEnv("LINKEDIN_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.LinkedIn(clientID, clientSecret, "r_liteprofile", "r_emailaddress")
		log.Println("✓ LinkedIn OAuth configured")
		providersConfigured++
	}

	// Steam OpenID
	auth.Steam()
	log.Println("✓ Steam OpenID configured")
	providersConfigured++

	// Additional providers
	if clientID, clientSecret := getEnv("AMAZON_CLIENT_ID", ""), getEnv("AMAZON_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Amazon(clientID, clientSecret, "profile")
		log.Println("✓ Amazon OAuth configured")
		providersConfigured++
	}

	if clientID, clientSecret := getEnv("GITLAB_CLIENT_ID", ""), getEnv("GITLAB_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.GitLab(clientID, clientSecret, "openid", "profile", "email")
		log.Println("✓ GitLab OAuth configured")
		providersConfigured++
	}

	if clientID, clientSecret := getEnv("YAHOO_CLIENT_ID", ""), getEnv("YAHOO_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Yahoo(clientID, clientSecret, "openid", "profile", "email")
		log.Println("✓ Yahoo OAuth configured")
		providersConfigured++
	}

	if clientID, clientSecret := getEnv("YANDEX_CLIENT_ID", ""), getEnv("YANDEX_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Yandex(clientID, clientSecret, "login:info", "login:email")
		log.Println("✓ Yandex OAuth configured")
		providersConfigured++
	}

	if clientID, clientSecret := getEnv("DROPBOX_CLIENT_ID", ""), getEnv("DROPBOX_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Dropbox(clientID, clientSecret, "account_info.read")
		log.Println("✓ Dropbox OAuth configured")
		providersConfigured++
	}

	log.Printf("📊 Total providers configured: %d", providersConfigured)

	if providersConfigured == 0 {
		log.Println("⚠️ No OAuth providers configured! Please set environment variables.")
		log.Println("💡 Example: export GOOGLE_CLIENT_ID=your_id GOOGLE_CLIENT_SECRET=your_secret")
	}
}

// setupRoutes configures all application routes
func (app *Application) setupRoutes() {
	// Static file serving (for CSS, JS, images)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	// Public routes
	http.HandleFunc("/", app.handleHome)
	http.HandleFunc("/about", app.handleAbout)
	http.HandleFunc("/privacy", app.handlePrivacy)

	// Authentication routes (handled by Gonnect)
	http.Handle("/auth/", app.auth.Handler())

	// Protected web routes
	http.Handle("/dashboard", app.auth.RequireAuth(http.HandlerFunc(app.handleDashboard)))
	http.Handle("/profile", app.auth.RequireAuth(http.HandlerFunc(app.handleProfile)))
	http.Handle("/settings", app.auth.RequireAuth(http.HandlerFunc(app.handleSettings)))

	// Admin routes (require authentication)
	http.Handle("/admin", app.auth.RequireAuth(http.HandlerFunc(app.handleAdmin)))
	http.Handle("/admin/users", app.auth.RequireAuth(http.HandlerFunc(app.handleAdminUsers)))

	// API routes with CORS support
	http.HandleFunc("/api/auth/status", app.handleAPIAuthStatus)
	http.Handle("/api/user", app.auth.RequireAuth(http.HandlerFunc(app.handleAPIUser)))
	http.Handle("/api/user/profile", app.auth.RequireAuth(http.HandlerFunc(app.handleAPIUserProfile)))
	http.Handle("/api/user/tokens", app.auth.RequireAuth(http.HandlerFunc(app.handleAPIUserTokens)))
	http.Handle("/api/admin/users", app.auth.RequireAuth(http.HandlerFunc(app.handleAPIAdminUsers)))
	http.Handle("/api/admin/stats", app.auth.RequireAuth(http.HandlerFunc(app.handleAPIAdminStats)))

	// Optional auth routes (user info available if logged in)
	http.Handle("/optional", app.auth.OptionalAuth(http.HandlerFunc(app.handleOptionalAuth)))

	// Health and status endpoints
	http.HandleFunc("/health", app.handleHealth)
	http.HandleFunc("/status", app.handleStatus)

	// WebSocket endpoint for real-time features (if needed)
	// http.HandleFunc("/ws", app.handleWebSocket)
}

// Web route handlers

func (app *Application) handleHome(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)

	// If user is logged in, redirect to dashboard
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	data := struct {
		Title     string
		User      *gonnect.User
		Providers []string
		Error     string
	}{
		Title:     "Gonnect Comprehensive Example",
		User:      user,
		Providers: app.auth.ListProviders(),
		Error:     r.URL.Query().Get("error"),
	}

	app.renderTemplate(w, "home", data)
}

func (app *Application) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)
	if user == nil {
		// This should not happen with RequireAuth middleware, but let's be safe
		http.Redirect(w, r, "/?error=user_not_found", http.StatusFound)
		return
	}

	profile, _ := app.tokenStore.GetUserProfile(user.ID)

	data := struct {
		Title   string
		User    *gonnect.User
		Profile *UserProfile
	}{
		Title:   "Dashboard",
		User:    user,
		Profile: profile,
	}

	app.renderTemplate(w, "dashboard", data)
}

func (app *Application) handleProfile(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)
	if user == nil {
		http.Redirect(w, r, "/?error=user_not_found", http.StatusFound)
		return
	}
	profile, _ := app.tokenStore.GetUserProfile(user.ID)

	if r.Method == http.MethodPost {
		// Handle profile updates
		r.ParseForm()
		if profile != nil {
			if name := r.FormValue("name"); name != "" {
				profile.User.Name = name
			}
			if theme := r.FormValue("theme"); theme != "" {
				profile.Preferences["theme"] = theme
			}
			if notifications := r.FormValue("notifications"); notifications != "" {
				profile.Preferences["notifications"] = notifications == "on"
			}
			profile.UpdatedAt = time.Now()
		}
		http.Redirect(w, r, "/profile?updated=true", http.StatusFound)
		return
	}

	data := struct {
		Title   string
		User    *gonnect.User
		Profile *UserProfile
		Updated bool
	}{
		Title:   "Profile",
		User:    user,
		Profile: profile,
		Updated: r.URL.Query().Get("updated") == "true",
	}

	app.renderTemplate(w, "profile", data)
}

func (app *Application) handleSettings(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)
	if user == nil {
		http.Redirect(w, r, "/?error=user_not_found", http.StatusFound)
		return
	}
	profile, _ := app.tokenStore.GetUserProfile(user.ID)

	data := struct {
		Title   string
		User    *gonnect.User
		Profile *UserProfile
	}{
		Title:   "Settings",
		User:    user,
		Profile: profile,
	}

	app.renderTemplate(w, "settings", data)
}

func (app *Application) handleAdmin(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)
	users := app.tokenStore.ListUsers()

	data := struct {
		Title     string
		User      *gonnect.User
		UserCount int
		Users     []*UserProfile
	}{
		Title:     "Admin Dashboard",
		User:      user,
		UserCount: len(users),
		Users:     users,
	}

	app.renderTemplate(w, "admin", data)
}

func (app *Application) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)
	users := app.tokenStore.ListUsers()

	data := struct {
		Title string
		User  *gonnect.User
		Users []*UserProfile
	}{
		Title: "User Management",
		User:  user,
		Users: users,
	}

	app.renderTemplate(w, "admin_users", data)
}

func (app *Application) handleAbout(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)

	data := struct {
		Title string
		User  *gonnect.User
	}{
		Title: "About",
		User:  user,
	}

	app.renderTemplate(w, "about", data)
}

func (app *Application) handlePrivacy(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)

	data := struct {
		Title string
		User  *gonnect.User
	}{
		Title: "Privacy Policy",
		User:  user,
	}

	app.renderTemplate(w, "privacy", data)
}

func (app *Application) handleOptionalAuth(w http.ResponseWriter, r *http.Request) {
	user := gonnect.GetUser(r)

	if user != nil {
		fmt.Fprintf(w, `
		<h1>Hello %s!</h1>
		<p>You are logged in. <a href="/dashboard">Go to Dashboard</a></p>
		<p><a href="/auth/logout">Logout</a></p>
		`, user.Name)
	} else {
		fmt.Fprintf(w, `
		<h1>Hello Anonymous User!</h1>
		<p>You are not logged in. <a href="/">Login</a></p>
		`)
	}
}

// API route handlers

func (app *Application) handleAPIAuthStatus(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	user, err := app.auth.ValidateRequest(r)

	response := map[string]interface{}{
		"authenticated": err == nil && user != nil,
	}

	if user != nil {
		response["user"] = user
	}

	app.writeJSON(w, response)
}

func (app *Application) handleAPIUser(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	user := gonnect.GetUser(r)
	if user == nil {
		app.writeJSONError(w, "User not found", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"user": user,
	}

	app.writeJSON(w, response)
}

func (app *Application) handleAPIUserProfile(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	user := gonnect.GetUser(r)
	if user == nil {
		app.writeJSONError(w, "User not found", http.StatusUnauthorized)
		return
	}
	profile, exists := app.tokenStore.GetUserProfile(user.ID)

	if !exists {
		app.writeJSONError(w, "Profile not found", http.StatusNotFound)
		return
	}

	if r.Method == "PUT" {
		// Handle profile updates via API
		var updateData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			app.writeJSONError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if name, ok := updateData["name"].(string); ok && name != "" {
			profile.User.Name = name
		}
		if prefs, ok := updateData["preferences"].(map[string]interface{}); ok {
			for k, v := range prefs {
				profile.Preferences[k] = v
			}
		}
		profile.UpdatedAt = time.Now()
	}

	app.writeJSON(w, profile)
}

func (app *Application) handleAPIUserTokens(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	user := gonnect.GetUser(r)

	// Return token information (without sensitive data)
	tokens := make(map[string]interface{})
	for provider := range app.tokenStore.tokens[user.ID] {
		token, _ := app.tokenStore.GetToken(r.Context(), user.ID, provider)
		tokens[provider] = map[string]interface{}{
			"has_token":   true,
			"token_type":  token.TokenType,
			"expires_at":  token.Expiry,
			"has_refresh": token.RefreshToken != "",
		}
	}

	response := map[string]interface{}{
		"tokens": tokens,
	}

	app.writeJSON(w, response)
}

func (app *Application) handleAPIAdminUsers(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	users := app.tokenStore.ListUsers()

	response := map[string]interface{}{
		"users": users,
		"total": len(users),
	}

	app.writeJSON(w, response)
}

func (app *Application) handleAPIAdminStats(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	users := app.tokenStore.ListUsers()

	// Calculate statistics
	totalUsers := len(users)
	totalLogins := 0
	providerStats := make(map[string]int)

	for _, user := range users {
		totalLogins += user.LoginCount
		for _, provider := range user.Providers {
			providerStats[provider]++
		}
	}

	response := map[string]interface{}{
		"total_users":    totalUsers,
		"total_logins":   totalLogins,
		"provider_stats": providerStats,
		"providers":      app.auth.ListProviders(),
	}

	app.writeJSON(w, response)
}

// Utility route handlers

func (app *Application) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
		"providers": len(app.auth.ListProviders()),
		"users":     len(app.tokenStore.ListUsers()),
	}

	app.writeJSON(w, response)
}

func (app *Application) handleStatus(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"service":   "gonnect-comprehensive-example",
		"version":   "1.0.0",
		"status":    "running",
		"uptime":    time.Since(time.Now()).String(), // This would be calculated properly in a real app
		"providers": app.auth.ListProviders(),
		"features": map[string]bool{
			"jwt_auth":      true,
			"session_auth":  true,
			"cors":          true,
			"token_storage": true,
			"user_profiles": true,
		},
	}

	app.writeJSON(w, response)
}

// Helper methods

func (app *Application) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", app.config.CORSOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func (app *Application) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (app *Application) writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

func (app *Application) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, exists := app.templates[name]
	if !exists {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Template execution error", http.StatusInternalServerError)
	}
}

// loadTemplates loads all HTML templates
func loadTemplates() map[string]*template.Template {
	templates := make(map[string]*template.Template)

	// In a real application, you would load these from files
	// For this example, we'll define them inline

	templates["home"] = template.Must(template.New("home").Parse(homeTemplate))
	templates["dashboard"] = template.Must(template.New("dashboard").Parse(dashboardTemplate))
	templates["profile"] = template.Must(template.New("profile").Parse(profileTemplate))
	templates["settings"] = template.Must(template.New("settings").Parse(settingsTemplate))
	templates["admin"] = template.Must(template.New("admin").Parse(adminTemplate))
	templates["admin_users"] = template.Must(template.New("admin_users").Parse(adminUsersTemplate))
	templates["about"] = template.Must(template.New("about").Parse(aboutTemplate))
	templates["privacy"] = template.Must(template.New("privacy").Parse(privacyTemplate))

	return templates
}

// getEnv gets an environment variable with a fallback default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// HTML Templates
const homeTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}.user-info{background:#f0f0f0;padding:20px;border-radius:5px}.login-buttons a{display:inline-block;margin:10px;padding:10px 20px;background:#007cba;color:white;text-decoration:none;border-radius:5px}.login-buttons a:hover{background:#005a87}</style></head><body><h1>{{.Title}}</h1>{{if .Error}}<div style="color:red;padding:10px;background:#ffe6e6;border-radius:5px;margin:10px 0">Error: {{.Error}}</div>{{end}}{{if .User}}<div class="user-info"><h2>Welcome, {{.User.Name}}!</h2><p><a href="/dashboard">Go to Dashboard</a></p></div>{{else}}<p>Please login to continue:</p><div class="login-buttons">{{range .Providers}}<a href="/auth/{{.}}">Login with {{.}}</a>{{end}}</div>{{end}}</body></html>`

const dashboardTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}.nav{margin:20px 0}.nav a{margin-right:15px;padding:8px 16px;background:#007cba;color:white;text-decoration:none;border-radius:3px}.nav a:hover{background:#005a87}.stats{background:#f0f0f0;padding:20px;border-radius:5px;margin:20px 0}</style></head><body><h1>Dashboard</h1><div class="nav"><a href="/profile">Profile</a><a href="/settings">Settings</a><a href="/admin">Admin</a><a href="/auth/logout">Logout</a></div><div class="stats"><h3>Welcome {{.User.Name}}!</h3>{{if .Profile}}<p>Last Login: {{.Profile.LastLogin.Format "2006-01-02 15:04:05"}}</p><p>Login Count: {{.Profile.LoginCount}}</p><p>Providers: {{range .Profile.Providers}}{{.}} {{end}}</p>{{end}}</div></body></html>`

const profileTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}.form{background:#f0f0f0;padding:20px;border-radius:5px}.form input,.form select{width:100%;padding:8px;margin:5px 0;border:1px solid #ccc;border-radius:3px}.form button{background:#007cba;color:white;padding:10px 20px;border:none;border-radius:3px;cursor:pointer}</style></head><body><h1>{{.Title}}</h1>{{if .Updated}}<div style="color:green;padding:10px;background:#e6ffe6;border-radius:5px;margin:10px 0">Profile updated successfully!</div>{{end}}<div class="form"><form method="POST"><label>Name:</label><input type="text" name="name" value="{{.User.Name}}"><label>Theme:</label><select name="theme"><option value="light">Light</option><option value="dark">Dark</option></select><label><input type="checkbox" name="notifications"> Enable Notifications</label><button type="submit">Update Profile</button></form></div><p><a href="/dashboard">Back to Dashboard</a></p></body></html>`

const settingsTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}</style></head><body><h1>{{.Title}}</h1><p>Settings page - customize your experience here.</p><p><a href="/dashboard">Back to Dashboard</a></p></body></html>`

const adminTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}.stats{background:#f0f0f0;padding:20px;border-radius:5px;margin:20px 0}</style></head><body><h1>{{.Title}}</h1><div class="stats"><h3>Statistics</h3><p>Total Users: {{.UserCount}}</p></div><p><a href="/admin/users">Manage Users</a></p><p><a href="/dashboard">Back to Dashboard</a></p></body></html>`

const adminUsersTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ccc;padding:8px;text-align:left}</style></head><body><h1>{{.Title}}</h1><table><tr><th>Name</th><th>Email</th><th>Login Count</th><th>Last Login</th></tr>{{range .Users}}<tr><td>{{.User.Name}}</td><td>{{.User.Email}}</td><td>{{.LoginCount}}</td><td>{{.LastLogin.Format "2006-01-02 15:04:05"}}</td></tr>{{end}}</table><p><a href="/admin">Back to Admin</a></p></body></html>`

const aboutTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}</style></head><body><h1>{{.Title}}</h1><p>This is a comprehensive example of the Gonnect OAuth library.</p><p><a href="/">Home</a></p></body></html>`

const privacyTemplate = `<!DOCTYPE html><html><head><title>{{.Title}}</title><style>body{font-family:Arial,sans-serif;margin:40px}</style></head><body><h1>{{.Title}}</h1><p>Privacy policy content goes here.</p><p><a href="/">Home</a></p></body></html>`
