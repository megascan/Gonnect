// Package main demonstrates API-only usage of the Gonnect authentication library
// This example showcases:
// - Pure JSON API responses (no HTML/templates)
// - No middleware usage - manual authentication checks
// - JWT token authentication for stateless APIs
// - CORS support for frontend integration
// - RESTful endpoints for authentication flow
// - Error handling with proper HTTP status codes
// - User profile management via API
// - Token validation and refresh
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gonnect"
)

// APIResponse represents a standard API response structure
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// AuthStatusResponse represents the authentication status
type AuthStatusResponse struct {
	Authenticated bool          `json:"authenticated"`
	User          *gonnect.User `json:"user,omitempty"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
}

// LoginURLResponse represents available login URLs
type LoginURLResponse struct {
	Providers map[string]string `json:"providers"`
}

// Application represents our API application
type Application struct {
	auth   *gonnect.Gonnect
	config *Config
}

// Config holds application configuration
type Config struct {
	BaseURL   string
	Port      string
	JWTSecret string
	Debug     bool
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	return &Config{
		BaseURL:   getEnv("BASE_URL", "http://localhost:8080"),
		Port:      getEnv("PORT", "8080"),
		JWTSecret: getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
		Debug:     getEnv("DEBUG", "true") == "true",
	}
}

func main() {
	config := LoadConfig()

	// Create Gonnect instance for API usage
	auth := gonnect.New(config.BaseURL)

	// Configure providers
	configureProviders(auth)

	// Configure Gonnect for API usage
	auth.EnableJWT(config.JWTSecret)
	auth.EnableCORS()
	auth.WithLogger(gonnect.NewSimpleLogger(config.Debug))

	// Create application instance
	app := &Application{
		auth:   auth,
		config: config,
	}

	// Setup API routes
	app.setupAPIRoutes()

	// Start server
	log.Printf("🚀 Gonnect API Example starting on port %s", config.Port)
	log.Printf("📍 API Base URL: %s/api", config.BaseURL)
	log.Printf("🔐 Authentication: %s/api/auth", config.BaseURL)
	log.Printf("👤 User Info: %s/api/user", config.BaseURL)

	if config.Debug {
		log.Println("🐛 Debug mode enabled")
	}

	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

// configureProviders sets up OAuth providers
func configureProviders(auth *gonnect.Gonnect) {
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
		auth.Discord(clientID, clientSecret, "identify", "email")
		log.Println("✓ Discord OAuth configured")
		providersConfigured++
	}

	// Microsoft OAuth
	if clientID, clientSecret := getEnv("MICROSOFT_CLIENT_ID", ""), getEnv("MICROSOFT_CLIENT_SECRET", ""); clientID != "" && clientSecret != "" {
		auth.Microsoft(clientID, clientSecret, "openid", "profile", "email")
		log.Println("✓ Microsoft OAuth configured")
		providersConfigured++
	}

	log.Printf("📊 Total providers configured: %d", providersConfigured)

	if providersConfigured == 0 {
		log.Println("⚠️ No OAuth providers configured! Please set environment variables.")
		log.Println("💡 Example: export GOOGLE_CLIENT_ID=your_id GOOGLE_CLIENT_SECRET=your_secret")
	}
}

// setupAPIRoutes configures all API routes
func (app *Application) setupAPIRoutes() {
	// CORS preflight handler
	http.HandleFunc("/api/", app.handleCORSPreflight)

	// Authentication endpoints
	http.HandleFunc("/api/auth/providers", app.handleGetProviders)
	http.HandleFunc("/api/auth/status", app.handleAuthStatus)
	http.HandleFunc("/api/auth/logout", app.handleLogout)

	// OAuth flow endpoints (handled by Gonnect but with API responses)
	http.Handle("/auth/", app.auth.Handler())

	// Protected user endpoints
	http.HandleFunc("/api/user", app.handleGetUser)
	http.HandleFunc("/api/user/profile", app.handleUserProfile)

	// Health check
	http.HandleFunc("/api/health", app.handleHealth)

	// Documentation endpoint
	http.HandleFunc("/api/docs", app.handleDocs)

	// Serve the demo HTML page
	http.HandleFunc("/", app.handleDemoPage)
}

// CORS preflight handler
func (app *Application) handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
}

// handleGetProviders returns available OAuth providers
func (app *Application) handleGetProviders(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := app.auth.ListProviders()
	providerURLs := make(map[string]string)

	for _, provider := range providers {
		providerURLs[provider] = fmt.Sprintf("%s/auth/%s", app.config.BaseURL, provider)
	}

	response := LoginURLResponse{
		Providers: providerURLs,
	}

	app.writeSuccessResponse(w, response, "Available OAuth providers")
}

// handleAuthStatus checks if the user is authenticated
func (app *Application) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to validate the request (JWT or session)
	user, err := app.auth.ValidateRequest(r)

	response := AuthStatusResponse{
		Authenticated: err == nil && user != nil,
	}

	if user != nil {
		response.User = user
		// If using JWT, we could extract expiry from token
		// For now, we'll set a reasonable expiry time
		expiry := time.Now().Add(24 * time.Hour)
		response.ExpiresAt = &expiry
	}

	app.writeSuccessResponse(w, response, "Authentication status")
}

// handleLogout logs out the user
func (app *Application) handleLogout(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear session/JWT
	// For JWT, the client should just delete the token
	// For sessions, we can clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "gonnect_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(app.config.BaseURL, "https"),
		SameSite: http.SameSiteLaxMode,
	})

	app.writeSuccessResponse(w, nil, "Successfully logged out")
}

// handleGetUser returns the authenticated user's information
func (app *Application) handleGetUser(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate authentication
	user, err := app.auth.ValidateRequest(r)
	if err != nil || user == nil {
		app.writeErrorResponse(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	app.writeSuccessResponse(w, user, "User information retrieved")
}

// handleUserProfile handles user profile operations
func (app *Application) handleUserProfile(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate authentication
	user, err := app.auth.ValidateRequest(r)
	if err != nil || user == nil {
		app.writeErrorResponse(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Return user profile
		profile := map[string]interface{}{
			"user":       user,
			"last_login": time.Now(),
			"settings": map[string]interface{}{
				"theme":         "light",
				"notifications": true,
				"language":      "en",
			},
		}
		app.writeSuccessResponse(w, profile, "User profile retrieved")

	case http.MethodPut:
		// Update user profile
		var updateData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			app.writeErrorResponse(w, "Invalid JSON data", http.StatusBadRequest)
			return
		}

		// In a real application, you would update the user profile in your database
		// For this example, we'll just return the updated data
		response := map[string]interface{}{
			"user":    user,
			"updates": updateData,
			"message": "Profile updated successfully",
		}
		app.writeSuccessResponse(w, response, "Profile updated")

	default:
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealth returns API health status
func (app *Application) handleHealth(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"version":   "1.0.0",
		"providers": len(app.auth.ListProviders()),
		"features": map[string]bool{
			"jwt_auth": true,
			"cors":     true,
			"oauth2":   true,
		},
	}

	app.writeSuccessResponse(w, health, "API is healthy")
}

// handleDocs returns API documentation
func (app *Application) handleDocs(w http.ResponseWriter, r *http.Request) {
	app.setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	docs := map[string]interface{}{
		"title":       "Gonnect API Documentation",
		"version":     "1.0.0",
		"description": "RESTful API for OAuth authentication using Gonnect",
		"base_url":    app.config.BaseURL + "/api",
		"endpoints": map[string]interface{}{
			"GET /api/auth/providers": "Get available OAuth providers",
			"GET /api/auth/status":    "Check authentication status",
			"POST /api/auth/logout":   "Logout user",
			"GET /api/user":           "Get authenticated user info (requires auth)",
			"GET /api/user/profile":   "Get user profile (requires auth)",
			"PUT /api/user/profile":   "Update user profile (requires auth)",
			"GET /api/health":         "API health check",
			"GET /api/docs":           "This documentation",
		},
		"authentication": map[string]interface{}{
			"type":        "OAuth2 + JWT",
			"flow":        "Authorization Code",
			"jwt_header":  "Authorization: Bearer <token>",
			"session":     "Cookie-based sessions also supported",
			"oauth_start": "/auth/{provider} (e.g., /auth/google)",
		},
		"example_usage": map[string]interface{}{
			"1_get_providers": "GET /api/auth/providers",
			"2_start_oauth":   "Redirect to provider URL from step 1",
			"3_check_status":  "GET /api/auth/status",
			"4_get_user":      "GET /api/user (with auth)",
			"5_logout":        "POST /api/auth/logout",
		},
	}

	app.writeSuccessResponse(w, docs, "API documentation")
}

// handleDemoPage serves the HTML demo page
func (app *Application) handleDemoPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		app.setCORSHeaders(w)
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		app.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only serve the demo page for the root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "index.html")
}

// Helper methods

func (app *Application) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func (app *Application) writeSuccessResponse(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	response := APIResponse{
		Success: true,
		Data:    data,
		Message: message,
	}
	json.NewEncoder(w).Encode(response)
}

func (app *Application) writeErrorResponse(w http.ResponseWriter, errorMsg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := APIResponse{
		Success: false,
		Error:   errorMsg,
	}
	json.NewEncoder(w).Encode(response)
}

// getEnv gets an environment variable with a fallback default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
