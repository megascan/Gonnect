package gonnect

import (
	"encoding/json"
	"fmt"
	"gonnect/internal/coretypes"
	"net/http"
	"strings"
)

// Handler returns the main HTTP handler for all authentication routes
func (g *Gonnect) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register routes for each provider
	for name := range g.providers {
		// Login initiation routes
		mux.HandleFunc("/auth/"+name, g.handleLogin(name))
		mux.HandleFunc("/auth/"+name+"/login", g.handleLogin(name))

		// Callback routes
		mux.HandleFunc("/auth/"+name+"/callback", g.handleCallback(name))

		// API routes for SPA/frontend integration
		mux.HandleFunc("/api/auth/"+name, g.handleAPIAuthURL(name))
		mux.HandleFunc("/api/auth/"+name+"/callback", g.handleAPICallback(name))
	}

	// General auth routes
	mux.HandleFunc("/auth/logout", g.handleLogout())
	mux.HandleFunc("/api/auth/logout", g.handleAPILogout())
	mux.HandleFunc("/api/auth/user", g.handleAPIUser())

	return mux
}

// handleLogin initiates the OAuth flow for a specific provider
func (g *Gonnect) handleLogin(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		provider, exists := g.providers[providerName]
		if !exists {
			g.handleError(w, r, coretypes.NewProviderError(providerName, coretypes.ErrTypeProvider, "provider not found"), http.StatusNotFound)
			return
		}

		// Generate and store state parameter for CSRF protection
		state := generateState()
		if err := g.storeState(w, r, state); err != nil {
			g.handleError(w, r, coretypes.NewErrorWithCause(coretypes.ErrTypeSession, "failed to store state", err), http.StatusInternalServerError)
			return
		}

		// Get authorization URL from provider
		authURL, err := provider.BeginAuth(r.Context(), state)
		if err != nil {
			g.handleError(w, r, coretypes.NewProviderErrorWithCause(providerName, coretypes.ErrTypeAuthentication, "failed to begin auth", err), http.StatusInternalServerError)
			return
		}

		// Redirect to provider's authorization URL
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// handleCallback processes the OAuth callback from the provider
func (g *Gonnect) handleCallback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.logger != nil {
			g.logger.Info("handleCallback: starting OAuth callback", "provider", providerName, "url", r.URL.String())
		}

		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		provider, exists := g.providers[providerName]
		if !exists {
			if g.logger != nil {
				g.logger.Error("handleCallback: provider not found", "provider", providerName)
			}
			g.handleCallbackError(w, r, "provider not found")
			return
		}

		if g.logger != nil {
			g.logger.Info("handleCallback: provider found, validating state")
		}

		// Validate state parameter to prevent CSRF attacks
		stateValid := g.validateState(r)
		if g.logger != nil {
			g.logger.Info("handleCallback: state validation result", "valid", stateValid)
		}
		if !stateValid {
			if g.logger != nil {
				g.logger.Error("handleCallback: state validation failed")
			}
			g.handleCallbackError(w, r, "invalid state parameter")
			return
		}

		if g.logger != nil {
			g.logger.Info("handleCallback: state validation passed, checking for OAuth errors")
		}

		// Check for OAuth error in callback
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			if g.logger != nil {
				g.logger.Error("handleCallback: OAuth error in callback", "error", errMsg)
			}
			g.handleCallbackError(w, r, "OAuth error: "+errMsg)
			return
		}

		if g.logger != nil {
			g.logger.Info("handleCallback: no OAuth errors, completing authentication")
		}

		// Complete the authentication flow
		user, token, err := provider.CompleteAuth(r.Context(), r)
		if err != nil {
			if g.logger != nil {
				g.logger.Error("handleCallback: authentication failed", "error", err)
			}
			g.handleCallbackError(w, r, "authentication failed: "+err.Error())
			return
		}

		if g.logger != nil {
			g.logger.Info("handleCallback: authentication completed", "userID", user.ID, "userEmail", user.Email)
		}

		// Debug: Print all user information returned from OAuth provider
		fmt.Printf("=== OAUTH USER INFORMATION ===\n")
		fmt.Printf("User ID: %s\n", user.ID)
		fmt.Printf("Email: %s\n", user.Email)
		fmt.Printf("Name: %s\n", user.Name)
		fmt.Printf("Username: %s\n", user.Username)
		fmt.Printf("Avatar URL: %s\n", user.AvatarURL)
		fmt.Printf("Locale: %s\n", user.Locale)
		fmt.Printf("Raw Data Keys: ")
		if user.RawData != nil {
			for key := range user.RawData {
				fmt.Printf("%s, ", key)
			}
		}
		fmt.Printf("\n")

		// Print detailed raw data
		if user.RawData != nil {
			fmt.Printf("=== RAW USER DATA ===\n")
			for key, value := range user.RawData {
				fmt.Printf("%s: %v\n", key, value)
			}
		}

		// Debug: Print token information
		fmt.Printf("=== TOKEN INFORMATION ===\n")
		if len(token.AccessToken) > 20 {
			fmt.Printf("Access Token: %s...\n", token.AccessToken[:20])
		} else {
			fmt.Printf("Access Token: %s\n", token.AccessToken)
		}
		fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
		fmt.Printf("Token Type: %s\n", token.TokenType)
		fmt.Printf("Expiry: %v\n", token.Expiry)
		fmt.Printf("==============================\n")

		// Create user session
		if err := g.createSession(w, r, user, token); err != nil {
			if g.logger != nil {
				g.logger.Error("handleCallback: failed to create session", "error", err)
			}
			g.handleCallbackError(w, r, "failed to create session: "+err.Error())
			return
		}

		if g.logger != nil {
			g.logger.Info("handleCallback: session created successfully")
		}

		// Clear the state parameter
		g.clearState(w, r)

		if g.logger != nil {
			g.logger.Info("handleCallback: redirecting to success URL", "url", g.successRedirect)
		}

		// Redirect to success URL
		http.Redirect(w, r, g.successRedirect, http.StatusFound)
	}
}

// handleAPIAuthURL returns the authorization URL for API clients
func (g *Gonnect) handleAPIAuthURL(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		provider, exists := g.providers[providerName]
		if !exists {
			g.writeJSONError(w, "provider not found", http.StatusNotFound)
			return
		}

		// Generate state parameter
		state := generateState()
		if err := g.storeState(w, r, state); err != nil {
			g.writeJSONError(w, "failed to generate auth state", http.StatusInternalServerError)
			return
		}

		// Get authorization URL
		authURL, err := provider.BeginAuth(r.Context(), state)
		if err != nil {
			g.writeJSONError(w, "failed to generate auth URL", http.StatusInternalServerError)
			return
		}

		// Return JSON response
		response := map[string]string{
			"authURL": authURL,
			"state":   state,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// handleAPICallback processes OAuth callback for API clients
func (g *Gonnect) handleAPICallback(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		provider, exists := g.providers[providerName]
		if !exists {
			g.writeJSONError(w, "provider not found", http.StatusNotFound)
			return
		}

		// Validate state parameter
		if !g.validateState(r) {
			g.writeJSONError(w, "invalid state parameter", http.StatusBadRequest)
			return
		}

		// Check for OAuth error
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			g.writeJSONError(w, "OAuth error: "+errMsg, http.StatusBadRequest)
			return
		}

		// Complete authentication
		user, token, err := provider.CompleteAuth(r.Context(), r)
		if err != nil {
			g.writeJSONError(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		// Create session
		if err := g.createSession(w, r, user, token); err != nil {
			g.writeJSONError(w, "failed to create session", http.StatusInternalServerError)
			return
		}

		// Clear state
		g.clearState(w, r)

		// Prepare response
		response := map[string]interface{}{
			"success": true,
			"user":    user,
		}

		// Include JWT if enabled
		if g.jwtSecret != nil {
			jwt, err := g.generateJWT(user)
			if err == nil {
				response["token"] = jwt
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// handleLogout logs out the user (traditional web app)
func (g *Gonnect) handleLogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g.clearSession(w, r)
		http.Redirect(w, r, g.failureRedirect, http.StatusFound)
	}
}

// handleAPILogout logs out the user (API endpoint)
func (g *Gonnect) handleAPILogout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		g.clearSession(w, r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}
}

// handleAPIUser returns the current user information for API clients
func (g *Gonnect) handleAPIUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if g.corsEnabled {
			g.setCORSHeaders(w)
		}

		user, err := g.ValidateRequest(r)
		if err != nil {
			g.writeJSONError(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		response := map[string]interface{}{
			"user":          user,
			"authenticated": true,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Helper methods for session and state management

// storeState stores the OAuth state parameter in the session
func (g *Gonnect) storeState(w http.ResponseWriter, r *http.Request, state string) error {
	sessionName := g.sessionName + "_state"
	if g.logger != nil {
		g.logger.Info("storeState: storing state", "state", state, "sessionName", sessionName)
	}

	session, err := g.sessionStore.Get(r.Context(), r, sessionName)
	if err != nil {
		if g.logger != nil {
			g.logger.Info("storeState: creating new session", "error", err)
		}
		session = g.sessionStore.New(r.Context(), r, sessionName)
	}

	if g.logger != nil {
		g.logger.Info("storeState: got session", "sessionID", session.ID(), "isNew", session.IsNew())
	}

	session.Set("oauth_state", state)

	err = g.sessionStore.Save(r.Context(), w, r, session)
	if err != nil {
		if g.logger != nil {
			g.logger.Error("storeState: failed to save session", "error", err)
		}
		return err
	}

	if g.logger != nil {
		g.logger.Info("storeState: successfully saved state to session")
	}
	return nil
}

// validateState validates the OAuth state parameter against the stored value
func (g *Gonnect) validateState(r *http.Request) bool {
	stateParam := r.URL.Query().Get("state")
	if g.logger != nil {
		g.logger.Info("validateState: received state parameter", "state", stateParam)
	}
	if stateParam == "" {
		if g.logger != nil {
			g.logger.Error("validateState: no state parameter in request")
		}
		return false
	}

	sessionName := g.sessionName + "_state"
	if g.logger != nil {
		g.logger.Info("validateState: looking for session", "sessionName", sessionName)
	}

	session, err := g.sessionStore.Get(r.Context(), r, sessionName)
	if err != nil {
		if g.logger != nil {
			g.logger.Error("validateState: failed to get session", "error", err, "sessionName", sessionName)
		}
		return false
	}

	if g.logger != nil {
		g.logger.Info("validateState: got session", "sessionID", session.ID(), "isNew", session.IsNew())
	}

	storedState := session.Get("oauth_state")
	if g.logger != nil {
		g.logger.Info("validateState: stored state", "storedState", storedState)
	}
	if storedState == nil {
		if g.logger != nil {
			g.logger.Error("validateState: no stored state found in session")
		}
		return false
	}

	storedStateStr, ok := storedState.(string)
	if !ok {
		if g.logger != nil {
			g.logger.Error("validateState: stored state is not a string", "type", fmt.Sprintf("%T", storedState))
		}
		return false
	}

	match := stateParam == storedStateStr
	if g.logger != nil {
		g.logger.Info("validateState: comparison result", "match", match, "received", stateParam, "stored", storedStateStr)
	}

	return match
}

// clearState removes the OAuth state from the session
func (g *Gonnect) clearState(w http.ResponseWriter, r *http.Request) {
	session, err := g.sessionStore.Get(r.Context(), r, g.sessionName+"_state")
	if err != nil {
		return
	}

	session.Delete("oauth_state")
	g.sessionStore.Save(r.Context(), w, r, session)
}

// createSession creates a new user session with authentication data
func (g *Gonnect) createSession(w http.ResponseWriter, r *http.Request, user coretypes.User, token coretypes.Token) error {
	session, err := g.sessionStore.Get(r.Context(), r, g.sessionName)
	if err != nil {
		session = g.sessionStore.New(r.Context(), r, g.sessionName)
	}

	// Store user information in session
	session.Set("user_id", user.ID)
	session.Set("user_email", user.Email)
	session.Set("user_name", user.Name)
	session.Set("user_username", user.Username)
	session.Set("user_avatar_url", user.AvatarURL)
	session.Set("user_locale", user.Locale)
	session.Set("authenticated", true)

	// Store token if token store is not configured (fallback to session)
	if g.tokenStore == nil {
		session.Set("access_token", token.AccessToken)
		session.Set("refresh_token", token.RefreshToken)
		session.Set("token_expiry", token.Expiry.Unix())
	} else {
		// Store token in dedicated token store
		exportedToken := convertInternalTokenToExported(&token)
		if err := g.tokenStore.StoreToken(r.Context(), user.ID, "", *exportedToken); err != nil {
			// Log error but don't fail the session creation
			if g.logger != nil {
				g.logger.Warn("failed to store token", "error", err)
			}
		}
	}

	return g.sessionStore.Save(r.Context(), w, r, session)
}

// clearSession removes the user session
func (g *Gonnect) clearSession(w http.ResponseWriter, r *http.Request) {
	session, err := g.sessionStore.Get(r.Context(), r, g.sessionName)
	if err != nil {
		return
	}

	// Get user ID for token cleanup
	if userID := session.Get("user_id"); userID != nil && g.tokenStore != nil {
		if userIDStr, ok := userID.(string); ok {
			g.tokenStore.DeleteToken(r.Context(), userIDStr, "")
		}
	}

	// Clear session
	session.Clear()
	g.sessionStore.Delete(r.Context(), w, r, session)
}

// getUserFromSession retrieves user information from the session
func (g *Gonnect) getUserFromSession(r *http.Request) (*coretypes.User, error) {
	session, err := g.sessionStore.Get(r.Context(), r, g.sessionName)
	if err != nil {
		return nil, coretypes.NewErrorWithCause(coretypes.ErrTypeSession, "failed to get session", err)
	}

	authenticated := session.Get("authenticated")
	if authenticated == nil {
		return nil, coretypes.NewError(coretypes.ErrTypeAuthentication, "user not authenticated")
	}

	if authBool, ok := authenticated.(bool); !ok || !authBool {
		return nil, coretypes.NewError(coretypes.ErrTypeAuthentication, "user not authenticated")
	}

	user := &coretypes.User{
		ID:        getStringFromSession(session, "user_id"),
		Email:     getStringFromSession(session, "user_email"),
		Name:      getStringFromSession(session, "user_name"),
		Username:  getStringFromSession(session, "user_username"),
		AvatarURL: getStringFromSession(session, "user_avatar_url"),
		Locale:    getStringFromSession(session, "user_locale"),
	}

	return user, nil
}

// getStringFromSession safely extracts a string value from session
func getStringFromSession(session Session, key string) string {
	if val := session.Get(key); val != nil {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// isAPIRequest determines if the request expects a JSON response
func (g *Gonnect) isAPIRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") ||
		r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		strings.HasPrefix(r.URL.Path, "/api/")
}

// setCORSHeaders sets CORS headers for API requests
func (g *Gonnect) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // Configure appropriately in production
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// handleError handles errors for traditional web requests
func (g *Gonnect) handleError(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	if g.logger != nil {
		g.logger.Error("authentication error", "error", err, "path", r.URL.Path)
	}

	if g.isAPIRequest(r) {
		g.writeJSONError(w, err.Error(), statusCode)
	} else {
		http.Redirect(w, r, g.failureRedirect, http.StatusFound)
	}
}

// handleCallbackError handles errors during OAuth callback
func (g *Gonnect) handleCallbackError(w http.ResponseWriter, r *http.Request, message string) {
	if g.logger != nil {
		g.logger.Error("OAuth callback error", "error", message, "path", r.URL.Path, "url", r.URL.String())
	}

	// Add stack trace to understand where this is being called from
	fmt.Printf("DEBUG: handleCallbackError called with message: %s\n", message)
	fmt.Printf("DEBUG: Request URL: %s\n", r.URL.String())
	fmt.Printf("DEBUG: Request path: %s\n", r.URL.Path)

	if g.isAPIRequest(r) {
		g.writeJSONError(w, message, http.StatusBadRequest)
	} else {
		// Add error message as query parameter for web apps
		redirectURL := fmt.Sprintf("%s?error=%s", g.failureRedirect, message)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// writeJSONError writes a JSON error response
func (g *Gonnect) writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}
