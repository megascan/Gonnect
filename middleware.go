package gonnect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gonnect/internal/coretypes"
	"net/http"
	"strings"
	"time"
)

// RequireAuth middleware ensures the user is authenticated
func (g *Gonnect) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := g.ValidateRequest(r)
		if err != nil {
			if g.isAPIRequest(r) {
				g.writeJSONError(w, "unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, g.failureRedirect, http.StatusFound)
			}
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth middleware checks for authentication but doesn't require it
func (g *Gonnect) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := g.ValidateRequest(r)
		if err == nil && user != nil {
			// Add user to context if authenticated
			ctx := context.WithValue(r.Context(), userContextKey, user)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// ValidateRequest validates a request and returns the authenticated user
// It checks both JWT tokens (Authorization header) and session cookies
func (g *Gonnect) ValidateRequest(r *http.Request) (*User, error) {
	// Try JWT first (for API clients)
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			return g.validateJWT(token)
		}
	}

	// Fall back to session (for web clients)
	internalUser, err := g.getUserFromSession(r)
	if err != nil {
		return nil, err
	}
	return convertInternalUserToExported(internalUser), nil
}

// JWT Implementation

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar_url"`
	Locale    string `json:"locale"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// generateJWT creates a JWT token for the given user
func (g *Gonnect) generateJWT(user coretypes.User) (string, error) {
	if g.jwtSecret == nil {
		return "", coretypes.NewError(coretypes.ErrTypeConfig, "JWT secret not configured")
	}

	now := time.Now()
	claims := JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		Locale:    user.Locale,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(), // 24 hour expiry
	}

	// Create header
	header := map[string]interface{}{
		"typ": "JWT",
		"alg": "HS256",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", coretypes.NewErrorWithCause(coretypes.ErrTypeToken, "failed to marshal JWT header", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", coretypes.NewErrorWithCause(coretypes.ErrTypeToken, "failed to marshal JWT claims", err)
	}

	// Base64 encode header and claims
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Create signature
	message := headerB64 + "." + claimsB64
	signature := g.signJWT(message)

	// Combine all parts
	token := message + "." + signature

	return token, nil
}

// validateJWT validates a JWT token and returns the user
func (g *Gonnect) validateJWT(tokenString string) (*User, error) {
	if g.jwtSecret == nil {
		return nil, coretypes.NewError(coretypes.ErrTypeConfig, "JWT secret not configured")
	}

	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, coretypes.NewError(coretypes.ErrTypeToken, "invalid JWT format")
	}

	headerB64, claimsB64, signatureB64 := parts[0], parts[1], parts[2]

	// Verify signature
	message := headerB64 + "." + claimsB64
	expectedSignature := g.signJWT(message)
	if !hmac.Equal([]byte(signatureB64), []byte(expectedSignature)) {
		return nil, coretypes.NewError(coretypes.ErrTypeToken, "invalid JWT signature")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, coretypes.NewErrorWithCause(coretypes.ErrTypeToken, "failed to decode JWT claims", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, coretypes.NewErrorWithCause(coretypes.ErrTypeToken, "failed to unmarshal JWT claims", err)
	}

	// Check expiration
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, coretypes.NewError(coretypes.ErrTypeToken, "JWT token expired")
	}

	// Convert claims to User
	user := &User{
		ID:        claims.UserID,
		Email:     claims.Email,
		Name:      claims.Name,
		Username:  claims.Username,
		AvatarURL: claims.AvatarURL,
		Locale:    claims.Locale,
	}

	return user, nil
}

// signJWT creates an HMAC-SHA256 signature for the JWT
func (g *Gonnect) signJWT(message string) string {
	mac := hmac.New(sha256.New, g.jwtSecret)
	mac.Write([]byte(message))
	signature := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}

// Session validation helpers

// getUser retrieves the authenticated user from the request (for middleware)
func (g *Gonnect) getUser(r *http.Request) *coretypes.User {
	user, _ := g.ValidateRequest(r)
	return convertExportedUserToInternal(user)
}

// isAuthenticated checks if the request has a valid authentication
func (g *Gonnect) isAuthenticated(r *http.Request) bool {
	user, err := g.ValidateRequest(r)
	return err == nil && user != nil
}

// Memory-based token store implementation (for development/testing)

// MemoryTokenStore implements TokenStore using in-memory storage
type MemoryTokenStore struct {
	tokens map[string]map[string]Token // userID -> provider -> token
}

// NewMemoryTokenStore creates a new memory-based token store
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		tokens: make(map[string]map[string]Token),
	}
}

// StoreToken stores a token for a user and provider
func (m *MemoryTokenStore) StoreToken(ctx context.Context, userID string, provider string, token Token) error {
	if m.tokens[userID] == nil {
		m.tokens[userID] = make(map[string]Token)
	}
	m.tokens[userID][provider] = token
	return nil
}

// GetToken retrieves a token for a user and provider
func (m *MemoryTokenStore) GetToken(ctx context.Context, userID string, provider string) (Token, error) {
	if userTokens, exists := m.tokens[userID]; exists {
		if token, exists := userTokens[provider]; exists {
			return token, nil
		}
	}
	return Token{}, NewError(ErrTypeToken, "token not found")
}

// DeleteToken removes a token for a user and provider
func (m *MemoryTokenStore) DeleteToken(ctx context.Context, userID string, provider string) error {
	if userTokens, exists := m.tokens[userID]; exists {
		delete(userTokens, provider)
		if len(userTokens) == 0 {
			delete(m.tokens, userID)
		}
	}
	return nil
}

// RefreshToken refreshes a token for a user and provider
func (m *MemoryTokenStore) RefreshToken(ctx context.Context, userID string, provider string) (Token, error) {
	// This would typically call the provider's refresh endpoint
	// For now, just return the existing token
	return m.GetToken(ctx, userID, provider)
}

// Simple logger implementation

// SimpleLogger implements the Logger interface with basic logging
type SimpleLogger struct {
	enabled bool
}

// NewSimpleLogger creates a new simple logger
func NewSimpleLogger(enabled bool) *SimpleLogger {
	return &SimpleLogger{enabled: enabled}
}

// Debug logs debug messages
func (l *SimpleLogger) Debug(msg string, fields ...interface{}) {
	if l.enabled {
		fmt.Printf("[DEBUG] %s %v\n", msg, fields)
	}
}

// Info logs info messages
func (l *SimpleLogger) Info(msg string, fields ...interface{}) {
	if l.enabled {
		fmt.Printf("[INFO] %s %v\n", msg, fields)
	}
}

// Warn logs warning messages
func (l *SimpleLogger) Warn(msg string, fields ...interface{}) {
	if l.enabled {
		fmt.Printf("[WARN] %s %v\n", msg, fields)
	}
}

// Error logs error messages
func (l *SimpleLogger) Error(msg string, fields ...interface{}) {
	if l.enabled {
		fmt.Printf("[ERROR] %s %v\n", msg, fields)
	}
}

// Middleware helper functions

// WithLogger sets a logger for the Gonnect instance (chainable)
func (g *Gonnect) WithLogger(logger Logger) *Gonnect {
	g.logger = logger
	return g
}

// WithTokenStore sets a token store for the Gonnect instance (chainable)
func (g *Gonnect) WithTokenStore(store TokenStore) *Gonnect {
	g.tokenStore = store
	return g
}

// WithSessionStore sets a session store for the Gonnect instance (chainable)
func (g *Gonnect) WithSessionStore(store SessionStore) *Gonnect {
	g.sessionStore = store
	return g
}

// GetSessionStore returns the current session store
func (g *Gonnect) GetSessionStore() SessionStore {
	return g.sessionStore
}

// GetTokenStore returns the current token store
func (g *Gonnect) GetTokenStore() TokenStore {
	return g.tokenStore
}

// Security helpers

// generateCSRFToken generates a CSRF token for forms
func (g *Gonnect) generateCSRFToken() string {
	return generateState() // Reuse the secure state generation
}

// validateCSRFToken validates a CSRF token
func (g *Gonnect) validateCSRFToken(r *http.Request, expectedToken string) bool {
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	return token == expectedToken
}

// Rate limiting helpers (basic implementation)

// RateLimiter provides basic rate limiting functionality
type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()

	// Clean old requests
	if requests, exists := rl.requests[key]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) < rl.window {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.requests[key] = validRequests
	}

	// Check if under limit
	if len(rl.requests[key]) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests[key] = append(rl.requests[key], now)
	return true
}

// WithRateLimit adds rate limiting to the Gonnect instance
func (g *Gonnect) WithRateLimit(limit int, window time.Duration) *Gonnect {
	// This would be implemented to add rate limiting middleware
	// For now, just return the instance
	return g
}
