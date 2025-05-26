// Package gonnect provides a unified authentication library for Go applications,
// supporting OAuth2, OpenID Connect, and social login providers.
package gonnect

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"gonnect/internal/coretypes"
)

// User represents a generic user object returned by a provider
type User struct {
	ID        string                 `json:"id"`         // Unique identifier from the provider
	Email     string                 `json:"email"`      // User's email address
	Name      string                 `json:"name"`       // User's display name
	Username  string                 `json:"username"`   // Username (may differ from name)
	AvatarURL string                 `json:"avatar_url"` // URL to user's profile picture
	Locale    string                 `json:"locale"`     // User's locale/language preference
	RawData   map[string]interface{} `json:"raw_data"`   // Original data from provider
}

// Token represents the token data from a provider
type Token struct {
	AccessToken  string                 `json:"access_token"`  // OAuth2 access token
	RefreshToken string                 `json:"refresh_token"` // OAuth2 refresh token
	Expiry       time.Time              `json:"expiry"`        // Token expiration time
	IDToken      string                 `json:"id_token"`      // OpenID Connect ID token
	TokenType    string                 `json:"token_type"`    // Token type (usually "Bearer")
	Scope        string                 `json:"scope"`         // Granted scopes
	Extra        map[string]interface{} `json:"extra"`         // Provider-specific token data
}

// Config holds the common configuration for a provider
type Config struct {
	ClientID     string                 `json:"client_id"`     // OAuth2 client ID
	ClientSecret string                 `json:"client_secret"` // OAuth2 client secret
	RedirectURL  string                 `json:"redirect_url"`  // OAuth2 redirect URL
	Scopes       []string               `json:"scopes"`        // Requested OAuth2 scopes
	Extra        map[string]interface{} `json:"extra"`         // Provider-specific configuration
}

// SessionStore defines the interface for session storage backends
type SessionStore interface {
	Get(ctx context.Context, r *http.Request, name string) (Session, error)
	New(ctx context.Context, r *http.Request, name string) Session
	Save(ctx context.Context, w http.ResponseWriter, r *http.Request, s Session) error
	Delete(ctx context.Context, w http.ResponseWriter, r *http.Request, s Session) error
}

// Session represents a user session with authentication data
type Session interface {
	ID() string
	Get(key string) interface{}
	Set(key string, val interface{})
	Delete(key string)
	Clear()
	IsNew() bool
	Values() map[string]interface{}
	CreatedAt() time.Time
	LastAccessed() time.Time
	MaxAge() time.Duration
	SetMaxAge(duration time.Duration)
}

// TokenStore defines the interface for persistent token storage
type TokenStore interface {
	StoreToken(ctx context.Context, userID string, provider string, token Token) error
	GetToken(ctx context.Context, userID string, provider string) (Token, error)
	DeleteToken(ctx context.Context, userID string, provider string) error
	RefreshToken(ctx context.Context, userID string, provider string) (Token, error)
}

// Logger defines the interface for logging within Gonnect
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// Gonnect is the main client for handling authentication flows
type Gonnect struct {
	baseURL      string
	secretKey    []byte
	providers    map[string]coretypes.Provider
	sessionStore SessionStore
	tokenStore   TokenStore

	// Configuration
	sessionName     string
	successRedirect string
	failureRedirect string
	logger          Logger

	// API/SPA support
	jwtSecret   []byte
	corsEnabled bool
}

// GonnectConfig holds advanced configuration options for Gonnect
type GonnectConfig struct {
	BaseURL         string
	SecretKey       []byte
	SessionStore    SessionStore
	TokenStore      TokenStore
	SessionName     string
	SuccessRedirect string
	FailureRedirect string
	Logger          Logger
	JWTSecret       []byte
	EnableCORS      bool
}

// New creates a new Gonnect instance with sensible defaults
func New(baseURL string) *Gonnect {
	secretKey := generateSecretKey()
	return &Gonnect{
		baseURL:         baseURL,
		secretKey:       secretKey,
		providers:       make(map[string]coretypes.Provider),
		sessionStore:    NewCookieSessionStore(secretKey, CookieOptions{}),
		sessionName:     "gonnect_session",
		successRedirect: "/",
		failureRedirect: "/login",
	}
}

// NewWithConfig creates a new Gonnect instance with advanced configuration
func NewWithConfig(cfg GonnectConfig) *Gonnect {
	g := &Gonnect{
		baseURL:         cfg.BaseURL,
		secretKey:       cfg.SecretKey,
		providers:       make(map[string]coretypes.Provider),
		sessionStore:    cfg.SessionStore,
		tokenStore:      cfg.TokenStore,
		sessionName:     cfg.SessionName,
		successRedirect: cfg.SuccessRedirect,
		failureRedirect: cfg.FailureRedirect,
		logger:          cfg.Logger,
		jwtSecret:       cfg.JWTSecret,
		corsEnabled:     cfg.EnableCORS,
	}

	// Apply sensible defaults
	if g.secretKey == nil {
		g.secretKey = generateSecretKey()
	}
	if g.sessionStore == nil {
		g.sessionStore = NewCookieSessionStore(g.secretKey, CookieOptions{})
	}
	if g.sessionName == "" {
		g.sessionName = "gonnect_session"
	}
	if g.successRedirect == "" {
		g.successRedirect = "/"
	}
	if g.failureRedirect == "" {
		g.failureRedirect = "/login"
	}

	return g
}

// SetSecret sets the secret key for session encryption (chainable)
func (g *Gonnect) SetSecret(key string) *Gonnect {
	g.secretKey = []byte(key)
	return g
}

// SetSessionName sets the session cookie name (chainable)
func (g *Gonnect) SetSessionName(name string) *Gonnect {
	g.sessionName = name
	return g
}

// OnSuccess sets the redirect URL for successful authentication (chainable)
func (g *Gonnect) OnSuccess(path string) *Gonnect {
	g.successRedirect = path
	return g
}

// OnFailure sets the redirect URL for failed authentication (chainable)
func (g *Gonnect) OnFailure(path string) *Gonnect {
	g.failureRedirect = path
	return g
}

// EnableJWT enables JWT token support for API clients (chainable)
func (g *Gonnect) EnableJWT(secret string) *Gonnect {
	g.jwtSecret = []byte(secret)
	return g
}

// EnableCORS enables CORS support for frontend applications (chainable)
func (g *Gonnect) EnableCORS() *Gonnect {
	g.corsEnabled = true
	return g
}

// AddProvider adds a custom provider to the Gonnect instance
func (g *Gonnect) AddProvider(name string, provider coretypes.Provider) *Gonnect {
	g.providers[name] = provider
	return g
}

// GetProvider returns a provider by name
func (g *Gonnect) GetProvider(name string) (coretypes.Provider, bool) {
	provider, exists := g.providers[name]
	return provider, exists
}

// ListProviders returns a list of all configured provider names
func (g *Gonnect) ListProviders() []string {
	names := make([]string, 0, len(g.providers))
	for name := range g.providers {
		names = append(names, name)
	}
	return names
}

// generateSecretKey generates a secure random key for session encryption
func generateSecretKey() []byte {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		panic("gonnect: failed to generate secure random key: " + err.Error())
	}
	return key
}

// generateState generates a secure random state parameter for OAuth2 flows
func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("gonnect: failed to generate secure random state: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Context key for storing user information in request context
type contextKey string

const userContextKey contextKey = "gonnect_user"

// GetUser retrieves the authenticated user from the request context
// This is typically populated by a middleware after successful authentication.
func GetUser(r *http.Request) *User {
	if user, ok := r.Context().Value(userContextKey).(*User); ok {
		return user
	}
	return nil
}

// convertInternalUserToExported converts internal User to exported User
func convertInternalUserToExported(user *coretypes.User) *User {
	if user == nil {
		return nil
	}
	return &User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		Locale:    user.Locale,
		RawData:   user.RawData,
	}
}

// convertExportedUserToInternal converts exported User to internal User
func convertExportedUserToInternal(user *User) *coretypes.User {
	if user == nil {
		return nil
	}
	return &coretypes.User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		Locale:    user.Locale,
		RawData:   user.RawData,
	}
}

// convertInternalTokenToExported converts internal Token to exported Token
func convertInternalTokenToExported(token *coretypes.Token) *Token {
	if token == nil {
		return nil
	}
	return &Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		IDToken:      token.IDToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
		Extra:        token.Extra,
	}
}

// convertExportedTokenToInternal converts exported Token to internal Token
func convertExportedTokenToInternal(token *Token) *coretypes.Token {
	if token == nil {
		return nil
	}
	return &coretypes.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		IDToken:      token.IDToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
		Extra:        token.Extra,
	}
}
