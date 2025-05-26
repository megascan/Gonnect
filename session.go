package gonnect

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gonnect/internal/coretypes"
	"net/http"
	"sync"
	"time"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CookieOptions holds configuration for cookie-based sessions
type CookieOptions struct {
	Path     string        // Cookie path (default: "/")
	Domain   string        // Cookie domain
	MaxAge   time.Duration // Session expiration (default: 24 hours)
	Secure   bool          // Secure flag (default: true for HTTPS)
	HttpOnly bool          // HttpOnly flag (default: true)
	SameSite http.SameSite // SameSite attribute (default: SameSiteLaxMode)
}

// CookieSessionStore implements SessionStore using encrypted cookies
type CookieSessionStore struct {
	secretKey []byte
	options   CookieOptions
	gcm       cipher.AEAD
}

// cookieSession implements the Session interface
type cookieSession struct {
	id           string
	name         string // Cookie name
	values       map[string]interface{}
	isNew        bool
	createdAt    time.Time
	lastAccessed time.Time
	maxAge       time.Duration
	mutex        sync.RWMutex
}

// NewCookieSessionStore creates a new cookie-based session store with AES-256-GCM encryption
func NewCookieSessionStore(secretKey []byte, opts CookieOptions) *CookieSessionStore {
	if len(secretKey) < 32 {
		panic("gonnect: session secret key must be at least 32 bytes")
	}

	// Create AES cipher for encryption
	block, err := aes.NewCipher(secretKey[:32])
	if err != nil {
		panic("gonnect: failed to create AES cipher: " + err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("gonnect: failed to create GCM cipher: " + err.Error())
	}

	// Set secure defaults
	if opts.Path == "" {
		opts.Path = "/"
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 24 * time.Hour
	}
	if opts.SameSite == 0 {
		opts.SameSite = http.SameSiteLaxMode
	}
	opts.HttpOnly = true // Always enforce HttpOnly for security

	return &CookieSessionStore{
		secretKey: secretKey,
		options:   opts,
		gcm:       gcm,
	}
}

// Get retrieves an existing session from the request
func (s *CookieSessionStore) Get(ctx context.Context, r *http.Request, name string) (Session, error) {
	fmt.Printf("DEBUG: CookieSessionStore.Get() called with name: %s\n", name)

	// Debug: Print all cookies
	fmt.Printf("DEBUG: All cookies in request:\n")
	for _, cookie := range r.Cookies() {
		fmt.Printf("  - %s = %s\n", cookie.Name, cookie.Value[:min(50, len(cookie.Value))])
	}

	cookie, err := r.Cookie(name)
	if err != nil {
		fmt.Printf("DEBUG: Cookie '%s' not found: %v\n", name, err)
		// Cookie not found, return new session
		return s.New(ctx, r, name), nil
	}

	fmt.Printf("DEBUG: Found cookie '%s' with value length: %d\n", name, len(cookie.Value))

	session, err := s.decryptSession(cookie.Value)
	if err != nil {
		fmt.Printf("DEBUG: Failed to decrypt session: %v\n", err)
		// Invalid session, return new session
		return s.New(ctx, r, name), nil
	}

	// Set the session name and update last accessed time
	session.name = name
	session.lastAccessed = time.Now()
	session.isNew = false

	fmt.Printf("DEBUG: Successfully retrieved session with ID: %s\n", session.id)
	return session, nil
}

// New creates a new session
func (s *CookieSessionStore) New(ctx context.Context, r *http.Request, name string) Session {
	now := time.Now()
	return &cookieSession{
		id:           generateSessionID(),
		name:         name,
		values:       make(map[string]interface{}),
		isNew:        true,
		createdAt:    now,
		lastAccessed: now,
		maxAge:       s.options.MaxAge,
	}
}

// Save encrypts and saves the session as a cookie
func (s *CookieSessionStore) Save(ctx context.Context, w http.ResponseWriter, r *http.Request, session Session) error {
	cookieSession := session.(*cookieSession)
	fmt.Printf("DEBUG: CookieSessionStore.Save() called for session ID: %s, name: %s\n", cookieSession.id, cookieSession.name)

	encryptedData, err := s.encryptSession(cookieSession)
	if err != nil {
		fmt.Printf("DEBUG: Failed to encrypt session: %v\n", err)
		return coretypes.NewErrorWithCause(coretypes.ErrTypeSession, "failed to encrypt session", err)
	}

	cookie := &http.Cookie{
		Name:     cookieSession.name, // Use session name as cookie name
		Value:    encryptedData,
		Path:     s.options.Path,
		Domain:   s.options.Domain,
		MaxAge:   int(s.options.MaxAge.Seconds()),
		Secure:   s.options.Secure,
		HttpOnly: s.options.HttpOnly,
		SameSite: s.options.SameSite,
	}

	fmt.Printf("DEBUG: Setting cookie with name: %s, path: %s, maxAge: %d, secure: %v, httpOnly: %v\n",
		cookie.Name, cookie.Path, cookie.MaxAge, cookie.Secure, cookie.HttpOnly)

	http.SetCookie(w, cookie)
	return nil
}

// Delete removes the session cookie
func (s *CookieSessionStore) Delete(ctx context.Context, w http.ResponseWriter, r *http.Request, session Session) error {
	cookieSession := session.(*cookieSession)
	cookie := &http.Cookie{
		Name:     cookieSession.name, // Use session name as cookie name
		Value:    "",
		Path:     s.options.Path,
		Domain:   s.options.Domain,
		MaxAge:   -1,
		Secure:   s.options.Secure,
		HttpOnly: s.options.HttpOnly,
		SameSite: s.options.SameSite,
	}

	http.SetCookie(w, cookie)
	return nil
}

// encryptSession encrypts session data using AES-256-GCM
func (s *CookieSessionStore) encryptSession(session *cookieSession) (string, error) {
	// Serialize session data
	data := map[string]interface{}{
		"id":            session.id,
		"values":        session.values,
		"created_at":    session.createdAt.Unix(),
		"last_accessed": session.lastAccessed.Unix(),
		"max_age":       session.maxAge.Seconds(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Encrypt data
	ciphertext := s.gcm.Seal(nonce, nonce, jsonData, nil)

	// Create HMAC for additional authentication
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write(ciphertext)
	signature := mac.Sum(nil)

	// Combine signature and ciphertext
	combined := append(signature, ciphertext...)

	return base64.URLEncoding.EncodeToString(combined), nil
}

// decryptSession decrypts and validates session data
func (s *CookieSessionStore) decryptSession(encryptedData string) (*cookieSession, error) {
	// Decode base64
	combined, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(combined) < 32 {
		return nil, fmt.Errorf("invalid session data length")
	}

	// Split signature and ciphertext
	signature := combined[:32]
	ciphertext := combined[32:]

	// Verify HMAC
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write(ciphertext)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("session signature verification failed")
	}

	// Extract nonce and encrypted data
	nonceSize := s.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	nonce := ciphertext[:nonceSize]
	encryptedPayload := ciphertext[nonceSize:]

	// Decrypt data
	plaintext, err := s.gcm.Open(nil, nonce, encryptedPayload, nil)
	if err != nil {
		return nil, err
	}

	// Deserialize session data
	var data map[string]interface{}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}

	// Reconstruct session with safe type assertions
	id, ok := data["id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session id type")
	}

	values, ok := data["values"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid session values type")
	}

	createdAtFloat, ok := data["created_at"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid session created_at type")
	}

	lastAccessedFloat, ok := data["last_accessed"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid session last_accessed type")
	}

	maxAgeFloat, ok := data["max_age"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid session max_age type")
	}

	session := &cookieSession{
		id:           id,
		name:         "", // Will be set by the caller
		values:       values,
		createdAt:    time.Unix(int64(createdAtFloat), 0),
		lastAccessed: time.Unix(int64(lastAccessedFloat), 0),
		maxAge:       time.Duration(maxAgeFloat) * time.Second,
	}

	// Check if session has expired
	if time.Since(session.lastAccessed) > session.maxAge {
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// generateSessionID generates a secure random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("gonnect: failed to generate session ID: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Session interface implementation for cookieSession

// ID returns the session ID
func (s *cookieSession) ID() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.id
}

// Get retrieves a value from the session
func (s *cookieSession) Get(key string) interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.values[key]
}

// Set stores a value in the session
func (s *cookieSession) Set(key string, val interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.values[key] = val
}

// Delete removes a value from the session
func (s *cookieSession) Delete(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.values, key)
}

// Clear removes all values from the session
func (s *cookieSession) Clear() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.values = make(map[string]interface{})
}

// IsNew returns true if this is a new session
func (s *cookieSession) IsNew() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isNew
}

// Values returns a copy of all session values
func (s *cookieSession) Values() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	values := make(map[string]interface{})
	for k, v := range s.values {
		values[k] = v
	}
	return values
}

// CreatedAt returns when the session was created
func (s *cookieSession) CreatedAt() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.createdAt
}

// LastAccessed returns when the session was last accessed
func (s *cookieSession) LastAccessed() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.lastAccessed
}

// MaxAge returns the session's maximum age
func (s *cookieSession) MaxAge() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.maxAge
}

// SetMaxAge sets the session's maximum age
func (s *cookieSession) SetMaxAge(duration time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.maxAge = duration
}
