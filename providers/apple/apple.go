package apple

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/megascan/gonnect/internal/coretypes"

	"github.com/golang-jwt/jwt/v4"
)

const (
	appleAuthURL     = "https://appleid.apple.com/auth/authorize"
	appleTokenURL    = "https://appleid.apple.com/auth/token"
	appleUserInfoURL = "https://appleid.apple.com/auth/userinfo" // This might not be standard or might require special handling
	appleIssuerURL   = "https://appleid.apple.com"
	appleKeysURL     = "https://appleid.apple.com/auth/keys"
)

// Provider implements the gonnect.Provider interface for Apple OAuth2
type Provider struct {
	clientID     string
	clientSecret string // This is often a JWT signed by your private key for Apple
	redirectURL  string
	scopes       []string
	// teamID       string // Often required for client_secret generation
	// keyID        string // Often required for client_secret generation
	// privateKey   string // Path to or content of the .p8 private key file
}

// UserInfo represents the user information that might be decoded from Apple's ID token
// or fetched from a userinfo endpoint (if Apple provides one that's usable this way).
// Apple primarily relies on the ID Token for user information.
type UserInfo struct {
	Sub            string `json:"sub"` // User's unique ID
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`   // Can be string "true" or bool true
	IsPrivateEmail string `json:"is_private_email"` // Can be string "true" or bool true, for private relay emails
	RealUserStatus int    `json:"real_user_status"` // Indicates if Apple believes this is a real user (0, 1, or 2)
	// Name fields are typically requested via scope and come in the initial callback user object, not always in ID token.
	// Name           NameInfo `json:"name,omitempty"`
}

// IDTokenClaims represents the claims in Apple's ID token
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Nonce         string `json:"nonce,omitempty"`
}

/* // NameInfo is nested if name scope is requested and user provides it.
   // This often comes in the `user` JSON object alongside the `code` in the initial POST, not from token/userinfo endpoint.
type NameInfo struct {
    FirstName string `json:"firstName,omitempty"`
    LastName  string `json:"lastName,omitempty"`
}*/

// TokenResponse represents the OAuth2 token response from Apple
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"` // Crucial for Apple, contains user info
}

// AppleErrorResponse represents error responses from Apple
type AppleErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// AppleKey represents a public key from Apple's JWKS endpoint
type AppleKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AppleKeysResponse represents the response from Apple's keys endpoint
type AppleKeysResponse struct {
	Keys []AppleKey `json:"keys"`
}

// New creates a new Apple provider instance
// Note: clientSecret for Apple is complex, usually a JWT you generate.
// This basic setup assumes clientSecret is pre-generated or handled externally.
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret, // This would need to be the generated JWT for token requests
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

// Name returns the provider's name
func (p *Provider) Name() string {
	return "apple"
}

// BeginAuth initiates the OAuth2 flow by returning the authorization URL
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"response_type": {"code"}, // Some flows might ask for "code id_token"
		"state":         {state},
		"response_mode": {"form_post"}, // Apple requires form_post for web
	}

	authURLWithParams := appleAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow using the authorization code
// Apple sends user data in the initial POST along with the code if name/email scopes are requested.
// This info should be captured here if needed, as it's not always in the ID token.
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	// Apple typically sends data as POST form parameters
	if err := r.ParseForm(); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "failed to parse callback form: "+err.Error())
	}

	code := r.FormValue("code")
	// state := r.FormValue("state") // State is validated by Gonnect core
	idTokenHint := r.FormValue("id_token") // This is the ID token from Apple
	userJSON := r.FormValue("user")        // Optional user struct if 'name' scope was granted during first auth

	if code == "" && idTokenHint == "" { // id_token might be sent directly if re-authenticating without code
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code and id_token not found in callback")
	}

	// If code is present, exchange it for tokens
	var appleTokenResp TokenResponse
	var claims *IDTokenClaims

	if code != "" {
		var err error
		appleTokenResp, err = p.exchangeCodeForToken(ctx, code)
		if err != nil {
			return user, token, err
		}
		// If response contains an ID token, use that. Otherwise, expect it from callback.
		if appleTokenResp.IDToken != "" {
			idTokenHint = appleTokenResp.IDToken
		}
	}

	if idTokenHint == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token not found in token response or callback")
	}

	// Validate and parse the ID token
	claims, validationErr := p.validateIDToken(ctx, idTokenHint)
	if validationErr != nil {
		return user, token, validationErr
	}

	// Populate user information from ID token claims
	parsedUser, err := p.parseUserInfoFromClaims(claims, userJSON)
	if err != nil {
		return user, token, err
	}
	user = parsedUser

	token = coretypes.Token{
		AccessToken:  appleTokenResp.AccessToken,  // This might be empty if only id_token flow
		RefreshToken: appleTokenResp.RefreshToken, // Often not provided by Apple in subsequent auths
		IDToken:      idTokenHint,
		TokenType:    appleTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(appleTokenResp.ExpiresIn)),
	}

	return user, token, nil
}

// RefreshToken refreshes an access token using a refresh token
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	var newGonnectToken coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	if refreshToken == "" {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "refresh token is empty")
	}

	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to generate client secret for refresh: "+err.Error())
	}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", clientSecret)
	v.Set("refresh_token", refreshToken)
	v.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to refresh token: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read refresh token response body: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		var errResp AppleErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			// Common error: "invalid_grant". Can mean refresh token expired or revoked.
			return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("failed to refresh Apple token: %s - %s", errResp.Error, errResp.ErrorDescription))
		}
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var refreshedTokenResp TokenResponse // Apple returns new AT, new RT (sometimes), and new ID token
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error())
	}

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshedTokenResp.RefreshToken, // Apple may or may not return a new RT
		IDToken:      refreshedTokenResp.IDToken,      // A new ID token is usually returned
		TokenType:    refreshedTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	// Persist the old refresh token if Apple doesn't send a new one
	if newGonnectToken.RefreshToken == "" {
		newGonnectToken.RefreshToken = refreshToken
	}

	return newGonnectToken, nil
}

// ValidateToken validates a token (typically ID token for Apple)
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.IDToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token is empty for validation")
	}

	claims, validationErr := p.validateIDToken(ctx, token.IDToken)
	if validationErr != nil {
		return coretypes.User{}, false, validationErr // Already a GonnectError
	}

	// User info from claims. The `userJSON` would not be available here usually.
	user, err := p.parseUserInfoFromClaims(claims, "")
	if err != nil {
		return coretypes.User{}, false, err // Already a GonnectError
	}

	return user, true, nil
}

// SupportsRefresh indicates if the provider supports token refresh
func (p *Provider) SupportsRefresh() bool {
	return true
}

// exchangeCodeForToken exchanges authorization code for access token
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to generate client secret for Apple: "+err.Error())
	}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", clientSecret)
	v.Set("code", code)
	v.Set("grant_type", "authorization_code")
	v.Set("redirect_uri", p.redirectURL) // Required by Apple

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to exchange code for token: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read token response body: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		var errResp AppleErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token from Apple: %s - %s", errResp.Error, errResp.ErrorDescription))
		}
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse token response: "+err.Error())
	}

	return tokenResponse, nil
}

// fetchUserInfoFromIDTokenOrEndpoint is a placeholder for ID Token parsing or UserInfo endpoint call.
// Apple's primary user info source is the ID Token.
// A UserInfo endpoint like `appleUserInfoURL` is not standard for claims beyond what's in the ID token.
func (p *Provider) fetchUserInfoFromIDTokenOrEndpoint(ctx context.Context, accessToken, idToken string) (UserInfo, error) {
	// 1. PRIORITIZE ID TOKEN PARSING (Requires a JWT library e.g., github.com/golang-jwt/jwt/v5)
	//    - Verify signature using Apple's public keys.
	//    - Validate issuer (iss), audience (aud), expiration (exp), nonce (if used).
	//    - Extract claims like sub, email, email_verified, is_private_email, real_user_status.
	// Example (conceptual, needs JWT lib):
	/*
	   token, err := jwt.ParseWithClaims(idToken, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
	       // Fetch Apple public key based on kid in token header
	       return applePublicKey, nil
	   })
	   if err == nil && token.Valid {
	       claims := token.Claims.(*MyCustomClaims)
	       return UserInfo{Sub: claims.Sub, Email: claims.Email, ...}, nil
	   }
	*/

	// 2. FALLBACK/SUPPLEMENTAL: UserInfo Endpoint (IF a suitable one exists and is needed)
	// The standard OIDC UserInfo endpoint concept is less central to Apple's flow.
	// If p.appleUserInfoURL is set and meant to be used (and if it works with Bearer token):
	if accessToken != "" && appleUserInfoURL != "" { // Check if we have a token and URL
		req, err := http.NewRequestWithContext(ctx, "GET", appleUserInfoURL, nil)
		if err != nil {
			return UserInfo{}, fmt.Errorf("failed to create userinfo request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return UserInfo{}, fmt.Errorf("userinfo request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return UserInfo{}, fmt.Errorf("userinfo request returned status %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var userInfo UserInfo
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			return UserInfo{}, fmt.Errorf("failed to decode userinfo response: %w", err)
		}
		return userInfo, nil
	}

	// If only ID token is available and not parsed yet (as in this simplified example):
	// Return an error or an empty/partial UserInfo if critical fields can't be obtained.
	// This indicates that proper ID token parsing is essential.
	if idToken != "" {
		// Here you would parse the idToken. Since we are not doing that fully...
		// We can return an error, or if some basic info can be non-securely guessed for placeholder:
		// This is NOT for production. For now, returning error as proper parsing is needed.
		return UserInfo{}, fmt.Errorf("ID token present but not parsed; proper JWT validation required")
	}

	return UserInfo{}, fmt.Errorf("unable to fetch user information: no valid ID token parsing and no access token for endpoint call")
}

// Helper to read all bytes from io.Reader, used for error messages.
// Go 1.16+ has io.ReadAll directly.
func ioReadAll(r io.Reader) ([]byte, error) {
	// Simplified for brevity, in real code use io.ReadAll if Go version >= 1.16
	// or a loop with a buffer for older versions.
	buf := new(strings.Builder)
	_, err := io.Copy(buf, r)
	return []byte(buf.String()), err
}

// validateIDToken decodes and validates the ID token from Apple.
// Returns the parsed claims or a GonnectError.
func (p *Provider) validateIDToken(ctx context.Context, idToken string) (*IDTokenClaims, error) {
	keySet, err := p.fetchApplePublicKeys(ctx)
	if err != nil {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to fetch Apple public keys: "+err.Error()) // Already a GonnectError from fetchApplePublicKeys
	}

	var claims IDTokenClaims
	token, err := jwt.ParseWithClaims(idToken, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid header missing from token")
		}

		key, found := keySet[kid]
		if !found {
			return nil, fmt.Errorf("public key with kid '%s' not found", kid)
		}
		return key, nil // Return the *rsa.PublicKey
	})

	if err != nil {
		// Check for specific JWT errors
		var jwtErr *jwt.ValidationError
		if errors.As(err, &jwtErr) {
			if jwtErr.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "malformed ID token")
			} else if jwtErr.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token has expired")
			} else if jwtErr.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token not valid yet")
			} else if jwtErr.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token signature is invalid")
			}
		}
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "failed to parse or validate ID token: "+err.Error())
	}

	if !token.Valid {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token is invalid")
	}

	// Perform claims validation (issuer, audience, expiry already checked by jwt library if within leeway)
	if claims.Issuer != appleIssuerURL {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("ID token issuer mismatch: expected %s, got %s", appleIssuerURL, claims.Issuer))
	}
	if claims.Audience != p.clientID {
		// Apple ID tokens can have an array of audiences. For client-side apps, it's the client_id.
		// For server-side apps using client_secret_post, it might be different or also array.
		// For simplicity, checking single string audience here.
		// TODO: Handle array audience if necessary: `if !containsString(claims.AudienceArray, p.clientID)`
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("ID token audience mismatch: expected %s, got %s", p.clientID, claims.Audience))
	}

	// Nonce validation would happen here if p.storeNonce and p.retrieveNonce were implemented for CSRF protection
	// if claims.Nonce != p.retrieveNonce(state) { return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token nonce mismatch") }

	return &claims, nil
}

// parseUserInfoFromClaims constructs a gonnect.User from the ID token claims and optional user JSON.
func (p *Provider) parseUserInfoFromClaims(claims *IDTokenClaims, userJSON string) (coretypes.User, error) {
	email := claims.Email
	_ = claims.EmailVerified // Available in rawData

	var nameComponents struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	fullName := ""

	if userJSON != "" {
		var providedUser struct {
			Name  json.RawMessage `json:"name"` // Can be string or struct
			Email string          `json:"email"`
		}
		if err := json.Unmarshal([]byte(userJSON), &providedUser); err == nil {
			// Try to parse Name as struct first
			if json.Unmarshal(providedUser.Name, &nameComponents) == nil {
				fullName = strings.TrimSpace(nameComponents.FirstName + " " + nameComponents.LastName)
			} else {
				// Try to parse Name as string
				_ = json.Unmarshal(providedUser.Name, &fullName)
			}
			if providedUser.Email != "" && email == "" { // Prefer email from ID token if available
				email = providedUser.Email
				// email_verified status from `user` struct is not standard, rely on ID token's claim.
			}
		}
	}
	if fullName == "" && claims.Name != "" { // Fallback to name claim if present (not standard OIDC, but some might send)
		fullName = claims.Name
	}

	// Convert claims to map[string]interface{} for RawData
	var rawData map[string]interface{}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal ID token claims: "+err.Error())
	}
	if err := json.Unmarshal(claimsBytes, &rawData); err != nil {
		return coretypes.User{}, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal ID token claims to map: "+err.Error())
	}
	if userJSON != "" {
		var userRaw map[string]interface{}
		if json.Unmarshal([]byte(userJSON), &userRaw) == nil {
			rawData["user_provided"] = userRaw
		}
	}

	return coretypes.User{
		ID: claims.Subject, // Apple's unique user ID
		// Email might be a private relay email if user chose to hide their email.
		Email:   email,
		Name:    fullName,
		RawData: rawData,
		// Username, AvatarURL, Locale are not typically provided directly by Apple in ID token.
		// email_verified is an important claim for Apple.
		// Add it to rawData or a specific field if Gonnect.User supports it.
		// For now, it's in rawData via `claims.EmailVerified`.
	}, nil
}

// generateClientSecret generates a JWT client secret for Apple
// This is a simplified implementation - in production, you would need proper key management
func (p *Provider) generateClientSecret() (string, error) {
	// For now, return the pre-configured client secret
	// In a full implementation, this would generate a JWT using your private key
	if p.clientSecret == "" {
		return "", fmt.Errorf("client secret not configured")
	}
	return p.clientSecret, nil
}

// fetchApplePublicKeys fetches Apple's public keys for JWT verification
// This is a simplified implementation - in production, you would cache these keys
func (p *Provider) fetchApplePublicKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	// This is a placeholder implementation
	// In a real implementation, you would:
	// 1. Fetch keys from https://appleid.apple.com/auth/keys
	// 2. Parse the JWKS response
	// 3. Convert to RSA public keys
	// 4. Cache the keys with appropriate TTL

	return nil, fmt.Errorf("Apple public key fetching not implemented - this is a placeholder")
}
