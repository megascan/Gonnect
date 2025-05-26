package yahoo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gonnect/internal/coretypes"
)

const (
	yahooAuthURL  = "https://api.login.yahoo.com/oauth2/request_auth"
	yahooTokenURL = "https://api.login.yahoo.com/oauth2/get_token"
	// No separate UserInfo endpoint, info is in ID token
)

// Provider implements the coretypes.Provider interface for Yahoo OAuth2 (OpenID Connect).
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// IDTokenClaims represents the claims typically found in a Yahoo ID Token.
// Based on standard OIDC claims.
// https://developer.yahoo.com/oauth2/guide/openid_connect/getting_started.html#id_token
// Actual claims present may vary based on scopes and Yahoo's implementation.
type IDTokenClaims struct {
	ISS             string   `json:"iss"`             // Issuer
	Sub             string   `json:"sub"`             // Subject - User ID (Yahoo GUID)
	Aud             []string `json:"aud"`             // Audience (should contain client_id)
	EXP             int64    `json:"exp"`             // Expiration time
	IAT             int64    `json:"iat"`             // Issued at time
	Nonce           string   `json:"nonce,omitempty"` // Nonce from auth request
	Name            string   `json:"name,omitempty"`
	GivenName       string   `json:"given_name,omitempty"`
	FamilyName      string   `json:"family_name,omitempty"`
	Nickname        string   `json:"nickname,omitempty"`
	Email           string   `json:"email,omitempty"`
	EmailVerified   bool     `json:"email_verified,omitempty"`
	Picture         string   `json:"picture,omitempty"`
	ProfileURL      string   `json:"profile,omitempty"` // Standard OIDC claim name
	Locale          string   `json:"locale,omitempty"`
	XOauthYahooGUID string   `json:"xoauth_yahoo_guid,omitempty"` // Specific to Yahoo in token response, might also be in ID token
}

// TokenResponse is the OAuth2 token response from Yahoo.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IDToken         string `json:"id_token"`
	ExpiresIn       int64  `json:"expires_in"`
	TokenType       string `json:"token_type"`
	RefreshToken    string `json:"refresh_token"`
	XOauthYahooGUID string `json:"xoauth_yahoo_guid"`
}

// New creates a new Yahoo provider instance.
// Default scopes are "openid", "profile", "email".
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

func (p *Provider) Name() string {
	return "yahoo"
}

// TODO: Ideally use a shared utility for random string generation (e.g., from a future gonnect/utils package)
func generateNonce(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	nonce, err := generateNonce(32) // Generate a 32-byte random string for nonce
	if err != nil {
		return "", coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to generate nonce: "+err.Error())
	}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("redirect_uri", p.redirectURL)
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(p.scopes, " "))
	v.Set("state", state)
	v.Set("nonce", nonce)

	return yahooAuthURL + "?" + v.Encode(), nil
}

// decodeIDToken decodes the JWT payload without verifying the signature.
// IMPORTANT: In a production environment, the signature MUST be verified against Yahoo's public keys (JWKS).
func decodeIDToken(idToken string) (IDTokenClaims, error) {
	var claims IDTokenClaims
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 { // Should be 3 parts for a JWS, but we only need payload
		return claims, fmt.Errorf("invalid ID token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("failed to decode ID token payload: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("failed to parse ID token claims: %w", err)
	}
	return claims, nil
}

func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State is validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	yahooToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	idTokenClaims, err := decodeIDToken(yahooToken.IDToken)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "failed to decode ID token: "+err.Error())
	}

	// IMPORTANT: Validate ID Token claims (e.g., issuer, audience, nonce, expiry)
	// For example, check idTokenClaims.Nonce against the one stored in session.
	// This validation is critical for security and should be handled by Gonnect core or here robustly.
	// sessionNonce := session.GetNonce(state) // Example of how nonce might be retrieved
	// if idTokenClaims.Nonce != sessionNonce {
	// 	 return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token nonce mismatch")
	// }
	// if !contains(idTokenClaims.Aud, p.clientID) {
	// 	 return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token audience mismatch")
	// }
	// if idTokenClaims.EXP < time.Now().Unix() {
	// 	 return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token expired")
	// }
	// if idTokenClaims.ISS != "https://api.login.yahoo.com" { // Or from discovery document
	// 	 return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "ID token issuer mismatch")
	// }

	// Convert IDTokenClaims to map[string]interface{} for RawData
	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(idTokenClaims)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal ID token claims: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal ID token claims to map: "+err.Error())
	}

	user = coretypes.User{
		ID:        idTokenClaims.Sub, // Yahoo User ID (GUID)
		Email:     idTokenClaims.Email,
		Name:      idTokenClaims.Name,
		Username:  idTokenClaims.Nickname, // Or preferred_username if available
		AvatarURL: idTokenClaims.Picture,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  yahooToken.AccessToken,
		RefreshToken: yahooToken.RefreshToken,
		IDToken:      yahooToken.IDToken,
		TokenType:    yahooToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(yahooToken.ExpiresIn)),
	}

	return user, token, nil
}

func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("redirect_uri", p.redirectURL)
	v.Set("code", code)
	v.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, "POST", yahooTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "token request failed: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read token response: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("token request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to decode token response: "+err.Error())
	}

	return tokenResponse, nil
}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	var token coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("refresh_token", refreshToken)
	v.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, "POST", yahooTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "refresh request failed: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read refresh response: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("refresh request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to decode refresh response: "+err.Error())
	}

	token = coretypes.Token{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		IDToken:      tokenResponse.IDToken,
		TokenType:    tokenResponse.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)),
	}

	return token, nil
}

func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	// For Yahoo (OpenID Connect), we can validate the ID token if present
	if token.IDToken != "" {
		idTokenClaims, err := decodeIDToken(token.IDToken)
		if err != nil {
			return coretypes.User{}, false, nil // Invalid ID token
		}

		// Check if ID token is expired
		if idTokenClaims.EXP < time.Now().Unix() {
			return coretypes.User{}, false, nil // ID token expired
		}

		// Convert IDTokenClaims to map[string]interface{} for RawData
		var rawData map[string]interface{}
		jsonBytes, err := json.Marshal(idTokenClaims)
		if err != nil {
			return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal ID token claims: "+err.Error())
		}
		if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
			return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal ID token claims to map: "+err.Error())
		}

		user := coretypes.User{
			ID:        idTokenClaims.Sub,
			Email:     idTokenClaims.Email,
			Name:      idTokenClaims.Name,
			Username:  idTokenClaims.Nickname,
			AvatarURL: idTokenClaims.Picture,
			RawData:   rawData,
		}

		return user, true, nil
	}

	// If no ID token, we can't validate without making an API call
	// Yahoo doesn't have a separate userinfo endpoint like some other providers
	return coretypes.User{}, false, nil
}

func (p *Provider) SupportsRefresh() bool {
	return true
}
