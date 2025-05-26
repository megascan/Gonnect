package twitter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/megascan/gonnect/internal/coretypes"
)

// Note: Twitter API v1.1 (used in original example) is legacy.
// Twitter API v2 is preferred for new integrations and uses different OAuth2 flows (PKCE for user context).
// This implementation will reflect a basic OAuth2 flow, but specifics might vary with API v2.
const (
	twitterAuthURLBase    = "https://twitter.com/i/oauth2/authorize" // Example, check current Twitter docs
	twitterTokenURL       = "https://api.twitter.com/2/oauth2/token" // Example for v2
	twitterUserInfoURL_v2 = "https://api.twitter.com/2/users/me"     // Example for v2
)

// Provider implements the coretypes.Provider interface for Twitter OAuth2
type Provider struct {
	clientID     string
	clientSecret string // For confidential clients
	redirectURL  string
	scopes       []string
	// For PKCE flow (often used with public clients / mobile apps for v2):
	// codeVerifier string
}

// UserInfoV2 represents user information from Twitter API v2 /users/me endpoint
type UserInfoV2 struct {
	Data struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		// Add other fields as needed based on scope, e.g., profile_image_url, public_metrics, etc.
		ProfileImageURL string `json:"profile_image_url,omitempty"`
	} `json:"data"`
}

// TokenResponse represents the OAuth2 token response from Twitter
type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // In seconds
	AccessToken  string `json:"access_token"`
	Scope        string `json:"scope"` // Scopes granted
	RefreshToken string `json:"refresh_token,omitempty"`
}

// New creates a new Twitter provider instance
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

// Name returns the provider's name
func (p *Provider) Name() string {
	return "twitter"
}

// BeginAuth initiates the OAuth2 flow
// Twitter v2 uses PKCE, which requires generating a code_challenge and code_verifier.
// This basic example will omit PKCE for simplicity, assuming a flow that doesn't strictly require it
// or that client_secret is sufficient (confidential client).
// ALWAYS consult current Twitter OAuth2 documentation for the correct flow for your app type.
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")}, // Scopes are space-separated for Twitter v2
		"response_type": {"code"},
		"state":         {state},
		// For PKCE, you'd add:
		// "code_challenge": {generateCodeChallenge(p.codeVerifier)},
		// "code_challenge_method": {"S256"},
	}
	authURLWithParams := twitterAuthURLBase + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return coretypes.User{}, coretypes.Token{}, coretypes.NewProviderError("twitter", coretypes.ErrTypeAuthentication, "authorization code not found")
	}

	token, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, err
	}

	user, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, err
	}
	return user, token, nil
}

// RefreshToken refreshes an access token if a refresh token is available
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	if refreshToken == "" {
		return coretypes.Token{}, coretypes.NewProviderError("twitter", coretypes.ErrTypeToken, "refresh token is required")
	}
	data := url.Values{
		"client_id": {p.clientID},
		// Client secret might be required for confidential clients, sent via Basic Auth or in body
		// "client_secret": {p.clientSecret}, // Consult Twitter docs for confidential client refresh
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
	}

	// Twitter API v2 token endpoint requires Basic Auth for confidential clients (clientID:clientSecret)
	req, err := http.NewRequestWithContext(ctx, "POST", twitterTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeToken, "failed to create refresh request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// For confidential clients, Twitter expects client_id and client_secret via HTTP Basic Auth.
	// If this is a public client, client_secret is not used, but client_id is in the body.
	if p.clientSecret != "" { // Assuming confidential client if secret is present
		req.SetBasicAuth(p.clientID, p.clientSecret)
	} else {
		// For public clients, ensure client_id is in the body (already handled by `data`)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeToken, "failed to refresh token", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.Token{}, coretypes.NewProviderError("twitter", coretypes.ErrTypeToken, fmt.Sprintf("token refresh failed with status %d", resp.StatusCode))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeToken, "failed to decode token response", err)
	}

	token := coretypes.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken, // Might get a new one
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	return token, nil
}

// ValidateToken attempts to fetch user info to validate the token.
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	user, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, nil // Invalid token or error
	}
	return user, true, nil
}

// SupportsRefresh indicates if the provider supports token refresh.
func (p *Provider) SupportsRefresh() bool {
	return true // Twitter API v2 supports refresh tokens
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (coretypes.Token, error) {
	data := url.Values{
		"code":         {code},
		"grant_type":   {"authorization_code"},
		"redirect_uri": {p.redirectURL},
		// For PKCE flow, add:
		// "code_verifier": {p.codeVerifier},
	}
	// For public clients, client_id is in the request body.
	// For confidential clients, it's via Basic Auth.
	if p.clientSecret == "" { // Assuming public client if no secret
		data.Set("client_id", p.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", twitterTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "failed to create token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if p.clientSecret != "" { // Confidential client: Use Basic Auth
		req.SetBasicAuth(p.clientID, p.clientSecret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "token request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.Token{}, coretypes.NewProviderError("twitter", coretypes.ErrTypeProvider, fmt.Sprintf("token request failed with status %d", resp.StatusCode))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "failed to decode token response", err)
	}

	token := coretypes.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}
	return token, nil
}

// fetchUserInfo retrieves user information from Twitter's API v2.
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (coretypes.User, error) {
	// Twitter API v2 /users/me endpoint
	// Requires user.read scope for basic profile information
	req, err := http.NewRequestWithContext(ctx, "GET", twitterUserInfoURL_v2+"?user.fields=profile_image_url", nil)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "failed to create userinfo request", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "userinfo request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.User{}, coretypes.NewProviderError("twitter", coretypes.ErrTypeProvider, fmt.Sprintf("userinfo request failed with status %d", resp.StatusCode))
	}

	var userInfo UserInfoV2
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("twitter", coretypes.ErrTypeProvider, "failed to decode userinfo response", err)
	}

	user := coretypes.User{
		ID:        userInfo.Data.ID,
		Name:      userInfo.Data.Name,
		Username:  userInfo.Data.Username,
		AvatarURL: userInfo.Data.ProfileImageURL,
		// Twitter API v2 doesn't directly provide email in /users/me unless specific scope and approval
		Email: "", // Would require additional API call with email scope
		RawData: map[string]interface{}{
			"provider": "twitter",
			"data":     userInfo.Data,
		},
	}
	return user, nil
}
