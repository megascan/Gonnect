package google

import (
	"context"
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
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// Provider implements the gonnect.Provider interface for Google OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by Google's UserInfo endpoint
type UserInfo struct {
	Sub           string `json:"sub"` // Subject identifier - Standard OIDC claim
	ID            string `json:"id"`  // Google also often includes "id" which is same as "sub"
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	HD            string `json:"hd,omitempty"` // Hosted G Suite domain for the user
}

// TokenResponse represents the OAuth2 token response from Google
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// New creates a new Google provider instance.
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

// Name returns the provider's name
func (p *Provider) Name() string {
	return "google"
}

// BeginAuth initiates the OAuth2 flow by returning the authorization URL
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"response_type": {"code"},
		"state":         {state},
		"access_type":   {"offline"}, // Request refresh token
		"prompt":        {"consent"}, // Force consent to get refresh token
	}

	authURLWithParams := googleAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow using the authorization code
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State is validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	googleToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	googleUserInfo, err := p.fetchUserInfo(ctx, googleToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(googleUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal google user info: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal google user info to map: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user = coretypes.User{
		ID:        googleUserInfo.Sub, // "sub" is the standard OIDC subject identifier
		Email:     googleUserInfo.Email,
		Name:      googleUserInfo.Name,
		Username:  googleUserInfo.Email, // Google doesn't have a distinct username, email is often used
		AvatarURL: googleUserInfo.Picture,
		Locale:    googleUserInfo.Locale,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  googleToken.AccessToken,
		RefreshToken: googleToken.RefreshToken,
		TokenType:    googleToken.TokenType,
		IDToken:      googleToken.IDToken, // Google provides ID token
		Scope:        googleToken.Scope,
		Expiry:       time.Now().Add(time.Second * time.Duration(googleToken.ExpiresIn)),
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

	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh token request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to refresh token: "+err.Error()) // Was ErrTypeNetworkIO
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read refresh token response body: "+err.Error()) // Was ErrTypeNetworkIO
	}

	if resp.StatusCode != http.StatusOK {
		// Attempt to parse Google error response for refresh token
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("failed to refresh token: %s - %s", errResp.Error, errResp.ErrorDescription))
		}
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var refreshedTokenResp TokenResponse // Google refresh response does NOT include a new refresh_token
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error()) // Was ErrTypeJSONParsing
	}

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshToken, // Google does not return a new refresh token, so reuse the old one.
		TokenType:    refreshedTokenResp.TokenType,
		IDToken:      refreshedTokenResp.IDToken, // A new ID token might be returned
		Scope:        refreshedTokenResp.Scope,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	return newGonnectToken, nil
}

// ValidateToken validates a token and returns user info
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty for validation")
	}

	// To validate, we can try to fetch user info.
	// Alternatively, for Google, if an ID token is present, its signature and claims can be validated locally (more complex).
	// Using userinfo endpoint is simpler for this example.
	googleUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		// If fetchUserInfo fails, the token is likely invalid or expired.
		return coretypes.User{}, false, err // Error from fetchUserInfo indicates invalid token
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(googleUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal google user info for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal google user info to map for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user := coretypes.User{
		ID:        googleUserInfo.Sub,
		Email:     googleUserInfo.Email,
		Name:      googleUserInfo.Name,
		Username:  googleUserInfo.Email,
		AvatarURL: googleUserInfo.Picture,
		Locale:    googleUserInfo.Locale,
		RawData:   rawData,
	}

	return user, true, nil
}

// SupportsRefresh indicates that Google supports token refresh
func (p *Provider) SupportsRefresh() bool {
	return true
}

// exchangeCodeForToken exchanges an authorization code for access and refresh tokens
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", p.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to exchange code for token: "+err.Error()) // Was ErrTypeNetworkIO
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read token response body: "+err.Error()) // Was ErrTypeNetworkIO
	}

	if resp.StatusCode != http.StatusOK {
		// Attempt to parse Google error response
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token: %s - %s", errResp.Error, errResp.ErrorDescription))
		}
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse token response: "+err.Error()) // Was ErrTypeJSONParsing
	}

	return tokenResponse, nil
}

// fetchUserInfo retrieves user information from Google's API
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to fetch user info: "+err.Error()) // Was ErrTypeNetworkIO
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read user info response body: "+err.Error()) // Was ErrTypeNetworkIO
	}

	if resp.StatusCode != http.StatusOK {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get user info, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse user info: "+err.Error()) // Was ErrTypeJSONParsing
	}

	return userInfo, nil
}
