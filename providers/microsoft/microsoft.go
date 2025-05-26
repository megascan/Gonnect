package microsoft

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

const (
	microsoftAuthURL     = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	microsoftTokenURL    = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	microsoftUserInfoURL = "https://graph.microsoft.com/v1.0/me"
)

// Provider implements the coretypes.Provider interface for Microsoft OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by Microsoft Graph API
type UserInfo struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	JobTitle          string `json:"jobTitle"`
	OfficeLocation    string `json:"officeLocation"`
	PreferredLanguage string `json:"preferredLanguage"`
}

// TokenResponse represents the OAuth2 token response from Microsoft
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// New creates a new Microsoft provider instance
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
	return "microsoft"
}

// BeginAuth initiates the OAuth2 flow by returning the authorization URL
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"response_type": {"code"},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
		"response_mode": {"query"},
	}

	authURLWithParams := microsoftAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow using the authorization code
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return coretypes.User{}, coretypes.Token{}, coretypes.NewProviderError("microsoft", coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	// Exchange authorization code for tokens
	token, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to exchange authorization code for token", err)
	}

	// Fetch user information using the access token
	user, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to fetch user information", err)
	}

	return user, token, nil
}

// RefreshToken refreshes an access token using a refresh token
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	if refreshToken == "" {
		return coretypes.Token{}, coretypes.NewProviderError("microsoft", coretypes.ErrTypeToken, "refresh token is required")
	}

	data := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", microsoftTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeToken, "failed to create refresh request", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeToken, "failed to refresh token", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.Token{}, coretypes.NewProviderError("microsoft", coretypes.ErrTypeToken, fmt.Sprintf("token refresh failed with status: %d", resp.StatusCode))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeToken, "failed to decode token response", err)
	}

	// Convert to coretypes.Token
	token := coretypes.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}

	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// ValidateToken validates a token and returns user info
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	// Check if token is expired
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) {
		return coretypes.User{}, false, nil
	}

	// Fetch current user info to validate the token
	user, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		// Token is likely invalid
		return coretypes.User{}, false, nil
	}

	return user, true, nil
}

// SupportsRefresh indicates that Microsoft supports token refresh
func (p *Provider) SupportsRefresh() bool {
	return true
}

// exchangeCodeForToken exchanges an authorization code for access and refresh tokens
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (coretypes.Token, error) {
	data := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", microsoftTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return coretypes.Token{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.Token{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.Token{}, coretypes.NewProviderError("microsoft", coretypes.ErrTypeProvider, fmt.Sprintf("token exchange failed with status: %d", resp.StatusCode))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to decode token response", err)
	}

	// Convert to coretypes.Token
	token := coretypes.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}

	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// fetchUserInfo retrieves user information from Microsoft Graph API
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (coretypes.User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", microsoftUserInfoURL, nil)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to create user info request", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to fetch user info", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.User{}, coretypes.NewProviderError("microsoft", coretypes.ErrTypeProvider, fmt.Sprintf("user info request failed with status: %d", resp.StatusCode))
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("microsoft", coretypes.ErrTypeProvider, "failed to decode user info response", err)
	}

	// Convert Microsoft UserInfo to coretypes.User
	user := coretypes.User{
		ID:       userInfo.ID,
		Email:    userInfo.Mail,
		Name:     userInfo.DisplayName,
		Username: userInfo.UserPrincipalName,
		RawData: map[string]interface{}{
			"provider":          "microsoft",
			"id":                userInfo.ID,
			"displayName":       userInfo.DisplayName,
			"givenName":         userInfo.GivenName,
			"surname":           userInfo.Surname,
			"userPrincipalName": userInfo.UserPrincipalName,
			"mail":              userInfo.Mail,
			"jobTitle":          userInfo.JobTitle,
			"officeLocation":    userInfo.OfficeLocation,
			"preferredLanguage": userInfo.PreferredLanguage,
		},
	}

	return user, nil
}
