package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/megascan/gonnect/internal/coretypes"
)

const (
	githubAuthURL     = "https://github.com/login/oauth/authorize"
	githubTokenURL    = "https://github.com/login/oauth/access_token"
	githubUserInfoURL = "https://api.github.com/user"
	githubEmailURL    = "https://api.github.com/user/emails"
)

// Provider implements the gonnect.Provider interface for GitHub OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by GitHub's API
type UserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Location  string `json:"location"`
	Company   string `json:"company"`
	Blog      string `json:"blog"`
}

// EmailInfo represents email information from GitHub's API
type EmailInfo struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// TokenResponse represents the OAuth2 token response from GitHub
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ExpiresIn        int64  `json:"expires_in,omitempty"` // In seconds
	Scope            string `json:"scope,omitempty"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error,omitempty"`             // e.g., "bad_verification_code"
	ErrorDescription string `json:"error_description,omitempty"` // e.g., "The code passed is incorrect or expired."
	ErrorURI         string `json:"error_uri,omitempty"`         // e.g., "https://docs.github.com/apps/managing-oauth-apps/troubleshooting-oauth-app-access-token-request-errors/#bad-verification-code"
}

// New creates a new GitHub provider instance
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"user:email"} // Basic scope to read user email
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
	return "github"
}

// BeginAuth initiates the OAuth2 flow by returning the authorization URL
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
		"response_type": {"code"},
	}

	authURLWithParams := githubAuthURL + "?" + params.Encode()
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

	githubToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	githubUserInfo, err := p.fetchUserInfo(ctx, githubToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	// If email is not in main user info, try fetching from /user/emails
	if githubUserInfo.Email == "" {
		emails, err := p.fetchUserEmails(ctx, githubToken.AccessToken)
		if err == nil { // Proceed even if email fetching fails, primary info is more important
			for _, emailInfo := range emails {
				if emailInfo.Primary && emailInfo.Verified {
					githubUserInfo.Email = emailInfo.Email
					break
				}
			}
			// Fallback to the first verified email if no primary found
			if githubUserInfo.Email == "" {
				for _, emailInfo := range emails {
					if emailInfo.Verified {
						githubUserInfo.Email = emailInfo.Email
						break
					}
				}
			}
		} else {
			// Log this error, but don't fail the whole auth if email is the only missing piece from secondary call
			// Consider how your application wants to handle users without a verified primary email.
			// For now, we proceed without email if this call fails.
			// TODO: Use a logger from context or Gonnect instance if available.
			fmt.Printf("Gonnect (%s): failed to fetch user emails: %v\n", p.Name(), err)
		}
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(githubUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal github user info: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal github user info to map: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user = coretypes.User{
		ID:        fmt.Sprintf("%d", githubUserInfo.ID), // GitHub ID is int, convert to string
		Email:     githubUserInfo.Email,
		Name:      githubUserInfo.Name,
		Username:  githubUserInfo.Login,
		AvatarURL: githubUserInfo.AvatarURL,
		RawData:   rawData,
	}
	if user.Name == "" { // Fallback if Name field is empty
		user.Name = githubUserInfo.Login
	}

	token = coretypes.Token{
		AccessToken:  githubToken.AccessToken,
		RefreshToken: githubToken.RefreshToken,
		TokenType:    githubToken.TokenType,
		Scope:        githubToken.Scope,
	}
	if githubToken.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Second * time.Duration(githubToken.ExpiresIn))
	}

	return user, token, nil
}

// RefreshToken - GitHub doesn't support refresh tokens in the traditional sense
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	var newGonnectToken coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	if refreshToken == "" {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "refresh token is empty")
	}

	payload := url.Values{}
	payload.Set("client_id", p.clientID)
	payload.Set("client_secret", p.clientSecret)
	payload.Set("grant_type", "refresh_token")
	payload.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(payload.Encode()))
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
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var refreshedTokenResp TokenResponse
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error()) // Was ErrTypeJSONParsing
	}

	if refreshedTokenResp.Error != "" {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("GitHub token refresh error: %s - %s", refreshedTokenResp.Error, refreshedTokenResp.ErrorDescription))
	}

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshedTokenResp.RefreshToken, // GitHub should return a new refresh token
		TokenType:    refreshedTokenResp.TokenType,
		Scope:        refreshedTokenResp.Scope,
	}
	if refreshedTokenResp.ExpiresIn > 0 {
		newGonnectToken.Expiry = time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn))
	}

	// If GitHub doesn't return a new refresh token (it should, but good to be safe or if policy changes)
	if newGonnectToken.RefreshToken == "" {
		newGonnectToken.RefreshToken = refreshToken
	}

	return newGonnectToken, nil
}

// ValidateToken validates a token and returns user info
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty")
	}

	// To validate, we fetch user info. If successful, token is considered valid.
	githubUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, err // err from fetchUserInfo already a GonnectError or network error
	}

	// If email is not in main user info, try fetching from /user/emails
	if githubUserInfo.Email == "" {
		emails, emailErr := p.fetchUserEmails(ctx, token.AccessToken)
		if emailErr == nil {
			for _, emailInfo := range emails {
				if emailInfo.Primary && emailInfo.Verified {
					githubUserInfo.Email = emailInfo.Email
					break
				}
			}
			if githubUserInfo.Email == "" {
				for _, emailInfo := range emails {
					if emailInfo.Verified {
						githubUserInfo.Email = emailInfo.Email
						break
					}
				}
			}
		} // else, proceed without email if this secondary call fails
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(githubUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal github user info for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal github user info to map for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user := coretypes.User{
		ID:        fmt.Sprintf("%d", githubUserInfo.ID),
		Email:     githubUserInfo.Email,
		Name:      githubUserInfo.Name,
		Username:  githubUserInfo.Login,
		AvatarURL: githubUserInfo.AvatarURL,
		RawData:   rawData,
	}
	if user.Name == "" {
		user.Name = githubUserInfo.Login
	}

	return user, true, nil
}

// SupportsRefresh indicates that GitHub does not support token refresh
func (p *Provider) SupportsRefresh() bool {
	return false
}

// exchangeCodeForToken exchanges an authorization code for access token
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	payload := url.Values{}
	payload.Set("client_id", p.clientID)
	payload.Set("client_secret", p.clientSecret)
	payload.Set("code", code)
	payload.Set("redirect_uri", p.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json") // Important: Ask for JSON response

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
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse token response: "+err.Error()) // Was ErrTypeJSONParsing
	}

	// Check for error in response body, GitHub sometimes returns 200 OK with error in JSON
	if tokenResponse.Error != "" {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token: %s - %s", tokenResponse.Error, tokenResponse.ErrorDescription))
	}

	return tokenResponse, nil
}

// fetchUserInfo retrieves user information from GitHub's API
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

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

// fetchUserEmails retrieves the user's emails from GitHub's emails API
func (p *Provider) fetchUserEmails(ctx context.Context, accessToken string) ([]EmailInfo, error) {
	var emails []EmailInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailURL, nil)
	if err != nil {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user emails request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to fetch user emails: "+err.Error()) // Was ErrTypeNetworkIO
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read user emails response body: "+err.Error()) // Was ErrTypeNetworkIO
	}

	if resp.StatusCode != http.StatusOK {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get user emails, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse user emails: "+err.Error()) // Was ErrTypeJSONParsing
	}
	return emails, nil
}
