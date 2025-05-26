package gitlab

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
	// Default GitLab instance URL. Can be overridden if using a self-managed instance.
	gitlabDefaultBaseURL = "https://gitlab.com"
	gitlabAuthPath       = "/oauth/authorize"
	gitlabTokenPath      = "/oauth/token"
	gitlabUserInfoPath   = "/oauth/userinfo" // Standard OIDC UserInfo endpoint
)

// Provider implements the gonnect.Provider interface for GitLab OAuth2 (OIDC).
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	instanceURL  string // Base URL of the GitLab instance
}

type UserInfo struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name,omitempty"`
	Nickname          string   `json:"nickname,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Picture           string   `json:"picture,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Profile           string   `json:"profile,omitempty"`
	Website           string   `json:"website,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

// TokenResponse is the OAuth2 token response from GitLab.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`   // OIDC ID Token
	CreatedAt    int64  `json:"created_at,omitempty"` // Unix timestamp of token creation
}

// New creates a new GitLab provider instance.
// For self-managed GitLab, provide the instanceURL (e.g., "https://gitlab.example.com").
// If instanceURL is empty or not provided, it defaults to "https://gitlab.com".
func New(clientID, clientSecret, redirectURL string, scopes []string, instanceURL ...string) coretypes.Provider {
	currentInstanceURL := gitlabDefaultBaseURL
	if len(instanceURL) > 0 && instanceURL[0] != "" {
		currentInstanceURL = strings.TrimRight(instanceURL[0], "/")
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"} // Standard OIDC scopes
	}
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
		instanceURL:  currentInstanceURL,
	}
}

// Helper methods to construct URLs based on instanceURL
func (p *Provider) authURL() string {
	return p.instanceURL + gitlabAuthPath
}

func (p *Provider) tokenURL() string {
	return p.instanceURL + gitlabTokenPath
}

func (p *Provider) userInfoURL() string {
	return p.instanceURL + gitlabUserInfoPath
}

func (p *Provider) Name() string {
	return "gitlab"
}

func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, " ")}, // GitLab uses space-separated scopes for OIDC
		"response_type": {"code"},
		"state":         {state},
	}
	authURLWithParams := p.authURL() + "?" + params.Encode()
	return authURLWithParams, nil
}

func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	gitlabToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	gitlabUserInfo, err := p.fetchUserInfo(ctx, gitlabToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(gitlabUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal gitlab user info: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal gitlab user info to map: "+err.Error())
	}

	user = coretypes.User{
		ID:        gitlabUserInfo.Sub, // Subject identifier, standard OIDC claim
		Email:     gitlabUserInfo.Email,
		Name:      gitlabUserInfo.Name,
		Username:  gitlabUserInfo.PreferredUsername,
		AvatarURL: gitlabUserInfo.Picture,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  gitlabToken.AccessToken,
		RefreshToken: gitlabToken.RefreshToken,
		TokenType:    gitlabToken.TokenType,
		IDToken:      gitlabToken.IDToken, // GitLab provides ID token
		Scope:        gitlabToken.Scope,
		Expiry:       time.Now().Add(time.Second * time.Duration(gitlabToken.ExpiresIn)),
	}

	return user, token, nil
}

func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("code", code)
	v.Set("grant_type", "authorization_code")
	v.Set("redirect_uri", p.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL(), strings.NewReader(v.Encode()))
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
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse token response: "+err.Error())
	}

	return tokenResponse, nil
}

func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL(), nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to fetch user info: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read user info response body: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get user info, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse user info: "+err.Error())
	}

	return userInfo, nil
}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	var newGonnectToken coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	if refreshToken == "" {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "refresh token is empty")
	}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("refresh_token", refreshToken)
	v.Set("grant_type", "refresh_token")
	v.Set("redirect_uri", p.redirectURL) // GitLab requires redirect_uri for refresh token grant

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL(), strings.NewReader(v.Encode()))
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
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var refreshedTokenResp TokenResponse
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error())
	}

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshedTokenResp.RefreshToken, // GitLab should return a new refresh token
		TokenType:    refreshedTokenResp.TokenType,
		IDToken:      refreshedTokenResp.IDToken, // And potentially a new ID token
		Scope:        refreshedTokenResp.Scope,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	if newGonnectToken.RefreshToken == "" {
		newGonnectToken.RefreshToken = refreshToken // Fallback if not returned (though it should be)
	}

	return newGonnectToken, nil
}

func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty for validation")
	}

	// For OIDC providers like GitLab, validating the ID token is preferred if available and not expired.
	// However, a simpler validation is to fetch user info with the access token.
	// Proper ID token validation would involve checking signature against JWKS, issuer, audience, nonce, expiry.

	gitlabUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, err // Error from fetchUserInfo indicates an issue (e.g. invalid token)
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(gitlabUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal gitlab user info for validation: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal gitlab user info to map for validation: "+err.Error())
	}

	user := coretypes.User{
		ID:        gitlabUserInfo.Sub,
		Email:     gitlabUserInfo.Email,
		Name:      gitlabUserInfo.Name,
		Username:  gitlabUserInfo.PreferredUsername,
		AvatarURL: gitlabUserInfo.Picture,
		RawData:   rawData,
	}
	return user, true, nil
}

func (p *Provider) SupportsRefresh() bool {
	return true
}
