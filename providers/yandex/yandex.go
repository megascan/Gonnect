package yandex

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
	yandexAuthURL     = "https://oauth.yandex.ru/authorize"
	yandexTokenURL    = "https://oauth.yandex.ru/token"
	yandexUserInfoURL = "https://login.yandex.ru/info" // ?format=json is typically needed
)

// Provider implements the coretypes.Provider interface for Yandex OAuth2.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by Yandex's API.
// https://yandex.com/dev/passport/doc/dg/reference/response.html (structure may vary slightly)
// Common fields based on next-auth and typical Yandex responses:
type UserInfo struct {
	ID              string   `json:"id"`
	Login           string   `json:"login"`
	ClientID        string   `json:"client_id"`
	DefaultEmail    string   `json:"default_email"`
	Emails          []string `json:"emails,omitempty"`
	DefaultAvatarID string   `json:"default_avatar_id,omitempty"` // To construct avatar URL
	RealName        string   `json:"real_name,omitempty"`
	FirstName       string   `json:"first_name,omitempty"`
	LastName        string   `json:"last_name,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
	Sex             string   `json:"sex,omitempty"`
	Birthday        string   `json:"birthday,omitempty"` // Format YYYY-MM-DD or empty
	OldSocialLogin  string   `json:"old_social_login,omitempty"`
	IsAvatarEmpty   bool     `json:"is_avatar_empty,omitempty"`
}

// TokenResponse is the OAuth2 token response from Yandex.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"` // May not always be present
	Scope        string `json:"scope,omitempty"`         // Scopes granted
}

// New creates a new Yandex provider instance.
// Default scopes are "login:info", "login:email".
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"login:info", "login:email"} // Basic info and email
	}
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

func (p *Provider) Name() string {
	return "yandex"
}

func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("redirect_uri", p.redirectURL)
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(p.scopes, " "))
	v.Set("state", state)
	// Yandex also supports `force_confirm=yes` to always show consent screen
	return yandexAuthURL + "?" + v.Encode(), nil
}

func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	yandexToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	yandexUserInfo, err := p.fetchUserInfo(ctx, yandexToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(yandexUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal yandex user info: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal yandex user info to map: "+err.Error())
	}

	userName := yandexUserInfo.RealName
	if userName == "" {
		userName = yandexUserInfo.DisplayName
	}
	if userName == "" {
		userName = yandexUserInfo.Login
	}

	avatarURL := ""
	if yandexUserInfo.DefaultAvatarID != "" && !yandexUserInfo.IsAvatarEmpty {
		avatarURL = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", yandexUserInfo.DefaultAvatarID)
	}

	user = coretypes.User{
		ID:        yandexUserInfo.ID,
		Email:     yandexUserInfo.DefaultEmail,
		Name:      userName,
		Username:  yandexUserInfo.Login,
		AvatarURL: avatarURL,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  yandexToken.AccessToken,
		RefreshToken: yandexToken.RefreshToken,
		TokenType:    yandexToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(yandexToken.ExpiresIn)),
	}

	return user, token, nil
}

func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", yandexTokenURL, strings.NewReader(v.Encode()))
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

	// UserInfo endpoint for Yandex typically requires ?format=json
	userInfoURL := yandexUserInfoURL + "?format=json"

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error())
	}
	req.Header.Set("Authorization", "OAuth "+accessToken) // Yandex uses "OAuth <token>"

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
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse user info response: "+err.Error())
	}

	return userInfo, nil
}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	var token coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	if refreshToken == "" {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "refresh token is empty")
	}

	v := url.Values{}
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", yandexTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to refresh token: "+err.Error())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to read refresh token response body: "+err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error())
	}

	token = coretypes.Token{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		TokenType:    tokenResponse.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn)),
	}

	// If Yandex doesn't return a new refresh token, persist the old one
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}

	return token, nil
}

func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty")
	}

	// Check if token is expired
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) {
		return coretypes.User{}, false, nil // Token expired
	}

	// Attempt to fetch user info to validate the token
	userInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, nil // Token is likely invalid
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(userInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal user info for validation: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal user info to map for validation: "+err.Error())
	}

	userName := userInfo.RealName
	if userName == "" {
		userName = userInfo.DisplayName
	}
	if userName == "" {
		userName = userInfo.Login
	}

	avatarURL := ""
	if userInfo.DefaultAvatarID != "" && !userInfo.IsAvatarEmpty {
		avatarURL = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", userInfo.DefaultAvatarID)
	}

	user := coretypes.User{
		ID:        userInfo.ID,
		Email:     userInfo.DefaultEmail,
		Name:      userName,
		Username:  userInfo.Login,
		AvatarURL: avatarURL,
		RawData:   rawData,
	}

	return user, true, nil
}

func (p *Provider) SupportsRefresh() bool {
	return true
}
