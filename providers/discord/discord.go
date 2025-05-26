package discord

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
	discordAuthURL     = "https://discord.com/api/oauth2/authorize"
	discordTokenURL    = "https://discord.com/api/oauth2/token"
	discordUserInfoURL = "https://discord.com/api/users/@me"
)

// Provider implements the gonnect.Provider interface for Discord OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by Discord's API
type UserInfo struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	Locale        string `json:"locale"`
	GlobalName    string `json:"global_name"`
}

// TokenResponse represents the OAuth2 token response from Discord
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// New creates a new Discord provider instance
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"identify", "email"}
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
	return "discord"
}

// BeginAuth initiates the OAuth2 flow by returning the authorization URL
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
	}

	authURLWithParams := discordAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow using the authorization code
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	discordToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	discordUserInfo, err := p.fetchUserInfo(ctx, discordToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(discordUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal discord user info: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal discord user info to map: "+err.Error())
	}

	avatarURL := ""
	if discordUserInfo.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", discordUserInfo.ID, discordUserInfo.Avatar)
	}

	user = coretypes.User{
		ID:        discordUserInfo.ID,
		Email:     discordUserInfo.Email,
		Name:      discordUserInfo.GlobalName, // Use GlobalName if available
		Username:  discordUserInfo.Username,
		AvatarURL: avatarURL,
		Locale:    discordUserInfo.Locale,
		RawData:   rawData,
	}
	if user.Name == "" { // Fallback to Username if GlobalName is empty
		user.Name = discordUserInfo.Username
	}

	token = coretypes.Token{
		AccessToken:  discordToken.AccessToken,
		RefreshToken: discordToken.RefreshToken,
		TokenType:    discordToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(discordToken.ExpiresIn)),
		Scope:        discordToken.Scope,
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

	// Discord uses multipart/form-data for refresh token request if client_secret is used.
	// However, standard OAuth libraries often manage this with x-www-form-urlencoded.
	// Let's stick to x-www-form-urlencoded first as it's more common for client libraries.
	// If Discord strictly requires multipart/form-data for refresh with client_secret, this will need adjustment.

	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret) // Required for confidential clients
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discordTokenURL, strings.NewReader(data.Encode()))
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
		RefreshToken: refreshedTokenResp.RefreshToken, // Discord should return a new refresh token
		TokenType:    refreshedTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
		Scope:        refreshedTokenResp.Scope,
	}

	// If Discord doesn't return a new refresh token (it should), persist the old one.
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

	discordUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		// This could be due to an invalid/expired token or other issues.
		return coretypes.User{}, false, err // Pass along the specific error from fetchUserInfo
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(discordUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal discord user info for validation: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal discord user info to map for validation: "+err.Error())
	}

	avatarURL := ""
	if discordUserInfo.Avatar != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", discordUserInfo.ID, discordUserInfo.Avatar)
	}

	user := coretypes.User{
		ID:        discordUserInfo.ID,
		Email:     discordUserInfo.Email,
		Name:      discordUserInfo.GlobalName,
		Username:  discordUserInfo.Username,
		AvatarURL: avatarURL,
		Locale:    discordUserInfo.Locale,
		RawData:   rawData,
	}
	if user.Name == "" {
		user.Name = discordUserInfo.Username
	}

	return user, true, nil
}

// SupportsRefresh indicates that Discord supports token refresh
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
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.redirectURL)
	// data.Set("scope", strings.Join(p.scopes, " ")) // Not typically sent in token exchange for Discord

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discordTokenURL, strings.NewReader(data.Encode()))
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

// fetchUserInfo retrieves user information from Discord's API
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discordUserInfoURL, nil)
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
