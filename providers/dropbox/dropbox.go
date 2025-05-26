package dropbox

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
	dropboxAuthURLBase = "https://www.dropbox.com/oauth2/authorize"
	dropboxTokenURL    = "https://api.dropbox.com/oauth2/token"
	dropboxUserInfoURL = "https://api.dropboxapi.com/2/users/get_current_account"
)

// Provider implements the gonnect.Provider interface for Dropbox OAuth2.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string // Scopes for Dropbox, e.g., "account_info.read"
	// pkce bool // To indicate if PKCE should be used (for clients that can't keep secret)
	// codeVerifier string // Store if PKCE is used
}

// UserInfo represents the user information returned by Dropbox's API.
// https://www.dropbox.com/developers/documentation/http/documentation#users-get_current_account
type UserInfo struct {
	AccountID       string `json:"account_id"`
	Name            Name   `json:"name"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	ProfilePhotoURL string `json:"profile_photo_url,omitempty"`
	Disabled        bool   `json:"disabled"`
	Country         string `json:"country,omitempty"`
	Locale          string `json:"locale"`
	ReferralLink    string `json:"referral_link"`
	IsPaired        bool   `json:"is_paired"`
	AccountType     struct {
		Tag string `json:".tag"`
	} `json:"account_type"`
	RootInfo struct {
		Tag             string `json:".tag"`
		RootNamespaceID string `json:"root_namespace_id"`
		HomeNamespaceID string `json:"home_namespace_id"`
	} `json:"root_info"`
}

// Name is a sub-struct for UserInfo
type Name struct {
	GivenName       string `json:"given_name"`
	Surname         string `json:"surname"`
	FamiliarName    string `json:"familiar_name"`
	DisplayName     string `json:"display_name"`
	AbbreviatedName string `json:"abbreviated_name"`
}

// TokenResponse is the OAuth2 token response from Dropbox.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`              // Should be "bearer"
	ExpiresIn    int64  `json:"expires_in"`              // Short-lived access token duration
	RefreshToken string `json:"refresh_token,omitempty"` // Present if token_access_type=offline was used
	Scope        string `json:"scope,omitempty"`         // Granted scopes
	UID          string `json:"uid"`                     // User ID (deprecated, use account_id from userinfo)
	AccountID    string `json:"account_id,omitempty"`    // User ID
}

// New creates a new Dropbox provider instance.
// Default scope is "account_info.read".
// Requests offline access by default to get a refresh token.
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"account_info.read"} // Essential for get_current_account
	}
	return &Provider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       scopes,
	}
}

func (p *Provider) Name() string {
	return "dropbox"
}

func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("redirect_uri", p.redirectURL)
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(p.scopes, " "))
	v.Set("state", state)
	v.Set("token_access_type", "offline") // Request a refresh token

	// PKCE parameters would be added here if used:
	// v.Set("code_challenge", p.codeChallenge)
	// v.Set("code_challenge_method", "S256")

	return dropboxAuthURLBase + "?" + v.Encode(), nil
}

func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	dropboxToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	dropboxUserInfo, err := p.fetchUserInfo(ctx, dropboxToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(dropboxUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal dropbox user info: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal dropbox user info to map: "+err.Error())
	}

	user = coretypes.User{
		ID:        dropboxUserInfo.AccountID,
		Email:     dropboxUserInfo.Email,
		Name:      dropboxUserInfo.Name.DisplayName,
		Username:  dropboxUserInfo.Email, // Dropbox doesn't have a distinct username like some services
		AvatarURL: dropboxUserInfo.ProfilePhotoURL,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  dropboxToken.AccessToken,
		RefreshToken: dropboxToken.RefreshToken,
		TokenType:    dropboxToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(dropboxToken.ExpiresIn)),
	}

	return user, token, nil
}

func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	v.Set("redirect_uri", p.redirectURL) // Required if set in auth request
	// For standard code flow (not PKCE), client_id and client_secret are sent via Basic Auth

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dropboxTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)
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

	// Dropbox user info endpoint doesn't take query params, it's a POST request with nil body
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dropboxUserInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	// Dropbox API can sometimes expect Content-Type for POST even with no body, though often not strictly necessary
	// req.Header.Set("Content-Type", "application/json")

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
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
	// For refresh, client_id and client_secret are sent via Basic Auth

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dropboxTokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh token request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.clientID, p.clientSecret)
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

	// Dropbox refresh response only contains new access_token and expires_in
	var refreshedTokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error())
	}

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshToken, // Dropbox does not return a new refresh token, so reuse the old one
		TokenType:    refreshedTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	return newGonnectToken, nil
}

func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty")
	}

	dropboxUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(dropboxUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal dropbox user info for validation: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal dropbox user info to map for validation: "+err.Error())
	}

	user := coretypes.User{
		ID:        dropboxUserInfo.AccountID,
		Email:     dropboxUserInfo.Email,
		Name:      dropboxUserInfo.Name.DisplayName,
		Username:  dropboxUserInfo.Email,
		AvatarURL: dropboxUserInfo.ProfilePhotoURL,
		RawData:   rawData,
	}
	return user, true, nil
}

func (p *Provider) SupportsRefresh() bool {
	return true
}
