package amazon

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
	amazonAuthURL     = "https://www.amazon.com/ap/oa"
	amazonTokenURL    = "https://api.amazon.com/auth/o2/token"
	amazonUserInfoURL = "https://api.amazon.com/user/profile"
)

// Provider implements the gonnect.Provider interface for Amazon OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by Amazon's API.
// Fields depend on the scopes requested (e.g., "profile", "profile:user_id", "postal_code").
type UserInfo struct {
	UserID     string `json:"user_id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	PostalCode string `json:"postal_code,omitempty"` // Requires postal_code scope
}

// TokenResponse represents the OAuth2 token response from Amazon
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // In seconds
}

// New creates a new Amazon provider instance
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"profile", "profile:user_id"} // profile:user_id for the user_id field
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
	return "amazon"
}

// BeginAuth initiates the OAuth2 flow
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"scope":         {strings.Join(p.scopes, " ")}, // Space-separated scopes
		"response_type": {"code"},
		"redirect_uri":  {p.redirectURL},
		"state":         {state},
	}
	authURLWithParams := amazonAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	var user coretypes.User
	var token coretypes.Token

	code := r.URL.Query().Get("code")
	_ = r.URL.Query().Get("state") // State validated by Gonnect core

	if code == "" {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeAuthentication, "authorization code not found in callback")
	}

	amazonToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	amazonUserInfo, err := p.fetchUserInfo(ctx, amazonToken.AccessToken)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(amazonUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal amazon user info: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal amazon user info to map: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user = coretypes.User{
		ID:       amazonUserInfo.UserID,
		Email:    amazonUserInfo.Email,
		Name:     amazonUserInfo.Name,
		Username: amazonUserInfo.Name, // Amazon doesn't have a distinct username, use Name
		RawData:  rawData,
		// AvatarURL can be constructed if needed, or if a field provides it directly
	}

	token = coretypes.Token{
		AccessToken:  amazonToken.AccessToken,
		RefreshToken: amazonToken.RefreshToken,
		TokenType:    amazonToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(amazonToken.ExpiresIn)),
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

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("refresh_token", refreshToken)
	v.Set("grant_type", "refresh_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, amazonTokenURL, strings.NewReader(v.Encode()))
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

	newGonnectToken = coretypes.Token{
		AccessToken:  refreshedTokenResp.AccessToken,
		RefreshToken: refreshedTokenResp.RefreshToken, // Amazon should return a new refresh token
		TokenType:    refreshedTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	if newGonnectToken.RefreshToken == "" {
		newGonnectToken.RefreshToken = refreshToken // Fallback if not returned
	}

	return newGonnectToken, nil
}

// ValidateToken attempts to fetch user info to validate the token.
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty")
	}

	amazonUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		// This could be due to an invalid/expired token or other issues.
		return coretypes.User{}, false, err // Pass along the specific error from fetchUserInfo
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(amazonUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal amazon user info for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal amazon user info to map for validation: "+err.Error()) // Was ErrTypeJSONParsing
	}

	user := coretypes.User{
		ID:       amazonUserInfo.UserID,
		Email:    amazonUserInfo.Email,
		Name:     amazonUserInfo.Name,
		Username: amazonUserInfo.Name,
		RawData:  rawData,
	}
	return user, true, nil
}

// SupportsRefresh indicates if the provider supports token refresh.
func (p *Provider) SupportsRefresh() bool {
	return true // Amazon supports refresh tokens
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("code", code)
	v.Set("grant_type", "authorization_code")
	v.Set("redirect_uri", p.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, amazonTokenURL, strings.NewReader(v.Encode()))
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
		// Attempt to parse error response from Amazon
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

// fetchUserInfo retrieves user information from Amazon's API.
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, amazonUserInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error()) // Was ErrTypeNetworkIO
	}
	// Amazon expects the token in the Authorization header as "Bearer <token>"
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
