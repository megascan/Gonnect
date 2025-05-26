package facebook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	facebookAuthURL     = "https://www.facebook.com/v12.0/dialog/oauth"
	facebookTokenURL    = "https://graph.facebook.com/v12.0/oauth/access_token"
	facebookUserInfoURL = "https://graph.facebook.com/me"
)

// Provider implements the gonnect.Provider interface for Facebook OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents basic user information from Facebook.
// The fields you get depend on the scopes requested and user permissions.
type UserInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email,omitempty"` // Email is not guaranteed, requires 'email' scope and user permission
	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// TokenResponse represents the OAuth2 token response from Facebook
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // Typically in seconds
	RefreshToken string `json:"refresh_token,omitempty"`
}

// FacebookErrorDetail represents the error details from Facebook API
type FacebookErrorDetail struct {
	Message      string `json:"message"`
	Type         string `json:"type"`
	Code         int    `json:"code"`
	ErrorSubcode int    `json:"error_subcode,omitempty"`
	FBTraceID    string `json:"fbtrace_id,omitempty"`
}

// FacebookErrorResponse represents the error structure from Facebook API
type FacebookErrorResponse struct {
	Error FacebookErrorDetail `json:"error"`
}

// New creates a new Facebook provider instance
func New(clientID, clientSecret, redirectURL string, scopes []string) coretypes.Provider {
	if len(scopes) == 0 {
		scopes = []string{"email", "public_profile"}
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
	return "facebook"
}

// BeginAuth initiates the OAuth2 flow
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"scope":         {strings.Join(p.scopes, ",")}, // Facebook uses comma-separated scopes
		"response_type": {"code"},
		"state":         {state},
	}
	authURLWithParams := facebookAuthURL + "?" + params.Encode()
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

	facebookToken, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return user, token, err
	}

	appSecretProof := generateAppSecretProof(facebookToken.AccessToken, p.clientSecret)
	facebookUserInfo, err := p.fetchUserInfo(ctx, facebookToken.AccessToken, appSecretProof)
	if err != nil {
		return user, token, err
	}

	var rawData map[string]interface{}
	// Marshal the original UserInfo struct first
	jsonBytes, err := json.Marshal(facebookUserInfo)
	if err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal facebook user info: "+err.Error())
	}
	// Then unmarshal it into the map for RawData
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return user, token, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal facebook user info to map: "+err.Error())
	}
	// Ensure "picture" which might be a struct is correctly represented or simplified
	if picData, ok := rawData["picture"].(map[string]interface{}); ok {
		if picURL, ok := picData["data"].(map[string]interface{})["url"].(string); ok {
			rawData["picture_url"] = picURL // Add a simplified picture_url
		}
	}

	user = coretypes.User{
		ID:        facebookUserInfo.ID,
		Email:     facebookUserInfo.Email,
		Name:      facebookUserInfo.Name,
		Username:  facebookUserInfo.ID, // Facebook doesn't have a distinct username, use ID or name
		AvatarURL: facebookUserInfo.Picture.Data.URL,
		RawData:   rawData,
	}

	token = coretypes.Token{
		AccessToken:  facebookToken.AccessToken,
		RefreshToken: facebookToken.RefreshToken, // Facebook might not always return this
		TokenType:    facebookToken.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(facebookToken.ExpiresIn)),
	}

	return user, token, nil
}

// RefreshToken attempts to refresh an access token.
// Facebook's long-lived tokens usually don't need explicit refresh via this endpoint if handled correctly,
// but it can be used to extend expiration or if a short-lived token was somehow obtained by server.
func (p *Provider) RefreshToken(ctx context.Context, accessTokenToRefresh string) (coretypes.Token, error) {
	var newGonnectToken coretypes.Token
	httpClient := &http.Client{Timeout: 10 * time.Second}

	if accessTokenToRefresh == "" { // Facebook refers to this as refreshing a short-lived token
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access_token to refresh is empty (for Facebook, this is usually an existing short-lived token)")
	}

	v := url.Values{}
	v.Set("grant_type", "fb_exchange_token")
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("fb_exchange_token", accessTokenToRefresh)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, facebookTokenURL, nil)
	if err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create refresh token request: "+err.Error())
	}
	req.URL.RawQuery = v.Encode()
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
		var errResp FacebookErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, fmt.Sprintf("failed to refresh Facebook token: %s", errResp.Error.Message))
		}
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to refresh token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	var refreshedTokenResp TokenResponse // Facebook refresh returns a new access_token and its expiry.
	if err := json.Unmarshal(body, &refreshedTokenResp); err != nil {
		return newGonnectToken, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse refreshed token response: "+err.Error())
	}

	newGonnectToken = coretypes.Token{
		AccessToken: refreshedTokenResp.AccessToken,
		// Facebook's fb_exchange_token grant does NOT return a refresh_token.
		// The new access_token is typically long-lived (e.g., 60 days).
		// If you had an original refresh token from a web flow (not common for server), you might persist it.
		RefreshToken: "", // Explicitly empty as fb_exchange_token doesn't provide one.
		TokenType:    refreshedTokenResp.TokenType,
		Expiry:       time.Now().Add(time.Second * time.Duration(refreshedTokenResp.ExpiresIn)),
	}

	return newGonnectToken, nil
}

func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeToken, "access token is empty")
	}

	// To validate a Facebook token, we can make a call to the debug_token endpoint or fetch user info.
	// Fetching user info implicitly validates the token if successful.
	appSecretProof := generateAppSecretProof(token.AccessToken, p.clientSecret)
	facebookUserInfo, err := p.fetchUserInfo(ctx, token.AccessToken, appSecretProof)
	if err != nil {
		return coretypes.User{}, false, err // Error from fetchUserInfo can indicate invalid token
	}

	var rawData map[string]interface{}
	jsonBytes, err := json.Marshal(facebookUserInfo)
	if err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to marshal facebook user info for validation: "+err.Error())
	}
	if err := json.Unmarshal(jsonBytes, &rawData); err != nil {
		return coretypes.User{}, false, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to unmarshal facebook user info to map for validation: "+err.Error())
	}
	if picData, ok := rawData["picture"].(map[string]interface{}); ok {
		if picURL, ok := picData["data"].(map[string]interface{})["url"].(string); ok {
			rawData["picture_url"] = picURL
		}
	}

	user := coretypes.User{
		ID:        facebookUserInfo.ID,
		Email:     facebookUserInfo.Email,
		Name:      facebookUserInfo.Name,
		Username:  facebookUserInfo.ID,
		AvatarURL: facebookUserInfo.Picture.Data.URL,
		RawData:   rawData,
	}
	return user, true, nil
}

// SupportsRefresh indicates if the provider supports standard token refresh.
// Facebook has a different mechanism for extending token lifetimes.
func (p *Provider) SupportsRefresh() bool {
	return false // Standard refresh_token grant is not the typical way.
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (TokenResponse, error) {
	var tokenResponse TokenResponse
	httpClient := &http.Client{Timeout: 10 * time.Second}

	v := url.Values{}
	v.Set("client_id", p.clientID)
	v.Set("client_secret", p.clientSecret)
	v.Set("code", code)
	v.Set("redirect_uri", p.redirectURL) // Must match the one used in BeginAuth

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, facebookTokenURL, nil) // GET request
	if err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create token request: "+err.Error())
	}
	req.URL.RawQuery = v.Encode()
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
		var errResp FacebookErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token from Facebook: %s (type: %s, code: %d)", errResp.Error.Message, errResp.Error.Type, errResp.Error.Code))
		}
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get token, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return tokenResponse, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse token response: "+err.Error())
	}

	return tokenResponse, nil
}

// fetchUserInfo retrieves user information from Facebook's Graph API.
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken, appSecretProof string) (UserInfo, error) {
	var userInfo UserInfo
	httpClient := &http.Client{Timeout: 10 * time.Second}

	fbUserInfoURL := facebookUserInfoURL
	// Define fields to fetch. Picture URL is fetched as a sub-field.
	fields := "id,name,email,picture.type(large)" // Add more fields if needed, e.g., first_name,last_name

	v := url.Values{}
	v.Set("fields", fields)
	v.Set("access_token", accessToken)
	v.Set("appsecret_proof", appSecretProof) // Required for server-side calls

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fbUserInfoURL, nil)
	if err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to create user info request: "+err.Error())
	}
	req.URL.RawQuery = v.Encode()
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
		var errResp FacebookErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
			return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get user info from Facebook: %s (type: %s, code: %d)", errResp.Error.Message, errResp.Error.Type, errResp.Error.Code))
		}
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, fmt.Sprintf("failed to get user info, status: %d, body: %s", resp.StatusCode, string(body)))
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return userInfo, coretypes.NewProviderError(p.Name(), coretypes.ErrTypeProvider, "failed to parse user info: "+err.Error())
	}

	return userInfo, nil
}

func generateAppSecretProof(accessToken, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(accessToken))
	return hex.EncodeToString(mac.Sum(nil))
}
