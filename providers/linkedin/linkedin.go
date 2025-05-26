package linkedin

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
	linkedinAuthURL     = "https://www.linkedin.com/oauth/v2/authorization"
	linkedinTokenURL    = "https://www.linkedin.com/oauth/v2/accessToken"
	linkedinUserInfoURL = "https://api.linkedin.com/v2/me" // Basic profile
	linkedinEmailURL    = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))"
)

// Provider implements the coretypes.Provider interface for LinkedIn OAuth2
type Provider struct {
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
}

// UserInfo represents the user information returned by LinkedIn's API.
// Fields depend on the scopes (e.g., r_liteprofile, r_emailaddress).
type UserInfo struct {
	ID                 string `json:"id"`
	LocalizedFirstName string `json:"localizedFirstName"`
	LocalizedLastName  string `json:"localizedLastName"`
	ProfilePicture     struct {
		DisplayImage string `json:"displayImage"` // This might require specific projection
	} `json:"profilePicture,omitempty"`
	// Email will be fetched separately
}

// EmailAddress represents the email information from LinkedIn's emailAddress API
type EmailAddress struct {
	Elements []struct {
		Handle      string `json:"handle"`
		HandleTilde struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"handle~"`
	} `json:"elements"`
}

// TokenResponse represents the OAuth2 token response from LinkedIn
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // In seconds
	// LinkedIn doesn't typically return a refresh token in the standard OAuth2 sense for this flow.
	// Refreshing is often tied to the duration of the access token itself (e.g., long-lived tokens).
}

// New creates a new LinkedIn provider instance
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
	return "linkedin"
}

// BeginAuth initiates the OAuth2 flow
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURL},
		"state":         {state},
		"scope":         {strings.Join(p.scopes, " ")}, // Space-separated scopes
	}
	authURLWithParams := linkedinAuthURL + "?" + params.Encode()
	return authURLWithParams, nil
}

// CompleteAuth completes the OAuth2 flow
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return coretypes.User{}, coretypes.Token{}, coretypes.NewProviderError("linkedin", coretypes.ErrTypeAuthentication, "authorization code not found")
	}

	token, err := p.exchangeCodeForToken(ctx, code)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, err // Error is already provider-specific
	}

	gUser, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, coretypes.Token{}, err // Error is already provider-specific
	}

	return gUser, token, nil
}

// RefreshToken - LinkedIn access tokens are typically long-lived.
// Standard refresh token grant_type is not commonly used in the same way as other providers.
// The access token itself might be valid for a long period (e.g., 60 days).
// Refer to LinkedIn docs for token lifecycle management.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	return coretypes.Token{}, coretypes.NewProviderError("linkedin", coretypes.ErrTypeToken, "LinkedIn token refresh is not typically handled via standard refresh_token grant for this flow; tokens are often long-lived.")
}

// ValidateToken attempts to fetch user info to validate the token.
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	if token.AccessToken == "" {
		return coretypes.User{}, false, coretypes.NewProviderError("linkedin", coretypes.ErrTypeToken, "access token is missing")
	}
	if !token.Expiry.IsZero() && time.Now().After(token.Expiry) {
		return coretypes.User{}, false, nil // Token expired
	}

	user, err := p.fetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		return coretypes.User{}, false, nil // Could not fetch user info, token likely invalid
	}
	return user, true, nil
}

// SupportsRefresh indicates if the provider supports standard token refresh.
func (p *Provider) SupportsRefresh() bool {
	return false // As per common LinkedIn flow, standard refresh token grant isn't primary.
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func (p *Provider) exchangeCodeForToken(ctx context.Context, code string) (coretypes.Token, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", linkedinTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "failed to create token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "token request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.Token{}, coretypes.NewProviderError("linkedin", coretypes.ErrTypeProvider, fmt.Sprintf("token request failed with status %d", resp.StatusCode))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return coretypes.Token{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "failed to decode token response", err)
	}

	token := coretypes.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   "Bearer", // LinkedIn uses Bearer
	}
	if tokenResp.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	return token, nil
}

// fetchUserInfo retrieves user information from LinkedIn's API.
func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (coretypes.User, error) {
	// Fetch basic profile
	req, err := http.NewRequestWithContext(ctx, "GET", linkedinUserInfoURL+"?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))", nil)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "failed to create userinfo request for basic profile", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Restli-Protocol-Version", "2.0.0") // Recommended by LinkedIn

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "userinfo request for basic profile failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return coretypes.User{}, coretypes.NewProviderError("linkedin", coretypes.ErrTypeProvider, fmt.Sprintf("userinfo request for basic profile failed with status %d", resp.StatusCode))
	}

	var liUser UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&liUser); err != nil {
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "failed to decode userinfo (basic profile) response", err)
	}

	// Fetch email address
	email, err := p.fetchEmailAddress(ctx, accessToken)
	if err != nil {
		// Log or handle error, but proceed if email is not critical
		// For coretypes, email is usually important.
		return coretypes.User{}, coretypes.NewProviderErrorWithCause("linkedin", coretypes.ErrTypeProvider, "failed to fetch user email address", err)
	}

	name := strings.TrimSpace(liUser.LocalizedFirstName + " " + liUser.LocalizedLastName)

	// Extract avatar URL if available
	// LinkedIn's profilePicture structure can be complex. This is a simplified access.
	// The projection `profilePicture(displayImage~:playableStreams)` might be needed.
	// A more robust way is to parse `liUser.ProfilePicture.DisplayImage` which should contain `elements` array
	// and then finding an appropriate image URL.
	// For simplicity, we assume a direct field or a primary image URL.
	// This part may need adjustment based on actual API response structure for profile pictures with current projections.
	avatarURL := ""
	// Placeholder for actual avatar URL extraction logic based on LinkedIn API response.
	// The `profilePicture(displayImage~:playableStreams))` projection returns a complex object.
	// You'd typically iterate through `liUser.ProfilePicture.DisplayImage.Elements`
	// and find the identifier for the largest available image.
	// For example: `liUser.ProfilePicture.DisplayImage.Elements[length-1].Identifiers[0].Identifier`

	user := coretypes.User{
		ID:        liUser.ID,
		Email:     email,
		Name:      name,
		Username:  liUser.ID, // LinkedIn doesn't have a distinct public username in the same vein as others
		AvatarURL: avatarURL, // This needs proper parsing of the profilePicture field
		RawData: map[string]interface{}{
			"provider":             "linkedin",
			"localized_first_name": liUser.LocalizedFirstName,
			"localized_last_name":  liUser.LocalizedLastName,
			// Add other fields from liUser if needed
		},
	}
	return user, nil
}

// fetchEmailAddress retrieves the user's primary email from LinkedIn's API
func (p *Provider) fetchEmailAddress(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", linkedinEmailURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-Restli-Protocol-Version", "2.0.0") // Recommended

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("email request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("email request failed with status %d", resp.StatusCode)
	}

	var emailData EmailAddress
	if err := json.NewDecoder(resp.Body).Decode(&emailData); err != nil {
		return "", fmt.Errorf("failed to decode email response: %w", err)
	}

	if len(emailData.Elements) > 0 && emailData.Elements[0].HandleTilde.EmailAddress != "" {
		return emailData.Elements[0].HandleTilde.EmailAddress, nil
	}

	return "", fmt.Errorf("no email address found or email scope not granted")
}
