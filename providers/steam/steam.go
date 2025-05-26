package steam

import (
	"context"
	"net/http"

	"gonnect/internal/coretypes"
)

// Provider implements the coretypes.Provider interface for Steam (OpenID)
// This is a mock implementation, as Steam uses OpenID, not OAuth2 like others.
// A full OpenID implementation would differ significantly.
type Provider struct {
	name        string
	redirectURL string
	// Steam OpenID relies on an API key for some operations, not typically clientID/clientSecret
	// apiKey string
}

// New creates a new Steam provider instance (mock)
func New(redirectURL string) coretypes.Provider {
	return &Provider{
		name:        "steam",
		redirectURL: redirectURL,
	}
}

// Name returns the provider's name
func (p *Provider) Name() string {
	return p.name
}

// BeginAuth for Steam OpenID would involve redirecting to the Steam login page
// with specific OpenID parameters.
func (p *Provider) BeginAuth(ctx context.Context, state string) (string, error) {
	// Example OpenID 2.0 URL structure (highly simplified)
	// A real implementation would use an OpenID library to construct this URL.
	// Parameters like 'openid.ns', 'openid.mode', 'openid.claimed_id', 'openid.identity',
	// 'openid.return_to', 'openid.realm' are required.
	// Steam specific endpoint: https://steamcommunity.com/openid/login
	steamLoginURL := "https://steamcommunity.com/openid/login"

	// This is a very basic placeholder. A real OpenID request is more complex.
	// It should include parameters like 'openid.return_to' (p.redirectURL + "?state=" + state),
	// 'openid.realm' (base URL of the app), etc.
	// For Gonnect's state mechanism to work, the state needs to be passed through.
	// However, OpenID 2.0 doesn't have a 'state' parameter in the same way as OAuth2.
	// State is often appended to the 'openid.return_to' URL or managed via session before redirect.

	// For this mock, we'll just return a simplified conceptual URL.
	// The state parameter would typically be part of the return_to URL.
	return steamLoginURL + "?openid.mode=checkid_setup&openid.return_to=" + p.redirectURL + "&gonnect_state_placeholder=" + state, nil
}

// CompleteAuth for Steam OpenID involves validating the response from Steam.
// Steam POSTs back to the return_to URL with OpenID parameters.
// This requires verifying a signature sent by Steam using a shared secret or discovery.
func (p *Provider) CompleteAuth(ctx context.Context, r *http.Request) (coretypes.User, coretypes.Token, error) {
	// A real implementation would:
	// 1. Check r.Method to ensure it's GET or POST as expected from Steam.
	// 2. Extract all 'openid.*' parameters from r.Form.
	// 3. Verify 'openid.mode' (e.g., 'id_res').
	// 4. Verify the 'openid.signed' list of fields and the 'openid.sig' signature.
	//    This involves making a request back to Steam ('check_authentication').
	// 5. Extract the 'openid.claimed_id', which contains the user's SteamID64.
	//    Example: https://steamcommunity.com/openid/id/76561197960287930
	// 6. Optionally, use the Steam Web API (with an API key) to fetch user profile details (name, avatar) using the SteamID64.

	// Placeholder user and token, as this is a mock
	claimedID := r.URL.Query().Get("openid.claimed_id") // Highly simplified
	if claimedID == "" {
		// In a real flow, you'd check specific OpenID params
		claimedID = "mock-steam-id64-from-callback"
	}

	user := coretypes.User{
		ID:    claimedID,         // This would be the SteamID64
		Email: "",                // Steam OpenID doesn't directly provide email
		Name:  "Mock Steam User", // Would be fetched via Steam Web API
		RawData: map[string]interface{}{
			"provider":   p.name,
			"claimed_id": claimedID,
		},
	}

	// OpenID doesn't use OAuth2 tokens (Access Token, Refresh Token) in the same way.
	// Authentication is based on the assertion from Steam.
	token := coretypes.Token{
		AccessToken: "steam_openid_assertion_placeholder", // Not a typical Bearer token
		TokenType:   "OpenID",
	}

	return user, token, nil
}

// RefreshToken is not applicable to Steam OpenID in the OAuth2 sense.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (coretypes.Token, error) {
	return coretypes.Token{}, coretypes.NewProviderError(p.name, coretypes.ErrTypeProvider, "Operation not supported: Steam (OpenID) does not support token refresh in the OAuth2 manner.")
}

// ValidateToken for OpenID would mean re-validating the assertion or relying on session.
// Since OpenID is not token-based like OAuth2, this concept is different.
// For Gonnect's interface, we can treat the initial authentication as "validation".
func (p *Provider) ValidateToken(ctx context.Context, token coretypes.Token) (coretypes.User, bool, error) {
	// If the token.AccessToken is our placeholder for a validated OpenID assertion,
	// and we don't have a way to re-verify it without user context,
	// this method might be of limited use for Steam OpenID.
	// A session would typically store the authenticated user state.
	if token.AccessToken == "steam_openid_assertion_placeholder" && token.TokenType == "OpenID" {
		// This is a mock validation. In reality, you'd rely on the session
		// established after CompleteAuth.
		user := coretypes.User{
			ID:   "mock-steam-id64-validated",
			Name: "Mock Steam User (Validated)",
			RawData: map[string]interface{}{
				"provider": p.name,
			},
		}
		return user, true, nil
	}
	return coretypes.User{}, false, nil
}

// SupportsRefresh indicates that Steam OpenID does not support OAuth2 token refresh.
func (p *Provider) SupportsRefresh() bool {
	return false
}
