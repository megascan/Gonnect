package gonnect

import (
	"github.com/megascan/Gonnect/gonnect/internal/coretypes"
	"github.com/megascan/Gonnect/gonnect/providers/amazon"
	"github.com/megascan/Gonnect/gonnect/providers/apple"
	"github.com/megascan/Gonnect/gonnect/providers/discord"
	"github.com/megascan/Gonnect/gonnect/providers/dropbox"
	"github.com/megascan/Gonnect/gonnect/providers/facebook"
	"github.com/megascan/Gonnect/gonnect/providers/github"
	"github.com/megascan/Gonnect/gonnect/providers/gitlab"
	"github.com/megascan/Gonnect/gonnect/providers/google"
	"github.com/megascan/Gonnect/gonnect/providers/linkedin"
	"github.com/megascan/Gonnect/gonnect/providers/microsoft"
	"github.com/megascan/Gonnect/gonnect/providers/steam"
	"github.com/megascan/Gonnect/gonnect/providers/twitter"
	"github.com/megascan/Gonnect/gonnect/providers/yahoo"
	"github.com/megascan/Gonnect/gonnect/providers/yandex"
)

// Google adds Google OAuth2 provider with method chaining
func (g *Gonnect) Google(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Google
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	provider := google.New(clientID, clientSecret, g.baseURL+"/auth/google/callback", scopes)

	g.providers["google"] = provider.(coretypes.Provider)
	return g
}

// GitHub adds GitHub OAuth2 provider with method chaining
func (g *Gonnect) GitHub(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for GitHub
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	provider := github.New(clientID, clientSecret, g.baseURL+"/auth/github/callback", scopes)

	g.providers["github"] = provider.(coretypes.Provider)
	return g
}

// Discord adds Discord OAuth2 provider with method chaining
func (g *Gonnect) Discord(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Discord
	if len(scopes) == 0 {
		scopes = []string{"identify", "email"}
	}

	provider := discord.New(clientID, clientSecret, g.baseURL+"/auth/discord/callback", scopes)

	g.providers["discord"] = provider.(coretypes.Provider)
	return g
}

// Steam adds Steam OpenID provider with method chaining
func (g *Gonnect) Steam() *Gonnect {
	// Steam uses OpenID 2.0, not OAuth2
	// The redirect URL for Steam is constructed here
	redirectURL := g.baseURL + "/auth/steam/callback"

	provider := steam.New(redirectURL)

	g.providers["steam"] = provider.(coretypes.Provider)
	return g
}

// Microsoft adds Microsoft OAuth2 provider with method chaining
func (g *Gonnect) Microsoft(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Microsoft
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	provider := microsoft.New(clientID, clientSecret, g.baseURL+"/auth/microsoft/callback", scopes)

	g.providers["microsoft"] = provider.(coretypes.Provider)
	return g
}

// Apple adds Apple OAuth2 provider with method chaining
func (g *Gonnect) Apple(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Apple
	if len(scopes) == 0 {
		scopes = []string{"name", "email"}
	}

	provider := apple.New(clientID, clientSecret, g.baseURL+"/auth/apple/callback", scopes)

	g.providers["apple"] = provider.(coretypes.Provider)
	return g
}

// Facebook adds Facebook OAuth2 provider with method chaining
func (g *Gonnect) Facebook(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Facebook
	if len(scopes) == 0 {
		scopes = []string{"email", "public_profile"}
	}

	provider := facebook.New(clientID, clientSecret, g.baseURL+"/auth/facebook/callback", scopes)

	g.providers["facebook"] = provider.(coretypes.Provider)
	return g
}

// Twitter adds Twitter OAuth2 provider with method chaining
func (g *Gonnect) Twitter(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Twitter API v2 (user context)
	if len(scopes) == 0 {
		scopes = []string{"users.read", "tweet.read"} // Common read-only scopes
	}

	provider := twitter.New(clientID, clientSecret, g.baseURL+"/auth/twitter/callback", scopes)

	g.providers["twitter"] = provider.(coretypes.Provider)
	return g
}

// LinkedIn adds LinkedIn OAuth2 provider with method chaining
func (g *Gonnect) LinkedIn(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for LinkedIn
	if len(scopes) == 0 {
		scopes = []string{"r_liteprofile", "r_emailaddress"}
	}

	provider := linkedin.New(clientID, clientSecret, g.baseURL+"/auth/linkedin/callback", scopes)

	g.providers["linkedin"] = provider.(coretypes.Provider)
	return g
}

// Amazon adds Amazon OAuth2 provider with method chaining
func (g *Gonnect) Amazon(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Amazon
	if len(scopes) == 0 {
		scopes = []string{"profile"}
	}

	provider := amazon.New(clientID, clientSecret, g.baseURL+"/auth/amazon/callback", scopes)

	g.providers["amazon"] = provider.(coretypes.Provider)
	return g
}

// GitLab adds GitLab OAuth2 provider with method chaining
func (g *Gonnect) GitLab(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for GitLab (OIDC)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	provider := gitlab.New(clientID, clientSecret, g.baseURL+"/auth/gitlab/callback", scopes)

	g.providers["gitlab"] = provider.(coretypes.Provider)
	return g
}

// Yahoo adds Yahoo OIDC provider with method chaining
func (g *Gonnect) Yahoo(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Yahoo (OIDC)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	provider := yahoo.New(clientID, clientSecret, g.baseURL+"/auth/yahoo/callback", scopes)

	g.providers["yahoo"] = provider.(coretypes.Provider)
	return g
}

// Yandex adds Yandex OAuth2 provider with method chaining
func (g *Gonnect) Yandex(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Yandex
	if len(scopes) == 0 {
		scopes = []string{"login:info", "login:email"}
	}

	provider := yandex.New(clientID, clientSecret, g.baseURL+"/auth/yandex/callback", scopes)

	g.providers["yandex"] = provider.(coretypes.Provider)
	return g
}

// Dropbox adds Dropbox OAuth2 provider with method chaining
func (g *Gonnect) Dropbox(clientID, clientSecret string, scopes ...string) *Gonnect {
	// Default scopes for Dropbox
	if len(scopes) == 0 {
		scopes = []string{"account_info.read"} // For basic user info
	}

	provider := dropbox.New(clientID, clientSecret, g.baseURL+"/auth/dropbox/callback", scopes)
	g.providers["dropbox"] = provider.(coretypes.Provider)
	return g
}
