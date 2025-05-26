// Package main provides a debug example to test Gonnect authentication flow
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/megascan/gonnect"
)

func main() {
	baseURL := "http://localhost:8080"

	// Create Gonnect instance
	auth := gonnect.New(baseURL)

	// Configure a simple provider for testing
	auth.GitHub("demo-client-id", "demo-client-secret", "user:email")

	// Configure with debug logging
	auth.SetSessionName("debug_session")
	auth.OnSuccess("/success") // Clear success redirect
	auth.OnFailure("/failure") // Clear failure redirect
	auth.WithLogger(gonnect.NewSimpleLogger(true))

	// Home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)

		fmt.Printf("=== HOME PAGE REQUEST ===\n")
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("User: %v\n", user)
		fmt.Printf("========================\n")

		if user != nil {
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Debug - Authenticated</title></head>
<body>
	<h1>✅ You are authenticated!</h1>
	<p><strong>Name:</strong> %s</p>
	<p><strong>Email:</strong> %s</p>
	<p><strong>ID:</strong> %s</p>
	<p><a href="/success">Go to Success Page</a></p>
	<p><a href="/auth/logout">Logout</a></p>
</body>
</html>`, user.Name, user.Email, user.ID)
		} else {
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Debug - Not Authenticated</title></head>
<body>
	<h1>🔐 Debug Authentication Test</h1>
	<p>You are not authenticated.</p>
	<p><a href="/auth/github">Login with GitHub (Demo)</a></p>
	<p><strong>Note:</strong> This will fail with demo credentials, but you can see the flow.</p>
</body>
</html>`)
		}
	})

	// Success page (where users are redirected after login)
	http.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)

		fmt.Printf("=== SUCCESS PAGE REQUEST ===\n")
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("User: %v\n", user)
		fmt.Printf("============================\n")

		if user != nil {
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Success - Authentication Complete</title></head>
<body>
	<h1>🎉 Authentication Successful!</h1>
	<p>You have been successfully redirected after login.</p>
	<p><strong>Name:</strong> %s</p>
	<p><strong>Email:</strong> %s</p>
	<p><strong>ID:</strong> %s</p>
	<p><a href="/">Back to Home</a></p>
	<p><a href="/auth/logout">Logout</a></p>
</body>
</html>`, user.Name, user.Email, user.ID)
		} else {
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Success - No User</title></head>
<body>
	<h1>❌ No User Found</h1>
	<p>You reached the success page but no user is authenticated.</p>
	<p>This might indicate a session issue.</p>
	<p><a href="/">Back to Home</a></p>
</body>
</html>`)
		}
	})

	// Failure page
	http.HandleFunc("/failure", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("=== FAILURE PAGE REQUEST ===\n")
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("============================\n")

		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authentication Failed</title></head>
<body>
	<h1>❌ Authentication Failed</h1>
	<p>The authentication process failed.</p>
	<p><a href="/">Try Again</a></p>
</body>
</html>`)
	})

	// Protected route for testing
	http.Handle("/protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)

		fmt.Printf("=== PROTECTED PAGE REQUEST ===\n")
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("User: %v\n", user)
		fmt.Printf("==============================\n")

		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Protected Page</title></head>
<body>
	<h1>🔒 Protected Page</h1>
	<p>This page requires authentication.</p>
	<p><strong>Name:</strong> %s</p>
	<p><strong>Email:</strong> %s</p>
	<p><a href="/">Back to Home</a></p>
	<p><a href="/auth/logout">Logout</a></p>
</body>
</html>`, user.Name, user.Email)
	})))

	// Mount auth handlers
	http.Handle("/auth/", auth.Handler())

	// Debug endpoint to check session
	http.HandleFunc("/debug/session", func(w http.ResponseWriter, r *http.Request) {
		user := gonnect.GetUser(r)

		fmt.Printf("=== DEBUG SESSION ===\n")
		fmt.Printf("User: %v\n", user)
		fmt.Printf("Cookies: %v\n", r.Cookies())
		fmt.Printf("=====================\n")

		w.Header().Set("Content-Type", "application/json")
		if user != nil {
			fmt.Fprintf(w, `{
				"authenticated": true,
				"user": {
					"id": "%s",
					"name": "%s",
					"email": "%s"
				}
			}`, user.ID, user.Name, user.Email)
		} else {
			fmt.Fprintf(w, `{
				"authenticated": false,
				"user": null
			}`)
		}
	})

	port := "8080"
	log.Printf("🐛 Debug server starting on port %s", port)
	log.Printf("📍 Visit: http://localhost:%s", port)
	log.Printf("🔒 Protected: http://localhost:%s/protected", port)
	log.Printf("🎯 Success: http://localhost:%s/success", port)
	log.Printf("❌ Failure: http://localhost:%s/failure", port)
	log.Printf("🔍 Debug Session: http://localhost:%s/debug/session", port)
	log.Println("\n💡 This example uses demo credentials that will fail OAuth,")
	log.Println("   but you can observe the authentication flow and redirects.")
	log.Println("\n🔧 To test with real credentials, set environment variables:")
	log.Println("   export GITHUB_CLIENT_ID=your_github_client_id")
	log.Println("   export GITHUB_CLIENT_SECRET=your_github_client_secret")

	// Check for real credentials
	if githubID := os.Getenv("GITHUB_CLIENT_ID"); githubID != "" {
		if githubSecret := os.Getenv("GITHUB_CLIENT_SECRET"); githubSecret != "" {
			log.Println("\n✅ Real GitHub credentials detected! Reconfiguring...")
			auth.GitHub(githubID, githubSecret, "user:email")
			log.Println("✅ GitHub OAuth configured with real credentials")
		}
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
