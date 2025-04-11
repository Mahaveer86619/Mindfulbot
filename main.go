package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

var firebaseAuth *auth.Client

// --- Firebase Initialization ---

func initializeFirebase() {
	serviceAccountKeyPath := "serviceAccountKey.json"

	// Check if the file exists
	if _, err := os.Stat(serviceAccountKeyPath); os.IsNotExist(err) {
		log.Fatalf("FATAL: Firebase service account key file not found at '%s'. "+
			"Please download it from your Firebase project settings and update the path in main.go.", serviceAccountKeyPath)
	} else if err != nil {
		log.Fatalf("FATAL: Error checking service account key file: %v", err)
	}

	opt := option.WithCredentialsFile(serviceAccountKeyPath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("FATAL: error initializing Firebase app: %v", err)
	}

	firebaseAuth, err = app.Auth(context.Background())
	if err != nil {
		log.Fatalf("FATAL: error getting Firebase Auth client: %v", err)
	}
	log.Println("Firebase Admin SDK initialized successfully.")
}

// --- Authentication Middleware ---

type contextKey string

const userContextKey contextKey = "user"

// AuthMiddleware verifies the Firebase ID token from the Authorization header
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			log.Println("Auth failed: Missing Authorization header")
			return
		}

		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) != 2 || splitToken[1] == "" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			log.Println("Auth failed: Invalid Authorization header format")
			return
		}

		idToken := splitToken[1]

		// Verify the ID token
		token, err := firebaseAuth.VerifyIDToken(context.Background(), idToken)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			log.Printf("Auth failed: Token verification error: %v", err)
			return
		}

		// Add user information to the request context
		ctx := context.WithValue(r.Context(), userContextKey, token)
		log.Printf("Auth success: User %s authenticated", token.UID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper to get user from context
func getUserFromContext(ctx context.Context) *auth.Token {
	user, ok := ctx.Value(userContextKey).(*auth.Token)
	if !ok {
		return nil // Should not happen if middleware is applied correctly
	}
	return user
}


// --- HTTP Handlers ---

func serveFileHandler(filePath string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Serving file: %s for request: %s", filePath, r.URL.Path)
        // Consider setting Content-Type header based on file extension if needed
        // w.Header().Set("Content-Type", "text/html; charset=utf-8")
        http.ServeFile(w, r, filePath)
    }
}


// Placeholder handler for user login/signup verification (token is verified by middleware)
func authVerifyHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r.Context())
	if user == nil {
 		// This case should ideally be caught by the middleware, but adding for safety
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
        log.Println("Error: user nil in authVerifyHandler despite middleware")
		return
	}

	log.Printf("Token verified for user: %s, Email: %s", user.UID, user.Claims["email"]) // Example: Accessing claims

	// Respond with success or user info (optional)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "userId": user.UID})
}

// Placeholder dashboard handler
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r.Context())
	// In a real app, fetch dashboard data based on user.UID
	log.Printf("Accessing dashboard for user: %s", user.UID)
	serveFileHandler("dashboard.html")(w, r) // Serve the dashboard HTML
}

// Placeholder profile handler
func profileHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r.Context())
	// In a real app, fetch profile data based on user.UID
	log.Printf("Accessing profile for user: %s", user.UID)
	serveFileHandler("profile.html")(w, r) // Serve the profile HTML
}

// Placeholder logout handler (client typically handles sign-out, backend might revoke tokens if needed)
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r.Context())
    // Optional: Revoke refresh tokens if you need immediate session invalidation server-side
	// err := firebaseAuth.RevokeRefreshTokens(context.Background(), user.UID)
	// if err != nil {
	// 	log.Printf("Error revoking refresh token for user %s: %v", user.UID, err)
    //     http.Error(w, "Logout failed", http.StatusInternalServerError)
	// 	return
	// }
	log.Printf("Processing logout request for user: %s", user.UID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "logged out"})
}


// --- Main Server Setup ---

func main() {
	initializeFirebase()

	mux := http.NewServeMux()

	// --- Frontend Routes ---
	// Serve static files (HTML, CSS, JS) - adjust paths as needed
    // Ideally use a library or embed files for better static file serving
	mux.HandleFunc("/", serveFileHandler("login.html")) // Serve login page as default
    mux.HandleFunc("/login", serveFileHandler("login.html"))
    mux.HandleFunc("/signup", serveFileHandler("signup.html"))
    // Serve static assets like CSS/JS if you create them
    // fs := http.FileServer(http.Dir("./static")) // Example: if you have a static folder
    // mux.Handle("/static/", http.StripPrefix("/static/", fs))


	// --- API Routes (Require Authentication) ---
	api := http.NewServeMux() // Separate mux for authenticated routes
	api.HandleFunc("/verify-token", authVerifyHandler) // Endpoint for frontend to verify token after login/signup
	api.HandleFunc("/dashboard", dashboardHandler)
	api.HandleFunc("/profile", profileHandler)
	api.HandleFunc("/logout", logoutHandler) // Requires auth to know *who* is logging out

	// Apply AuthMiddleware to the API routes
	mux.Handle("/api/", http.StripPrefix("/api", AuthMiddleware(api)))


	// --- Start Server ---
	port := "8080"
	addr := ":" + port
	log.Printf("Server starting on http://localhost:%s", port)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on %s: %v", addr, err)
	}
}
