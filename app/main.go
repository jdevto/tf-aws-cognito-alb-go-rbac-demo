package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"demo-auth-app/internal/auth"
	"demo-auth-app/internal/requests"
)

var tpl *template.Template

func main() {
	// Initialize DynamoDB client
	tableName := os.Getenv("DYNAMODB_TABLE_NAME")
	if tableName != "" {
		ctx := context.Background()
		if err := requests.InitDynamoClient(ctx, tableName); err != nil {
			log.Fatalf("Failed to initialize DynamoDB client: %v", err)
		}
		log.Printf("✅ DynamoDB client initialized with table: %s", tableName)
	} else {
		log.Printf("⚠️  DYNAMODB_TABLE_NAME not set, request storage will not work")
	}

	// Parse templates in specific order to ensure content blocks are defined correctly
	// Parse layout first, then content templates (module, forbidden, requests)
	var err error
	tpl, err = template.ParseFiles(
		"web/templates/layout.html",
		"web/templates/module.html",
		"web/templates/forbidden.html",
		"web/templates/requests.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	// Setup routes
	mux := http.NewServeMux()

	// Static files (favicon, etc.)
	fs := http.FileServer(http.Dir("web/static"))
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".ico") {
			w.Header().Set("Content-Type", "image/x-icon")
		} else if strings.HasSuffix(r.URL.Path, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		}
		http.StripPrefix("/static/", fs).ServeHTTP(w, r)
	})
	mux.Handle("/static/", staticHandler)

	// Serve ICO favicon (browsers automatically request /favicon.ico)
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve ICO file first, fallback to SVG if ICO doesn't exist
		if _, err := os.Stat("web/static/favicon.ico"); err == nil {
			w.Header().Set("Content-Type", "image/x-icon")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			http.ServeFile(w, r, "web/static/favicon.ico")
		} else {
			// Fallback to SVG for modern browsers
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=31536000")
			http.ServeFile(w, r, "web/static/favicon.svg")
		}
	})

	// Serve SVG favicon directly
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		http.ServeFile(w, r, "web/static/favicon.svg")
	})

	// Public routes
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/forbidden", forbiddenHandler)

	// Protected routes (require authentication)
	mux.Handle("/module", auth.Middleware(http.HandlerFunc(moduleHandler)))
	mux.Handle("/whoami", auth.Middleware(http.HandlerFunc(whoamiHandler)))

	// Permission-based routes
	mux.Handle("/create", auth.Middleware(auth.RequirePermission("create_request")(createRequestHandler)))
	mux.HandleFunc("/approve/", func(w http.ResponseWriter, r *http.Request) {
		auth.Middleware(auth.RequirePermission("approve")(http.HandlerFunc(approveHandler))).ServeHTTP(w, r)
	})
	mux.HandleFunc("/reject/", func(w http.ResponseWriter, r *http.Request) {
		auth.Middleware(auth.RequirePermission("approve")(http.HandlerFunc(rejectHandler))).ServeHTTP(w, r)
	})
	mux.Handle("/requests", auth.Middleware(auth.RequirePermission("view")(viewRequestsHandler)))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// rootHandler redirects to the module page
func rootHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/module", http.StatusSeeOther)
}

// healthHandler returns OK for ALB health checks
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "ok")
}

// moduleHandler displays the shared module page with conditional admin controls
func moduleHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	isAdmin := false
	for _, group := range user.Groups {
		if group == "admins" {
			isAdmin = true
			break
		}
	}

	data := struct {
		User              auth.User
		IsAdmin           bool
		CanCreateRequest  bool
		CanApprove        bool
		CanView           bool
		IsViewerOnly      bool
	}{
		User:             user,
		IsAdmin:          isAdmin,
		CanCreateRequest: user.HasPermission("create_request"),
		CanApprove:       user.HasPermission("approve"),
		CanView:          user.HasPermission("view"),
		IsViewerOnly:     user.HasPermission("view") && !user.HasPermission("create_request") && !user.HasPermission("approve") && !isAdmin,
	}

	// Parse module.html and layout.html together to ensure module's content block is used
	moduleTmpl, err := template.ParseFiles("web/templates/module.html", "web/templates/layout.html")
	if err != nil {
		log.Printf("Failed to parse module templates: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = moduleTmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// createRequestHandler handles request creation (requires create_request permission)
func createRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := auth.UserFromContext(r.Context())
	description := r.FormValue("description")
	if description == "" {
		description = fmt.Sprintf("Request created by %s at %s", user.Email, time.Now().Format(time.RFC3339))
	}

	ctx := r.Context()
	req, err := requests.CreateRequest(ctx, user.Email, description)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Request Created</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
		.success { color: green; font-weight: bold; }
	</style>
</head>
<body>
	<h1>Request Created</h1>
	<p class="success">✓ Request created successfully!</p>
	<p><strong>Request ID:</strong> %s</p>
	<p><strong>Created by:</strong> %s</p>
	<p><strong>Description:</strong> %s</p>
	<p><strong>Status:</strong> %s</p>
	<p><a href="/module">Back to module</a> | <a href="/requests">View all requests</a></p>
</body>
</html>
	`, req.RequestID, req.CreatedBy, req.Description, req.Status)
}

// approveHandler handles request approval (requires approve permission)
func approveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := auth.UserFromContext(r.Context())
	requestID := strings.TrimPrefix(r.URL.Path, "/approve/")
	if requestID == "" {
		requestID = r.FormValue("request_id")
	}

	if requestID == "" {
		http.Error(w, "Request ID is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	err := requests.ApproveRequest(ctx, requestID, user.Email)
	if err != nil {
		log.Printf("Failed to approve request %s: %v", requestID, err)
		http.Error(w, fmt.Sprintf("Failed to approve request: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Request Approved</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
		.success { color: green; font-weight: bold; }
	</style>
</head>
<body>
	<h1>Request Approved</h1>
	<p class="success">✓ Request %s approved by reviewer: %s</p>
	<p>The request has been approved and processed.</p>
	<p><a href="/module">Back to module</a> | <a href="/requests">View all requests</a></p>
</body>
</html>
	`, requestID, user.Email)
}

// rejectHandler handles request rejection (requires approve permission)
func rejectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := auth.UserFromContext(r.Context())
	requestID := strings.TrimPrefix(r.URL.Path, "/reject/")
	if requestID == "" {
		requestID = r.FormValue("request_id")
	}

	if requestID == "" {
		http.Error(w, "Request ID is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	err := requests.RejectRequest(ctx, requestID, user.Email)
	if err != nil {
		log.Printf("Failed to reject request %s: %v", requestID, err)
		http.Error(w, fmt.Sprintf("Failed to reject request: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Request Rejected</title>
	<style>
		body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
		.warning { color: #dc3545; font-weight: bold; }
	</style>
</head>
<body>
	<h1>Request Rejected</h1>
	<p class="warning">✗ Request %s rejected by reviewer: %s</p>
	<p>The request has been rejected.</p>
	<p><a href="/module">Back to module</a> | <a href="/requests">View all requests</a></p>
</body>
</html>
	`, requestID, user.Email)
}

// viewRequestsHandler displays all requests (requires view permission)
func viewRequestsHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	ctx := r.Context()
	allRequests, err := requests.ListRequests(ctx, "")
	if err != nil {
		log.Printf("❌ Failed to list requests: %v", err)
		http.Error(w, "Failed to load requests", http.StatusInternalServerError)
		return
	}
	log.Printf("✅ Loaded %d requests from DynamoDB", len(allRequests))

	data := struct {
		User     auth.User
		Requests []*requests.Request
		CanApprove bool
	}{
		User:      user,
		Requests:  allRequests,
		CanApprove: user.HasPermission("approve"),
	}

	// Parse requests.html and layout.html together
	requestsTmpl, err := template.ParseFiles("web/templates/requests.html", "web/templates/layout.html")
	if err != nil {
		log.Printf("Failed to parse requests templates: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = requestsTmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		log.Printf("❌ Template execution error: %v", err)
		log.Printf("   Data: User=%s, Requests count=%d, CanApprove=%v", user.Email, len(allRequests), data.CanApprove)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// forbiddenHandler displays the forbidden page
func forbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Parse forbidden.html and layout.html together to ensure forbidden's content block is used
	forbiddenTmpl, err := template.ParseFiles("web/templates/forbidden.html", "web/templates/layout.html")
	if err != nil {
		log.Printf("Failed to parse forbidden templates: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = forbiddenTmpl.ExecuteTemplate(w, "layout.html", nil)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// whoamiHandler displays current user information for debugging
func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "User Information:\n")
	fmt.Fprintf(w, "  Sub: %s\n", user.Sub)
	fmt.Fprintf(w, "  Email: %s\n", user.Email)
	fmt.Fprintf(w, "  Groups: [%s]\n", strings.Join(user.Groups, ", "))
	fmt.Fprintf(w, "  Permissions:\n")
	if len(user.Permissions) > 0 {
		for perm, granted := range user.Permissions {
			if granted {
				fmt.Fprintf(w, "    - %s: true\n", perm)
			}
		}
	} else {
		fmt.Fprintf(w, "    (none)\n")
	}
}

// renderTemplate renders a template with the given data
func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := tpl.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
