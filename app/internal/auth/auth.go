package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/golang-jwt/jwt/v5"
)

var debugEnabled = os.Getenv("DEBUG") == "true"

func debugLog(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("DEBUG - "+format, v...)
	}
}

// Cognito client and cache
var (
	cognitoClient *cognitoidentityprovider.Client
	cognitoClientOnce sync.Once
	userPoolID string

	// Simple in-memory cache for user groups (key: user sub, value: groups)
	groupCache = struct {
		sync.RWMutex
		data map[string]cachedGroups
	}{
		data: make(map[string]cachedGroups),
	}
)

type cachedGroups struct {
	groups    []string
	expiresAt time.Time
}

const cacheTTL = 1 * time.Minute // Reduced to 1 minute for faster permission updates

// JWKS cache for Cognito public keys
var (
	jwksCache = struct {
		sync.RWMutex
		keys   map[string]*rsa.PublicKey
		expiry time.Time
	}{
		keys: make(map[string]*rsa.PublicKey),
	}
	jwksCacheTTL = 1 * time.Hour
)

// initPermissionConfig loads permission configuration from environment variables
// Format: PERMISSION_GROUPS='{"create_request":["request_creators"],"approve":["reviewers"],"view":["request_creators","reviewers","viewers"]}'
// Or use individual env vars: PERMISSION_CREATE_REQUEST_GROUPS='request_creators'
func initPermissionConfig() {
	permissionConfigOnce.Do(func() {
		config := &PermissionConfig{
			Permissions: make(map[string][]string),
		}

		// Try JSON format first (PERMISSION_GROUPS)
		jsonConfig := os.Getenv("PERMISSION_GROUPS")
		if jsonConfig != "" {
			if err := json.Unmarshal([]byte(jsonConfig), &config.Permissions); err == nil {
				log.Printf("✅ Loaded permission config from PERMISSION_GROUPS: %+v", config.Permissions)
				permissionConfig = config
				return
			}
			log.Printf("⚠️  Failed to parse PERMISSION_GROUPS JSON, trying individual env vars")
		}

		// Fallback to individual environment variables
		// PERMISSION_CREATE_REQUEST_GROUPS='request_creators'
		// PERMISSION_APPROVE_GROUPS='reviewers'
		// PERMISSION_VIEW_GROUPS='request_creators,reviewers,viewers'
		// etc.
		envPrefix := "PERMISSION_"
		for _, env := range os.Environ() {
			if !strings.HasPrefix(env, envPrefix) {
				continue
			}

			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			value := parts[1]

			// Extract permission name: PERMISSION_ADMIN_GROUPS -> admin
			// Remove prefix and _GROUPS suffix
			permissionName := strings.TrimPrefix(key, envPrefix)
			permissionName = strings.TrimSuffix(permissionName, "_GROUPS")
			permissionName = strings.ToLower(permissionName)

			if permissionName == "" {
				continue
			}

			// Parse comma-separated groups
			groups := strings.Split(value, ",")
			trimmedGroups := make([]string, 0, len(groups))
			for _, g := range groups {
				g = strings.TrimSpace(g)
				if g != "" {
					trimmedGroups = append(trimmedGroups, g)
				}
			}

			if len(trimmedGroups) > 0 {
				config.Permissions[permissionName] = trimmedGroups
			}
		}

		// Default configuration if nothing is set
		if len(config.Permissions) == 0 {
			config.Permissions = map[string][]string{
				"create_request": {"admins", "request_creators"}, // Admins and request creators can create
				"approve":        {"admins", "reviewers"},        // Admins and reviewers can approve
				"view":           {"admins", "request_creators", "reviewers", "viewers"}, // All groups can view
			}
			log.Printf("ℹ️  Using default permission config: %+v", config.Permissions)
		} else {
			log.Printf("✅ Loaded permission config from environment: %+v", config.Permissions)
		}

		permissionConfig = config
	})
}

// hasPermission checks if the user has a specific permission based on their groups
func hasPermission(groups []string, permission string) bool {
	initPermissionConfig()

	if permissionConfig == nil {
		return false
	}

	permissionGroups, ok := permissionConfig.Permissions[strings.ToLower(permission)]
	if !ok {
		return false
	}

	// Check if user has any of the groups that grant this permission
	for _, userGroup := range groups {
		for _, permGroup := range permissionGroups {
			if userGroup == permGroup {
				return true
			}
		}
	}

	return false
}

// calculatePermissions determines all permissions a user has based on their groups
func calculatePermissions(groups []string) map[string]bool {
	initPermissionConfig()

	permissions := make(map[string]bool)

	if permissionConfig == nil {
		return permissions
	}

	// Check each configured permission
	for permission := range permissionConfig.Permissions {
		permissions[permission] = hasPermission(groups, permission)
	}

	return permissions
}

func initCognitoClient() {
	cognitoClientOnce.Do(func() {
		userPoolID = os.Getenv("COGNITO_USER_POOL_ID")
		if userPoolID == "" {
			log.Printf("⚠️  COGNITO_USER_POOL_ID not set - group queries will be disabled")
			return
		}

		// Extract region from user pool ID (format: region_poolId) or use environment variable
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
		if region == "" {
			// Try to extract from user pool ID (format: ap-southeast-2_B2WZHjrjJ)
			parts := strings.Split(userPoolID, "_")
			if len(parts) > 0 {
				region = parts[0]
			}
		}
		if region == "" {
			log.Printf("⚠️  AWS region not found - group queries will be disabled")
			return
		}

		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
		)
		if err != nil {
			log.Printf("⚠️  Failed to load AWS config: %v - group queries will be disabled", err)
			return
		}

		cognitoClient = cognitoidentityprovider.NewFromConfig(cfg)
		log.Printf("✅ Cognito client initialized for user pool: %s (region: %s)", userPoolID, region)
	})
}

// invalidateGroupCache removes cached groups for a user (forces fresh query)
func invalidateGroupCache(userSub string) {
	groupCache.Lock()
	delete(groupCache.data, userSub)
	groupCache.Unlock()
	log.Printf("🗑️  Invalidated group cache for user %s", userSub)
}

// getGroupsFromCognito queries Cognito API for user's groups
// If forceRefresh is true, bypasses cache and always queries Cognito
func getGroupsFromCognito(ctx context.Context, userSub string, forceRefresh bool) ([]string, error) {
	initCognitoClient()

	if cognitoClient == nil || userPoolID == "" {
		return nil, nil // Not configured, return empty
	}

	// Check cache first (unless forcing refresh)
	if !forceRefresh {
		groupCache.RLock()
		if cached, ok := groupCache.data[userSub]; ok {
			if time.Now().Before(cached.expiresAt) {
				groupCache.RUnlock()
				debugLog("Using cached groups for user %s: %v", userSub, cached.groups)
				return cached.groups, nil
			}
		}
		groupCache.RUnlock()
	} else {
		// Invalidate cache when forcing refresh
		invalidateGroupCache(userSub)
	}

	// Query Cognito API
	log.Printf("🔍 Querying Cognito API for groups: userPoolId=%s, username=%s", userPoolID, userSub)

	result, err := cognitoClient.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(userSub),
	})

	if err != nil {
		log.Printf("❌ Failed to query Cognito groups for user %s: %v", userSub, err)
		return nil, err
	}

	groups := make([]string, 0, len(result.Groups))
	for _, group := range result.Groups {
		if group.GroupName != nil {
			groups = append(groups, *group.GroupName)
		}
	}

	log.Printf("✅ Retrieved groups from Cognito for user %s: %v", userSub, groups)

	// Cache the result
	groupCache.Lock()
	groupCache.data[userSub] = cachedGroups{
		groups:    groups,
		expiresAt: time.Now().Add(cacheTTL),
	}
	groupCache.Unlock()

	return groups, nil
}

// PermissionConfig maps permission names to groups that grant them
type PermissionConfig struct {
	// Permission name -> list of groups that grant this permission
	Permissions map[string][]string
}

var (
	permissionConfig     *PermissionConfig
	permissionConfigOnce sync.Once
)

// User represents an authenticated user with their Cognito attributes
type User struct {
	Sub         string
	Email       string
	Groups      []string
	Permissions map[string]bool // Dynamic permissions based on groups
}

// CognitoClaims represents the JWT claims from AWS Cognito (via ALB)
type CognitoClaims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	CognitoGroups []string `json:"cognito:groups"`
	Exp           int64    `json:"exp"` // Expiration time (Unix timestamp)
	Iss           string   `json:"iss"` // Issuer
}

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const userContextKey contextKey = "user"

// Middleware extracts and validates the Cognito JWT from ALB headers
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		var fromALB bool

		// Try ALB headers first (primary method - ALB verifies signatures)
		tokenStr = r.Header.Get("x-amzn-oidc-data")
		if tokenStr != "" {
			fromALB = true
		}
		if tokenStr == "" {
			tokenStr = r.Header.Get("x-amzn-oidc-accesstoken")
			if tokenStr != "" {
				fromALB = true
			}
		}
		if tokenStr == "" {
			tokenStr = r.Header.Get("x-amzn-oidc-identity")
			if tokenStr != "" {
				fromALB = true
			}
		}

		// Fallback to Authorization header (requires signature verification)
		if tokenStr == "" {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				tokenStr = strings.TrimSpace(authHeader[len("Bearer "):])
				fromALB = false // Must verify signature
			}
		}

		if tokenStr == "" {
			log.Printf("Missing JWT token in request headers")
			http.Error(w, "Unauthorized: missing authentication token", http.StatusUnauthorized)
			return
		}

		// Parse the JWT manually: header.payload.signature
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			log.Printf("Invalid JWT format: expected 3 parts, got %d", len(parts))
			http.Error(w, "Unauthorized: invalid token format", http.StatusUnauthorized)
			return
		}

		// Decode the payload (second part) - base64url
		payload := parts[1]

		var payloadBytes []byte
		var err error

		// Try base64.RawURLEncoding first
		payloadBytes, err = base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			// Then try URLEncoding with padding
			payloadBytes, err = base64.URLEncoding.DecodeString(payload)
			if err != nil {
				// Finally try standard base64
				payloadBytes, err = base64.StdEncoding.DecodeString(payload)
				if err != nil {
					log.Printf("Failed to decode JWT payload with all methods: %v (payload length: %d)", err, len(payload))
					log.Printf("Payload sample (first 50 chars): %s", payload[:min(50, len(payload))])
					http.Error(w, "Unauthorized: invalid token encoding", http.StatusUnauthorized)
					return
				}
			}
		}

		// Parse JSON claims into strongly typed struct
		var claims CognitoClaims
		if err := json.Unmarshal(payloadBytes, &claims); err != nil {
			log.Printf("Failed to parse JWT claims into CognitoClaims: %v", err)
			http.Error(w, "Unauthorized: invalid token claims", http.StatusUnauthorized)
			return
		}

		// Parse raw claims for fallback group extraction
		rawClaims := map[string]interface{}{}
		_ = json.Unmarshal(payloadBytes, &rawClaims)

		debugLog("JWT claims: %+v", rawClaims)

		// Security validations
		if !fromALB {
			// For non-ALB tokens (Authorization header), verify signature
			if claims.Iss == "" {
				// Try to get issuer from raw claims
				if issRaw, ok := rawClaims["iss"]; ok {
					if issStr, ok := issRaw.(string); ok {
						claims.Iss = issStr
					}
				}
			}
			if claims.Iss == "" {
				log.Printf("Missing issuer claim in token")
				http.Error(w, "Unauthorized: missing token issuer", http.StatusUnauthorized)
				return
			}

			if err := verifyJWTSignature(tokenStr, claims.Iss); err != nil {
				log.Printf("JWT signature verification failed: %v", err)
				http.Error(w, "Unauthorized: invalid token signature", http.StatusUnauthorized)
				return
			}

			// Verify issuer matches expected Cognito User Pool (only for direct tokens)
			if err := verifyIssuer(claims.Iss); err != nil {
				log.Printf("Issuer verification failed: %v", err)
				http.Error(w, "Unauthorized: invalid token issuer", http.StatusUnauthorized)
				return
			}
		}
		// Note: For ALB tokens, we trust ALB's verification. ALB has already verified
		// the original Cognito token signature before creating its own token.

		// Verify expiration (for both ALB and direct tokens)
		if claims.Exp > 0 {
			if time.Now().Unix() > claims.Exp {
				log.Printf("Token expired: exp=%d, now=%d", claims.Exp, time.Now().Unix())
				http.Error(w, "Unauthorized: token expired", http.StatusUnauthorized)
				return
			}
		} else {
			// Try to get exp from raw claims
			if expRaw, ok := rawClaims["exp"]; ok {
				if expFloat, ok := expRaw.(float64); ok {
					if time.Now().Unix() > int64(expFloat) {
						log.Printf("Token expired: exp=%d, now=%d", int64(expFloat), time.Now().Unix())
						http.Error(w, "Unauthorized: token expired", http.StatusUnauthorized)
						return
					}
				}
			}
		}

		// Extract groups from token (if present)
		var finalGroups []string
		if len(claims.CognitoGroups) > 0 {
			finalGroups = append(finalGroups, claims.CognitoGroups...)
		} else if groupsRaw, ok := rawClaims["cognito:groups"]; ok {
			// Fallback: extract from raw claims
			if groupsSlice, ok := groupsRaw.([]interface{}); ok {
				for _, g := range groupsSlice {
					if groupStr, ok := g.(string); ok {
						finalGroups = append(finalGroups, groupStr)
					}
				}
			}
		}

		log.Printf("Parsed JWT for user: %s (sub: %s)", claims.Email, claims.Sub)
		debugLog("Groups in token: %v", finalGroups)

		// Always query Cognito API for groups (ALB tokens don't include groups, and we want fresh data)
		// This ensures that if a user is removed from a group, they lose access immediately (within cache TTL)
		forceRefresh := false // Can be set to true for write operations if needed
		cognitoGroups, err := getGroupsFromCognito(r.Context(), claims.Sub, forceRefresh)
		if err == nil {
			// Always use Cognito's result if query succeeds (even if empty - user was removed from all groups)
			finalGroups = cognitoGroups
			if len(cognitoGroups) > 0 {
				log.Printf("Retrieved groups from Cognito API: %v", finalGroups)
			} else {
				log.Printf("⚠️  User has no groups in Cognito (removed from all groups)")
			}
		} else {
			log.Printf("Failed to query Cognito API: %v", err)
			// If Cognito query fails, fall back to token groups (if available) for read operations
			// For write operations, RequirePermission will force refresh and deny if it fails
			if len(finalGroups) == 0 {
				log.Printf("⚠️  No groups available from Cognito or token")
			} else {
				log.Printf("⚠️  Using token groups as fallback (Cognito query failed)")
			}
		}

		// Calculate permissions from groups
		permissions := calculatePermissions(finalGroups)

		// Log calculated permissions for debugging
		grantedPerms := make([]string, 0)
		for perm, granted := range permissions {
			if granted {
				grantedPerms = append(grantedPerms, perm)
			}
		}
		if len(grantedPerms) > 0 {
			log.Printf("✅ User %s has permissions: %v (groups: %v)", claims.Email, grantedPerms, finalGroups)
		} else {
			log.Printf("⚠️  User %s has no permissions (groups: %v)", claims.Email, finalGroups)
		}

		// Check if user has any permissions at all
		hasAnyPermission := false
		for _, granted := range permissions {
			if granted {
				hasAnyPermission = true
				break
			}
		}

		// Allow access to /forbidden and /whoami even without permissions (for debugging)
		// For all other routes, require at least one permission
		allowedWithoutPermissions := r.URL.Path == "/forbidden" || r.URL.Path == "/whoami"

		// If user has no groups or no permissions, redirect to forbidden (unless already on forbidden/whoami)
		if !allowedWithoutPermissions && (len(finalGroups) == 0 || !hasAnyPermission) {
			log.Printf("User %s has no groups or permissions - redirecting to forbidden", claims.Email)
			http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
			return
		}

		user := User{
			Sub:         claims.Sub,
			Email:       claims.Email,
			Groups:      finalGroups,
			Permissions: permissions,
		}

		// Store user in context
		ctx := context.WithValue(r.Context(), userContextKey, user)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// min returns the minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// UserFromContext retrieves the authenticated user from the request context
func UserFromContext(ctx context.Context) User {
	user, ok := ctx.Value(userContextKey).(User)
	if !ok {
		return User{} // Return zero value if no user in context
	}
	return user
}

// RequirePermission is a middleware that restricts access based on a permission name
// For write operations, it forces a fresh group query to ensure permissions are up-to-date
func RequirePermission(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())

			// For write operations (create, approve, etc.), force refresh groups to ensure latest permissions
			// This prevents users who were removed from groups from performing write operations
			isWriteOperation := permission == "create_request" || permission == "approve"

			if isWriteOperation {
				// Force refresh groups from Cognito to get latest permissions
				groups, err := getGroupsFromCognito(r.Context(), user.Sub, true)
				if err != nil {
					// If we can't refresh groups for a write operation, deny access for safety
					log.Printf("❌ Failed to refresh groups for write operation: %v - denying access", err)
					http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
					return
				}

				// If user has no groups, deny access immediately
				if len(groups) == 0 {
					log.Printf("❌ User %s has no groups - denying write operation %s", user.Email, permission)
					http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
					return
				}

				// Recalculate permissions with fresh groups
				permissions := calculatePermissions(groups)
				user.Groups = groups
				user.Permissions = permissions

				log.Printf("🔄 Refreshed groups for write operation: user=%s, groups=%v, permissions=%v",
					user.Email, groups, permissions)

				// Update context with fresh user data
				ctx := context.WithValue(r.Context(), userContextKey, user)
				r = r.WithContext(ctx)
			}

			// Final permission check
			if !user.HasPermission(permission) {
				log.Printf("❌ User %s denied access to %s (groups: %v, permissions: %v)",
					user.Email, permission, user.Groups, user.Permissions)
				http.Redirect(w, r, "/forbidden", http.StatusSeeOther)
				return
			}

			log.Printf("✅ User %s granted access to %s (groups: %v)", user.Email, permission, user.Groups)
			next(w, r)
		}
	}
}

// HasPermission checks if the user has a specific permission
func (u User) HasPermission(permission string) bool {
	if u.Permissions == nil {
		return false
	}
	return u.Permissions[strings.ToLower(permission)]
}

// verifyIssuer verifies that the token issuer matches the expected Cognito User Pool
func verifyIssuer(iss string) error {
	if iss == "" {
		return fmt.Errorf("issuer claim is empty")
	}

	initCognitoClient()
	if userPoolID == "" {
		// If user pool ID is not configured, skip issuer verification
		// This allows the app to work without Cognito API access
		return nil
	}

	// Extract region from user pool ID
	parts := strings.Split(userPoolID, "_")
	if len(parts) < 2 {
		return fmt.Errorf("invalid user pool ID format")
	}
	region := parts[0]

	// Expected issuer format: https://cognito-idp.{region}.amazonaws.com/{userPoolId}
	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)

	if iss != expectedIssuer {
		return fmt.Errorf("issuer mismatch: expected %s, got %s", expectedIssuer, iss)
	}

	return nil
}

// verifyJWTSignature verifies the JWT signature using Cognito's public keys (JWKS)
func verifyJWTSignature(tokenStr, issuer string) error {
	if issuer == "" {
		return fmt.Errorf("issuer is required for signature verification")
	}

	// Parse token to get kid (key ID) from header
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return fmt.Errorf("missing kid in JWT header")
	}

	// Get public key from JWKS cache or fetch it
	publicKey, err := getPublicKey(issuer, kid)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature using jwt library
	parser := jwt.NewParser()
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse/verify token: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("token is not valid")
	}

	return nil
}

// getPublicKey fetches and caches Cognito's public keys from JWKS endpoint
func getPublicKey(issuer, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	jwksCache.RLock()
	if time.Now().Before(jwksCache.expiry) {
		if key, ok := jwksCache.keys[kid]; ok {
			jwksCache.RUnlock()
			return key, nil
		}
	}
	jwksCache.RUnlock()

	// Fetch JWKS from Cognito
	jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", issuer)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"` // RSA modulus
			E   string `json:"e"` // RSA exponent
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Update cache
	jwksCache.Lock()
	defer jwksCache.Unlock()

	// Clear old cache
	jwksCache.keys = make(map[string]*rsa.PublicKey)

		// Parse and cache all keys
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		// Decode base64url encoded modulus and exponent
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		// Convert exponent bytes to int (usually 65537, but handle any size)
		var eInt int
		if len(eBytes) == 0 {
			continue
		}
		for i := 0; i < len(eBytes); i++ {
			eInt = eInt<<8 | int(eBytes[i])
		}
		if eInt == 0 {
			eInt = 65537 // Default RSA exponent
		}

		// Create RSA public key
		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}

		// Basic validation: check that N and E are valid
		if publicKey.N.Sign() <= 0 || publicKey.E <= 0 {
			log.Printf("Invalid RSA public key for kid %s: N or E is invalid", key.Kid)
			continue
		}

		jwksCache.keys[key.Kid] = publicKey
	}

	// Update cache expiry
	jwksCache.expiry = time.Now().Add(jwksCacheTTL)

	// Return requested key
	if key, ok := jwksCache.keys[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
}

// hasGroup checks if a group name exists in the groups slice
func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}
