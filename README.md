# Demo Auth App - Cognito ALB Go RBAC

A demonstration application showcasing AWS Cognito authentication with role-based access control (RBAC) using an Application Load Balancer, DynamoDB, and a Go web application.

## Architecture

- **Go Web App**: Web server with JWT-based authentication and permission-based access control
- **AWS Cognito**: User authentication and group management
- **Application Load Balancer**: HTTPS termination and Cognito integration
- **EC2**: Hosts the Go application
- **S3**: Stores application code
- **DynamoDB**: Stores request data (create, approve, reject)

## Features

- **Configurable Permission System**: Map Cognito groups to application permissions via environment variables
- **Request Management**: Create, view, approve, and reject requests with DynamoDB persistence
- **Security**: JWT signature verification, expiration checks, and issuer validation
- **Group-Based Access Control**: Users in different Cognito groups have different permissions
- **Real-time Permission Updates**: Force refresh on write operations to ensure latest permissions

## Permission Model

The application uses a flexible permission system with these default permissions:

- **`create_request`**: Users can create new requests
- **`approve`**: Users can approve or reject requests
- **`view`**: Users can view all requests (read-only)

### Default Groups

- **`admins`**: Full access to all permissions
- **`request_creators`**: Can create requests and view all
- **`reviewers`**: Can approve/reject requests and view all
- **`viewers`**: Can only view requests (read-only)

## Project Structure

```plaintext
.
├── app/                          # Go web application
│   ├── go.mod
│   ├── main.go                   # Main server with routes
│   ├── internal/
│   │   ├── auth/
│   │   │   └── auth.go           # JWT parsing, Cognito API, permissions
│   │   └── requests/
│   │       └── requests.go       # DynamoDB request operations
│   └── web/
│       ├── static/               # Static files (favicon)
│       └── templates/
│           ├── layout.html       # Base template
│           ├── module.html       # Main module page
│           ├── requests.html    # Request listing page
│           └── forbidden.html   # Access denied page
│
└── infra/                        # Terraform infrastructure
    ├── main.tf                   # Root module configuration
    ├── variables.tf              # Input variables
    ├── outputs.tf                # Output values
    ├── locals.tf                 # Local variables
    └── modules/
        ├── cognito/              # Cognito user pool and groups
        ├── ec2/                  # EC2 instance and IAM
        ├── dynamodb/             # DynamoDB table
        └── ...
```

## Prerequisites

- AWS Account with appropriate permissions
- Terraform >= 1.0
- ACM Certificate ARN (for HTTPS on ALB)
- (Optional) Route53 hosted zone for custom domain

## Deployment

### 1. Configure Terraform Variables

Create `infra/terraform.tfvars`:

```hcl
aws_region      = "us-east-1"
certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT_ID"

# Seed users (optional - can be string, list, or null)
admin_email           = "admin@example.com"
request_creator_email = "creator@example.com"
reviewer_email        = "reviewer@example.com"
viewer_email          = "viewer@example.com"

# Optional: Custom domain
domain_name     = "demo.yourdomain.com"
hosted_zone_id  = "Z1234567890ABC"
```

### 2. Deploy Infrastructure

```bash
cd infra
terraform init
terraform plan
terraform apply
```

Wait for deployment to complete (5-10 minutes). Note the outputs:

- `alb_url`: HTTPS URL to access the application
- `cognito_user_pool_id`: For manual user management
- `seed_user_passwords`: Auto-generated temporary passwords for seed users

### 3. Get User Passwords

After deployment, retrieve auto-generated passwords:

```bash
terraform output -json seed_user_passwords
```

### 4. Test the Application

1. Open the ALB URL in your browser
2. You'll be redirected to Cognito login
3. Login with a seed user (use password from terraform output)
4. Change temporary password on first login
5. Navigate the application based on your group permissions

## How It Works

### Authentication Flow

```plaintext
User → ALB (HTTPS) → Cognito Login → ALB injects JWT → EC2 Go App
                                                           ↓
                                                    Query Cognito API
                                                           ↓
                                                    Get User Groups
                                                           ↓
                                                    Calculate Permissions
```

1. User accesses ALB URL
2. ALB redirects to Cognito for authentication
3. User logs in with Cognito credentials
4. Cognito redirects back to ALB with auth code
5. ALB exchanges code for JWT tokens
6. ALB creates its own JWT and forwards request with `x-amzn-oidc-data` header
7. Go app extracts user `sub` from JWT
8. Go app queries Cognito API for user groups
9. Go app calculates permissions based on group membership
10. Go app enforces permissions on routes

### Permission System

The application uses a configurable permission system:

1. **Permission Configuration**: Loaded from environment variables
   - JSON format: `PERMISSION_GROUPS='{"create_request":["request_creators"],"approve":["reviewers"]}'`
   - Individual vars: `PERMISSION_CREATE_REQUEST_GROUPS='request_creators'`
   - Defaults: Built-in defaults if no config provided

2. **Group Query**: Queries Cognito API directly for user groups
   - Uses `AdminListGroupsForUser` API
   - Cached for 1 minute (reduced from 5 minutes for faster updates)
   - Force refresh on write operations

3. **Permission Calculation**: Maps groups to permissions
   - User can be in multiple groups
   - Permissions are union of all group permissions
   - Write operations force fresh group query

### Security Features

- **JWT Signature Verification**: Verifies signatures for direct tokens (Authorization header)
- **Token Expiration**: Checks `exp` claim and rejects expired tokens
- **Issuer Verification**: Validates token issuer matches expected Cognito User Pool
- **ALB Trust**: Trusts ALB's JWT verification (ALB already verified original Cognito token)
- **Force Refresh**: Write operations always query fresh groups from Cognito

### Request Management

- **Create Request**: Users with `create_request` permission can create requests
- **View Requests**: Users with `view` permission can see all requests
- **Approve/Reject**: Users with `approve` permission can approve or reject pending requests
- **DynamoDB Storage**: All requests stored in DynamoDB with status tracking

## Routes

- `GET /` - Redirects to `/module`
- `GET /module` - Main page (shows different UI based on permissions)
- `POST /create` - Create a new request (requires `create_request` permission)
- `GET /requests` - View all requests (requires `view` permission)
- `POST /approve/{id}` - Approve a request (requires `approve` permission)
- `POST /reject/{id}` - Reject a request (requires `approve` permission)
- `GET /forbidden` - Access denied page
- `GET /whoami` - Debug endpoint showing user info and permissions
- `GET /health` - Health check for ALB

## Permission Configuration

### Default Configuration

If no configuration is provided, the system uses:

```json
{
  "create_request": ["admins", "request_creators"],
  "approve": ["admins", "reviewers"],
  "view": ["admins", "request_creators", "reviewers", "viewers"]
}
```

### Custom Configuration via Terraform

```hcl
module "ec2" {
  # ... other config ...

  permission_groups = jsonencode({
    create_request = ["request_creators", "power_users"]
    approve        = ["reviewers", "senior_reviewers"]
    view           = ["request_creators", "reviewers", "viewers"]
  })
}
```

### Custom Configuration via Environment Variable

```bash
PERMISSION_GROUPS='{
  "create_request": ["request_creators"],
  "approve": ["reviewers"],
  "view": ["request_creators", "reviewers", "viewers"]
}'
```

Or use individual variables:

```bash
PERMISSION_CREATE_REQUEST_GROUPS='request_creators'
PERMISSION_APPROVE_GROUPS='reviewers'
PERMISSION_VIEW_GROUPS='request_creators,reviewers,viewers'
```

## Key Implementation Details

### Why Query Cognito API?

ALB creates its own JWT (`x-amzn-oidc-data`) which doesn't include Cognito groups, even if a Pre-Token Lambda adds them to the original Cognito token. The recommended approach is to:

1. Extract user `sub` from ALB's JWT
2. Query Cognito API directly for user groups
3. Cache results to minimize API calls

This follows AWS best practices and ensures accurate, up-to-date group membership.

### Permission Updates

- **Normal requests**: Groups cached for 1 minute
- **Write operations**: Force refresh to get latest groups
- **User removal**: When a user is removed from a group, they lose access on next write operation (within cache TTL)

### Security Posture

- ✅ JWT signature verification (for direct tokens)
- ✅ Token expiration enforcement
- ✅ Issuer validation
- ✅ Defense-in-depth (ALB + application-level validation)
- ✅ Force refresh on write operations
- ✅ Empty groups check (deny access if no groups)

## Cleanup

```bash
cd infra
terraform destroy
```

This removes all AWS resources including:

- Cognito User Pool
- EC2 instance
- ALB
- DynamoDB table
- S3 bucket (must be empty)

## Troubleshooting

### App not responding

```bash
# SSM into EC2
sudo systemctl status demo-auth-app
sudo journalctl -u demo-auth-app -f
```

### User can't access routes

- Check user is assigned to a group in Cognito
- Verify group name matches permission configuration exactly (case-sensitive)
- Check application logs for permission calculations
- Use `/whoami` endpoint to see user's groups and permissions

### Permissions not updating

- Groups are cached for 1 minute
- Write operations force refresh
- Check Cognito API permissions are correct
- Verify `COGNITO_USER_POOL_ID` environment variable is set

### Authentication loop

- Check Cognito callback URLs match ALB DNS
- Verify certificate is valid for ALB DNS or custom domain

### 502 Bad Gateway

- EC2 app not running: check systemd service
- Security group blocking traffic: verify SG allows ALB → EC2:8080

## License

MIT
