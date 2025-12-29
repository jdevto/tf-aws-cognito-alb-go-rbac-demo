#!/bin/bash
set -e

# Logging
exec > >(tee /var/log/user-data.log) 2>&1
echo "=== Starting user data script at $(date) ==="

# Configuration
S3_BUCKET="${s3_bucket_id}"
AWS_REGION="${aws_region}"
COGNITO_USER_POOL_ID="${cognito_user_pool_id}"
PERMISSION_GROUPS="${permission_groups}"
DYNAMODB_TABLE_NAME="${dynamodb_table_name}"
APP_DIR="/opt/demo-auth-app"

echo "Configuration:"
echo "  S3 Bucket: $S3_BUCKET"
echo "  AWS Region: $AWS_REGION"
echo "  Cognito User Pool ID: $COGNITO_USER_POOL_ID"
echo "  DynamoDB Table Name: $DYNAMODB_TABLE_NAME"

# Update system
echo "Updating system packages..."
dnf update -y

# Install Go
echo "Installing Go 1.24..."
curl -sL https://go.dev/dl/go1.24.0.linux-amd64.tar.gz -o /tmp/go.tar.gz
if [ $? -ne 0 ]; then
    echo "✗ Failed to download Go"
    exit 1
fi

rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz

# Set Go environment
export PATH=$PATH:/usr/local/go/bin
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export GOMODCACHE=/root/go/pkg/mod

# Create Go directories
mkdir -p $GOPATH/pkg/mod
mkdir -p $GOCACHE

echo "Go version:"
go version

# Create app directory
echo "Creating app directory..."
mkdir -p $APP_DIR

# Sync app code from S3
echo "Syncing app code from S3..."
echo "  Source: s3://$S3_BUCKET/app/"
echo "  Destination: $APP_DIR/"

aws s3 sync s3://$S3_BUCKET/app/ $APP_DIR/ --region $AWS_REGION --delete

# Verify sync
if [ $? -eq 0 ]; then
    echo "✓ S3 sync completed successfully"
else
    echo "✗ S3 sync failed"
    exit 1
fi

echo "Downloaded files:"
ls -lah $APP_DIR/

# Verify required files
echo "Verifying required files..."
if [ ! -f "$APP_DIR/go.mod" ]; then
    echo "✗ go.mod not found"
    exit 1
fi

if [ ! -f "$APP_DIR/main.go" ]; then
    echo "✗ main.go not found"
    exit 1
fi

echo "✓ All required files found"

# Download Go dependencies
cd $APP_DIR
echo "Downloading Go dependencies..."

# Run go mod tidy first to ensure go.sum is correct
echo "Running go mod tidy to generate go.sum..."
export PATH=$PATH:/usr/local/go/bin
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export GOMODCACHE=/root/go/pkg/mod

cd $APP_DIR
go mod tidy

if [ $? -ne 0 ]; then
    echo "✗ go mod tidy failed"
    exit 1
fi

# Verify go.sum was created
if [ ! -f "$APP_DIR/go.sum" ]; then
    echo "✗ go.sum was not created"
    exit 1
fi

echo "✓ go.sum generated successfully"

# Then download dependencies
echo "Downloading Go dependencies..."
go mod download

if [ $? -eq 0 ]; then
    echo "✓ Go dependencies downloaded"
else
    echo "✗ Go dependencies download failed"
    exit 1
fi

# Create systemd service
echo "Creating systemd service for demo-auth-app..."
cat > /etc/systemd/system/demo-auth-app.service <<EOF
[Unit]
Description=Demo Auth App
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
# Ensure go.sum exists before starting
ExecStartPre=/bin/bash -c 'export PATH=\$PATH:/usr/local/go/bin && export HOME=/root && export GOPATH=/root/go && export GOCACHE=/root/.cache/go-build && export GOMODCACHE=/root/go/pkg/mod && cd $APP_DIR && go mod tidy'
ExecStart=/usr/local/go/bin/go run .
Restart=always
RestartSec=5
Environment="HOME=/root"
Environment="GOPATH=/root/go"
Environment="GOCACHE=/root/.cache/go-build"
Environment="GOMODCACHE=/root/go/pkg/mod"
Environment="DEBUG=${debug_enabled}"
Environment="COGNITO_USER_POOL_ID=${cognito_user_pool_id}"
Environment="AWS_REGION=${aws_region}"
Environment="DYNAMODB_TABLE_NAME=${dynamodb_table_name}"
${permission_groups_env}

[Install]
WantedBy=multi-user.target
EOF

# Create S3 sync script
echo "Creating S3 sync script..."
cat > /usr/local/bin/demo-auth-app-s3-sync.sh <<SCRIPT_EOF
#!/bin/bash
set -e

APP_DIR="$APP_DIR"
S3_BUCKET="$S3_BUCKET"
AWS_REGION="$AWS_REGION"

export PATH=\$PATH:/usr/local/go/bin
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export GOMODCACHE=/root/go/pkg/mod

# Only hash source code files (exclude temp files, logs, etc.)
BEFORE_HASH=\$(find "\$APP_DIR" -type f \( -name "*.go" -o -name "*.mod" -o -name "*.sum" -o -name "*.html" -o -name "*.ico" -o -name "*.svg" \) -exec md5sum {} \; | sort | md5sum)

aws s3 sync "s3://\$S3_BUCKET/app/" "\$APP_DIR/" --region "\$AWS_REGION" --delete

AFTER_HASH=\$(find "\$APP_DIR" -type f \( -name "*.go" -o -name "*.mod" -o -name "*.sum" -o -name "*.html" -o -name "*.ico" -o -name "*.svg" \) -exec md5sum {} \; | sort | md5sum)

if [ "\$BEFORE_HASH" != "\$AFTER_HASH" ]; then
  echo "Source files changed, running go mod tidy..."
  cd "\$APP_DIR" && go mod tidy
  echo "Restarting demo-auth-app"
  systemctl restart demo-auth-app.service
else
  echo "No source file changes detected, skipping restart"
fi
SCRIPT_EOF

chmod +x /usr/local/bin/demo-auth-app-s3-sync.sh

# Create S3 sync service
echo "Creating S3 sync service..."
cat > /etc/systemd/system/demo-auth-app-s3-sync.service <<EOF
[Unit]
Description=Demo Auth App S3 Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/demo-auth-app-s3-sync.sh
Environment="AWS_DEFAULT_REGION=$AWS_REGION"
EOF

# Create timer for S3 sync
echo "Creating S3 sync timer..."
cat > /etc/systemd/system/demo-auth-app-s3-sync.timer <<EOF
[Unit]
Description=Demo Auth App S3 Sync Timer
After=network.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=demo-auth-app-s3-sync.service

[Install]
WantedBy=timers.target
EOF

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Start app service
echo "Starting demo-auth-app service..."
systemctl enable demo-auth-app.service
systemctl start demo-auth-app.service

# Wait for app to start
sleep 5

echo "App service status:"
systemctl status demo-auth-app.service --no-pager || true

# Check if app is listening on port 8080
echo "Checking if app is listening on port 8080..."
if ss -tuln | grep -q ':8080'; then
    echo "✓ App is listening on port 8080"
else
    echo "✗ App is NOT listening on port 8080"
    echo "Recent logs:"
    journalctl -u demo-auth-app.service -n 20 --no-pager
fi

# Enable and start S3 sync timer
echo "Enabling S3 sync timer..."
systemctl enable demo-auth-app-s3-sync.timer
systemctl start demo-auth-app-s3-sync.timer

echo "Timer status:"
systemctl status demo-auth-app-s3-sync.timer --no-pager || true

echo "=== User data script completed at $(date) ==="
echo ""
echo "Summary:"
echo "  ✓ Demo Auth App service: demo-auth-app.service"
echo "  ✓ S3 Sync timer: demo-auth-app-s3-sync.timer (runs every 5 minutes)"
echo ""
echo "Useful commands:"
echo "  systemctl status demo-auth-app.service"
echo "  journalctl -u demo-auth-app.service -f"
echo "  curl http://localhost:8080/health"
echo "  systemctl start demo-auth-app-s3-sync.service  # Manual sync"
