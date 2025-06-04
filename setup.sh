#!/bin/bash

# Event Forwarder Setup Script for Ubuntu 22.04
# This script sets up the event-forwarder service with proper security

set -e

# Configuration
SERVICE_NAME="event-forwarder"
SERVICE_USER="go_blu"
INSTALL_DIR="/opt/event-forwarder"
CONFIG_DIR="/etc/event-forwarder"
CERT_DIR="/etc/event-forwarder/certs"
LOG_DIR="/var/log/event-forwarder"
BINARY_NAME="event-forwarder"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo_error "This script must be run as root (use sudo)"
   exit 1
fi

echo_info "Setting up Event Forwarder service..."

# Create service user (system user with no shell and no home directory)
if ! id "$SERVICE_USER" &>/dev/null; then
    echo_info "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
else
    echo_info "Service user $SERVICE_USER already exists"
fi

# Create directories
echo_info "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$CERT_DIR"
mkdir -p "$LOG_DIR"

# Set directory permissions
echo_info "Setting directory permissions..."
chown root:root "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"

chown root:"$SERVICE_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"

chown root:"$SERVICE_USER" "$CERT_DIR"
chmod 750 "$CERT_DIR"

chown "$SERVICE_USER":"$SERVICE_USER" "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Copy binary if it exists
if [ -f "./$BINARY_NAME" ]; then
    echo_info "Installing binary to $INSTALL_DIR/$BINARY_NAME"
    cp "./$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chown root:root "$INSTALL_DIR/$BINARY_NAME"
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
else
    echo_warn "Binary $BINARY_NAME not found in current directory"
    echo_warn "Please copy your compiled binary to $INSTALL_DIR/$BINARY_NAME"
fi

# Copy config if it exists
if [ -f "./config.json" ]; then
    echo_info "Installing configuration to $CONFIG_DIR/config.json"
    cp "./config.json" "$CONFIG_DIR/config.json"
    chown root:"$SERVICE_USER" "$CONFIG_DIR/config.json"
    chmod 640 "$CONFIG_DIR/config.json"
else
    echo_warn "config.json not found in current directory"
fi

# Create systemd service file
echo_info "Creating systemd service file..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Event Forwarder Service
Documentation=https://github.com/your-org/event-forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_DIR/$BINARY_NAME $CONFIG_DIR/config.json
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$LOG_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
RestrictNamespaces=yes

# Network security
PrivateNetwork=no
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Capability restrictions
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Process limits
LimitNOFILE=65536
LimitNPROC=4096

# Working directory
WorkingDirectory=$INSTALL_DIR

# Environment
Environment=HOME=/tmp
Environment=USER=$SERVICE_USER

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

# Set proper permissions on service file
chown root:root "/etc/systemd/system/$SERVICE_NAME.service"
chmod 644 "/etc/systemd/system/$SERVICE_NAME.service"

# Generate self-signed certificate if none exists
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
    echo_info "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    
    chown root:"$SERVICE_USER" "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
    chmod 640 "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
else
    echo_info "SSL certificates already exist"
fi

# Reload systemd
echo_info "Reloading systemd daemon..."
systemctl daemon-reload

# Enable service (but don't start it yet)
echo_info "Enabling service..."
systemctl enable "$SERVICE_NAME"

echo_info "Setup completed successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}INSTALLATION SUMMARY${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}Service User:${NC} $SERVICE_USER (system user, no shell, no home)"
echo -e "${YELLOW}Binary Location:${NC} $INSTALL_DIR/$BINARY_NAME"
echo -e "${YELLOW}Configuration:${NC} $CONFIG_DIR/config.json"
echo -e "${YELLOW}SSL Certificates:${NC} $CERT_DIR/"
echo -e "${YELLOW}Log Directory:${NC} $LOG_DIR/"
echo -e "${YELLOW}Systemd Service:${NC} $SERVICE_NAME"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}NEXT STEPS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
if [ ! -f "$INSTALL_DIR/$BINARY_NAME" ]; then
    echo -e "${RED}1. Copy your compiled binary:${NC}"
    echo "   sudo cp ./event-forwarder $INSTALL_DIR/$BINARY_NAME"
    echo "   sudo chown root:root $INSTALL_DIR/$BINARY_NAME"
    echo "   sudo chmod 755 $INSTALL_DIR/$BINARY_NAME"
    echo ""
fi

if [ ! -f "$CONFIG_DIR/config.json" ]; then
    echo -e "${RED}2. Create/copy configuration file:${NC}"
    echo "   sudo cp ./config.json $CONFIG_DIR/config.json"
    echo "   sudo chown root:$SERVICE_USER $CONFIG_DIR/config.json"
    echo "   sudo chmod 640 $CONFIG_DIR/config.json"
    echo ""
fi

echo -e "${YELLOW}3. Review and edit configuration:${NC}"
echo "   sudo nano $CONFIG_DIR/config.json"
echo ""
echo -e "${YELLOW}4. Start the service:${NC}"
echo "   sudo systemctl start $SERVICE_NAME"
echo ""
echo -e "${YELLOW}5. Check service status:${NC}"
echo "   sudo systemctl status $SERVICE_NAME"
echo ""
echo -e "${YELLOW}6. View logs:${NC}"
echo "   sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo -e "${YELLOW}7. Test the service:${NC}"
echo "   curl -k https://localhost:8443/health"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}SECURITY FEATURES ENABLED${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "• Dedicated system user ($SERVICE_USER) with no shell access"
echo "• Restricted filesystem access (read-only system, private tmp)"
echo "• Limited capabilities (only CAP_NET_BIND_SERVICE)"
echo "• Process and resource limits enforced"
echo "• Network namespace restrictions"
echo "• No new privileges allowed"
echo "• Self-signed SSL certificate generated"
echo ""

# Final security note
echo_warn "SECURITY NOTE: The service user '$SERVICE_USER' is a system account"
echo_warn "with minimal privileges. It can only bind to privileged ports and"
echo_warn "access its own log directory and configuration files."
