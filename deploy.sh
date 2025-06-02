#!/bin/bash
# Metasploit MCP Server - Automated Deployment Script for Digital Ocean
# This script automates the deployment process on a fresh Ubuntu droplet

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root (use sudo)"
    exit 1
fi

print_status "Starting Metasploit MCP Server deployment..."

# Update system
print_status "Updating system packages..."
apt update && apt upgrade -y
print_success "System updated"

# Install dependencies
print_status "Installing dependencies..."
apt install -y curl git nano ufw fail2ban unattended-upgrades
print_success "Dependencies installed"

# Install Docker
if ! command -v docker &> /dev/null; then
    print_status "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    print_success "Docker installed"
else
    print_success "Docker already installed"
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_status "Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    print_success "Docker Compose installed"
else
    print_success "Docker Compose already installed"
fi

# Clone repository
print_status "Cloning Metasploit MCP repository..."
if [ ! -d "/opt/metasploit-mcp" ]; then
    git clone https://github.com/your-repo/metasploit-mcp.git /opt/metasploit-mcp
else
    print_warning "Repository already exists, pulling latest changes..."
    cd /opt/metasploit-mcp && git pull
fi
cd /opt/metasploit-mcp
print_success "Repository ready"

# Generate passwords if .env doesn't exist
if [ ! -f ".env" ]; then
    print_status "Generating secure passwords..."
    MSF_PASS=$(openssl rand -base64 32)
    DB_PASS=$(openssl rand -base64 32)
    
    cat > .env << EOF
# Metasploit RPC Configuration
MSF_PASSWORD=${MSF_PASS}
DB_PASSWORD=${DB_PASS}

# Server Configuration
MCP_PORT=8085
LOG_LEVEL=INFO
EOF
    
    print_success "Environment configured with secure passwords"
    print_warning "Passwords saved in /opt/metasploit-mcp/.env"
else
    print_warning "Environment file already exists, skipping password generation"
fi

# Configure firewall
print_status "Configuring firewall..."
ufw --force disable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8085/tcp
ufw --force enable
print_success "Firewall configured"

# Configure automatic updates
print_status "Configuring automatic security updates..."
echo 'Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/50unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
print_success "Automatic updates configured"

# Configure fail2ban
print_status "Configuring fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban
print_success "Fail2ban configured"

# Create backup directory
mkdir -p /opt/metasploit-mcp/backups
mkdir -p /opt/metasploit-mcp/payloads

# Deploy with Docker Compose
print_status "Starting Docker containers..."
docker-compose up -d
print_success "Docker containers started"

# Wait for services to be ready
print_status "Waiting for services to initialize..."
sleep 30

# Check health
print_status "Checking service health..."
if curl -f http://localhost:8085/healthz > /dev/null 2>&1; then
    print_success "MCP Server is healthy!"
else
    print_error "MCP Server health check failed"
    print_warning "Check logs with: docker-compose logs mcp-server"
fi

# Create systemd service for auto-start
print_status "Creating systemd service..."
cat > /etc/systemd/system/metasploit-mcp.service << EOF
[Unit]
Description=Metasploit MCP Server
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=/opt/metasploit-mcp
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable metasploit-mcp
print_success "Systemd service created"

# Display summary
echo ""
print_success "Deployment completed successfully!"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Metasploit MCP Server Deployment Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  🌐 Server URL:     http://$(curl -s ifconfig.me):8085"
echo "  📚 API Docs:       http://$(curl -s ifconfig.me):8085/docs"
echo "  🏥 Health Check:   http://$(curl -s ifconfig.me):8085/healthz"
echo ""
echo "  📁 Installation:   /opt/metasploit-mcp"
echo "  🔐 Credentials:    /opt/metasploit-mcp/.env"
echo "  💾 Payloads:       /opt/metasploit-mcp/payloads"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
print_warning "Next steps:"
echo "  1. Configure DNS to point to this server"
echo "  2. Set up SSL with Let's Encrypt (see DEPLOY.md)"
echo "  3. Create a non-root user for management"
echo "  4. Review and adjust firewall rules as needed"
echo ""
print_status "View logs with: docker-compose -f /opt/metasploit-mcp/docker-compose.yml logs -f" 