#!/bin/bash
# =============================================================================
# Router Configuration Setup Script
# Prompts user for router credentials and saves to config file
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_DIR/router-config/router_config.json"

echo -e "${BLUE}"
echo "=============================================="
echo "   🔧 Router Configuration Setup"
echo "=============================================="
echo -e "${NC}"

echo "This script configures your router connection for network scanning."
echo "If you don't have an OpenWRT router or don't want router-based scanning,"
echo "you can skip this step and use local scanning instead."
echo ""

# Ask if user wants to configure router
read -p "Do you want to configure router-based scanning? (y/n) [n]: " configure_router
configure_router=${configure_router:-n}

if [[ "$configure_router" != "y" && "$configure_router" != "Y" ]]; then
    echo ""
    echo -e "${YELLOW}Skipping router configuration.${NC}"
    echo "Local network scanning will be used instead."
    
    # Create config with router disabled
    cat > "$CONFIG_FILE" << 'EOF'
{
    "enabled": false,
    "router_ip": "",
    "router_user": "",
    "router_pass": "",
    "scan_interval": 5,
    "auto_start": false,
    "description": "Router Network Scanner Configuration - Router scanning disabled, using local scanning"
}
EOF
    echo -e "${GREEN}✅ Router scanning disabled${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}Router Configuration${NC}"
echo "Enter your OpenWRT router details:"
echo ""

# Get router IP
read -p "Router IP address [192.168.1.1]: " router_ip
router_ip=${router_ip:-192.168.1.1}

# Validate IP format
if ! [[ $router_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Invalid IP address format${NC}"
    exit 1
fi

# Get router username
read -p "Router SSH username [root]: " router_user
router_user=${router_user:-root}

# Get router password (hidden input)
echo -n "Router SSH password: "
read -s router_pass
echo ""

if [ -z "$router_pass" ]; then
    echo -e "${RED}Password cannot be empty${NC}"
    exit 1
fi

# Get scan interval
read -p "Scan interval in seconds [5]: " scan_interval
scan_interval=${scan_interval:-5}

# Test connection
echo ""
echo -e "${YELLOW}Testing connection to router...${NC}"

if command -v sshpass &> /dev/null; then
    if timeout 5 sshpass -p "$router_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$router_user@$router_ip" "echo 'Connection successful'" 2>/dev/null; then
        echo -e "${GREEN}✅ Connection successful!${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not connect to router. Configuration will be saved anyway.${NC}"
        echo "   Please verify your credentials and ensure SSH is enabled on the router."
    fi
else
    echo -e "${YELLOW}⚠️  sshpass not installed, skipping connection test${NC}"
    echo "   Install with: sudo apt install sshpass"
fi

# Create config directory if needed
mkdir -p "$(dirname "$CONFIG_FILE")"

# Save configuration
cat > "$CONFIG_FILE" << EOF
{
    "enabled": true,
    "router_ip": "$router_ip",
    "router_user": "$router_user",
    "router_pass": "$router_pass",
    "scan_interval": $scan_interval,
    "auto_start": false,
    "description": "Router Network Scanner Configuration - Integrated with session.db for centralized logging"
}
EOF

# Set restrictive permissions on config file (contains password)
chmod 600 "$CONFIG_FILE"

echo ""
echo -e "${GREEN}=============================================="
echo "   ✅ Router Configuration Saved!"
echo "==============================================${NC}"
echo ""
echo "Configuration file: $CONFIG_FILE"
echo "Router IP: $router_ip"
echo "Username: $router_user"
echo "Scan interval: ${scan_interval}s"
echo ""
echo -e "${YELLOW}Note: The config file contains your password.${NC}"
echo "      Permissions set to 600 (owner read/write only)."
echo ""
