#!/bin/bash
# =============================================================================
# Universal Path Fixer
# Replaces all hardcoded paths with universal/auto-detected paths
# Run this script after copying files to a new system
# =============================================================================

set -e

# Get the directory where this script is located (installer folder)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Project dir is parent of installer folder
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔧 Fixing hardcoded paths in all files..."
echo "   Project directory: $PROJECT_DIR"
echo ""

# Get current user's home directory
USER_HOME="$HOME"
USER_NAME="$(whoami)"

# Function to replace paths in a file
fix_paths_in_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return
    fi
    
    # Skip binary files
    if file "$file" | grep -q "executable\|binary\|data"; then
        return
    fi
    
    echo "   Fixing: $file"
    
    # Replace common hardcoded paths
    sed -i "s|/home/lujain/Desktop/snort3|$PROJECT_DIR|g" "$file" 2>/dev/null || true
    sed -i "s|/home/lujain|$USER_HOME|g" "$file" 2>/dev/null || true
    sed -i "s|/usr/local/mqttlive|$PROJECT_DIR|g" "$file" 2>/dev/null || true
    sed -i "s|/opt/snort3|$PROJECT_DIR|g" "$file" 2>/dev/null || true
    sed -i "s|/usr/local/snort3|$PROJECT_DIR|g" "$file" 2>/dev/null || true
    
    # Fix portable-config references to config
    sed -i "s|portable-config|config|g" "$file" 2>/dev/null || true
    
    # Fix pi_migration_files references to pi-deployment
    sed -i "s|pi_migration_files|pi-deployment|g" "$file" 2>/dev/null || true
    
    # Fix "router config" (with space) to "router-config" (with hyphen)
    sed -i "s|router config|router-config|g" "$file" 2>/dev/null || true
    
    # Fix ML directory references
    sed -i "s|ML related things files|ml-models|g" "$file" 2>/dev/null || true
    
    # Fix ~/snort3 references
    sed -i "s|~/snort3/|$PROJECT_DIR/|g" "$file" 2>/dev/null || true
    sed -i "s|~/snort3$|$PROJECT_DIR|g" "$file" 2>/dev/null || true
}

# Fix all shell scripts
echo "📝 Fixing shell scripts..."
find "$PROJECT_DIR" -type f \( -name "*.sh" -o -name "mqttlive" -o -name "mqttlive_pi" \) 2>/dev/null | while read -r file; do
    fix_paths_in_file "$file"
done

# Fix Lua configuration files
echo "📝 Fixing Lua configuration files..."
find "$PROJECT_DIR/config" -type f -name "*.lua" 2>/dev/null | while read -r file; do
    fix_paths_in_file "$file"
done

# Fix Python scripts
echo "📝 Fixing Python scripts..."
find "$PROJECT_DIR" -type f -name "*.py" -not -path "*/venv/*" -not -path "*/__pycache__/*" 2>/dev/null | while read -r file; do
    fix_paths_in_file "$file"
done

# Make sure key scripts are executable
echo "📝 Setting executable permissions..."
chmod +x "$PROJECT_DIR/mqttlive" 2>/dev/null || true
chmod +x "$PROJECT_DIR/snortlive.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/start_ips.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/installer/"*.sh 2>/dev/null || true

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p "$PROJECT_DIR/logs"/{exports,pcap,scans}
mkdir -p "$PROJECT_DIR/router-config/Thesis_Scans"

echo ""
echo "✅ Path fixing complete!"
echo ""
echo "📋 Summary:"
echo "   - All hardcoded paths replaced with PROJECT_DIR: $PROJECT_DIR"
echo "   - portable-config references changed to config"
echo "   - pi_migration_files references changed to pi-deployment"
echo "   - router config (space) changed to router-config (hyphen)"
echo "   - Executable permissions set"
echo ""
echo "💡 Next steps:"
echo "   1. Configure router scanning (optional): ./installer/setup_router.sh"
echo "   2. Run the IPS system: ./mqttlive"
