#!/bin/bash
# Session Summary Script - Generates dashboard after session ends

SESSION_LOG_DIR="${SESSION_LOG_DIR:-logs/LATEST_SESSION}"
DB_PATH="$SESSION_LOG_DIR/session.db"

if [ ! -f "$DB_PATH" ]; then
    echo "❌ Database not found: $DB_PATH"
    exit 1
fi

echo "📊 Generating session dashboard..."
cd "$(dirname "$0")/.."

python3 dashboard/generate_dashboard.py "$DB_PATH"

if [ $? -eq 0 ]; then
    DASHBOARD_FILE="$SESSION_LOG_DIR/dashboard/session_dashboard.html"
    echo ""
    echo "✅ Dashboard generated successfully!"
    echo "📊 Open dashboard: file://$(realpath "$DASHBOARD_FILE")"
    echo "   Or: firefox $DASHBOARD_FILE"
else
    echo "❌ Failed to generate dashboard"
    exit 1
fi
