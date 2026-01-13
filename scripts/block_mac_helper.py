#!/usr/bin/env python3
"""Helper to block MAC address via system_monitor"""
import sys
import os

# Add paths - use dynamic detection
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)  # Go up from scripts/ to project root
sys.path.insert(0, script_dir)
sys.path.insert(0, project_dir)

# Also try environment variable
if os.environ.get('PROJECT_DIR'):
    sys.path.insert(0, os.environ.get('PROJECT_DIR'))

try:
    from system_monitor import SystemMonitor
    mac = sys.argv[1] if len(sys.argv) > 1 else None
    if mac:
        sm = SystemMonitor()
        sm._block_mac_address(mac)
        print("BLOCKED")
    else:
        print("ERROR: No MAC provided")
except Exception as e:
    print(f"ERROR: {e}")
