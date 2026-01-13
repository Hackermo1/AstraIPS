#!/usr/bin/env python3
"""Manage device blocking at gateway level using iptables MAC filtering"""

import subprocess
import sys
import os
from detection_state_tracker import DetectionStateTracker

def block_device_mac(mac_address, duration_minutes=60):
    """Block device using iptables MAC filtering"""
    try:
        # Check if rule already exists
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-m', 'mac', 
                     '--mac-source', mac_address, '-j', 'DROP']
        result = subprocess.run(check_cmd, capture_output=True, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            print(f"⚠️  Device {mac_address} already blocked")
            return True
        
        # Add blocking rule
        block_cmd = ['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac',
                     '--mac-source', mac_address, '-j', 'DROP']
        result = subprocess.run(block_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"🔒 Device {mac_address} blocked at gateway level for {duration_minutes} minutes")
            
            # Update database
            tracker = DetectionStateTracker()
            tracker.set_blocked(mac_address, duration_minutes)
            
            return True
        else:
            print(f"❌ Failed to block device: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error blocking device: {e}")
        return False

def unblock_device_mac(mac_address):
    """Remove iptables blocking rule"""
    try:
        # Try to remove rule (may not exist)
        unblock_cmd = ['sudo', 'iptables', '-D', 'INPUT', '-m', 'mac',
                       '--mac-source', mac_address, '-j', 'DROP']
        result = subprocess.run(unblock_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0:
            print(f"✅ Device {mac_address} unblocked")
            return True
        else:
            # Rule may not exist, that's okay
            print(f"⚠️  Blocking rule not found for {mac_address}")
            return False
    except Exception as e:
        print(f"❌ Error unblocking device: {e}")
        return False

def is_device_blocked(mac_address):
    """Check if device is currently blocked in iptables"""
    try:
        check_cmd = ['sudo', 'iptables', '-C', 'INPUT', '-m', 'mac',
                     '--mac-source', mac_address, '-j', 'DROP']
        result = subprocess.run(check_cmd, capture_output=True, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: gateway_block_manager.py [block|unblock|check] MAC_ADDRESS [duration_minutes]")
        sys.exit(1)
    
    action = sys.argv[1]
    mac_address = sys.argv[2]
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    
    if action == "block":
        success = block_device_mac(mac_address, duration)
        sys.exit(0 if success else 1)
    elif action == "unblock":
        success = unblock_device_mac(mac_address)
        sys.exit(0 if success else 1)
    elif action == "check":
        blocked = is_device_blocked(mac_address)
        print("1" if blocked else "0")
        sys.exit(0)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)
