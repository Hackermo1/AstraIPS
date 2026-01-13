#!/usr/bin/env python3
"""Helper to determine Snort mode (IDS vs IPS) based on interface type"""

import sys
import re

def is_ethernet_interface(interface):
    """Check if interface is Ethernet type"""
    if not interface:
        return False
    
    ethernet_patterns = [
        r'^eth\d+',      # eth0, eth1
        r'^enp\d+s\d+',  # enp3s0
        r'^ens\d+',      # ens33
        r'^en\d+',       # en0
    ]
    
    for pattern in ethernet_patterns:
        if re.match(pattern, interface):
            return True
    return False

def get_snort_mode(interface):
    """Get Snort mode (ips or ids) based on interface"""
    if is_ethernet_interface(interface):
        return "ips"
    else:
        return "ids"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("ids")  # Default to IDS for safety
        sys.exit(0)
    
    interface = sys.argv[1]
    mode = get_snort_mode(interface)
    print(mode)
