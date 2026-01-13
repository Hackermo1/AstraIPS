#!/usr/bin/env python3
"""
Snort DAQ Helper - Selects correct DAQ mode based on Snort mode (IDS vs IPS)
- IDS Mode: pcap DAQ (passive, alert only)
- IPS Mode: afpacket DAQ (inline, can drop packets)
"""

import sys
import os

def get_daq_mode(snort_mode, interface=None):
    """
    Get appropriate DAQ mode based on Snort mode
    
    Args:
        snort_mode: 'ids' or 'ips'
        interface: Optional interface name (for fallback detection)
    
    Returns:
        str: 'pcap' for IDS, 'afpacket' for IPS
    """
    # If mode is explicitly IPS, use afpacket (inline mode)
    if snort_mode == "ips":
        return "afpacket"
    
    # Default to pcap (passive mode) for IDS
    return "pcap"

def check_daq_available(daq_mode):
    """
    Check if DAQ module is available
    
    Args:
        daq_mode: 'pcap' or 'afpacket'
    
    Returns:
        bool: True if DAQ is available
    """
    if daq_mode == "pcap":
        # pcap DAQ is always available (built-in)
        return True
    elif daq_mode == "afpacket":
        # Check if afpacket DAQ module exists
        possible_paths = [
            "/usr/local/lib/daq/daq_afpacket.so",
            "/usr/lib/daq/daq_afpacket.so",
            "/usr/lib64/daq/daq_afpacket.so",
        ]
        return any(os.path.exists(path) for path in possible_paths)
    
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("pcap")  # Default to pcap (IDS mode)
        sys.exit(0)
    
    snort_mode = sys.argv[1].lower()
    interface = sys.argv[2] if len(sys.argv) > 2 else None
    
    daq_mode = get_daq_mode(snort_mode, interface)
    
    # Check if DAQ is available, fallback to pcap if not
    if not check_daq_available(daq_mode):
        if daq_mode == "afpacket":
            print("pcap", file=sys.stderr)  # Fallback to pcap
            print("⚠️  afpacket DAQ not available, falling back to pcap DAQ", file=sys.stderr)
        daq_mode = "pcap"
    
    print(daq_mode)
