#!/usr/bin/env python3
"""Wrapper script to record detection for Lua inspector"""

import sys
from detection_state_tracker import DetectionStateTracker

if __name__ == "__main__":
    if len(sys.argv) < 6:
        sys.exit(1)
    
    mac_address = sys.argv[1]
    device_ip = sys.argv[2]
    command = sys.argv[3]
    threat_level = sys.argv[4]
    detection_type = sys.argv[5]
    
    tracker = DetectionStateTracker()
    stage = tracker.record_detection(mac_address, device_ip, command, threat_level, detection_type)
    print(stage)
