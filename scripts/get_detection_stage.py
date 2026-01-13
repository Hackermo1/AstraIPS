#!/usr/bin/env python3
"""Wrapper script to get detection stage for Lua inspector"""

import sys
from detection_state_tracker import DetectionStateTracker

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("0")
        sys.exit(0)
    
    mac_address = sys.argv[1]
    tracker = DetectionStateTracker()
    stage = tracker.get_current_stage(mac_address)
    print(stage)
