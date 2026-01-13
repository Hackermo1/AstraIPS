#!/usr/bin/env python3
"""Track device detection state across 4 enforcement stages"""

import sqlite3
import os
from datetime import datetime, timedelta
from db_connection_helper import get_db_connection

class DetectionStateTracker:
    def __init__(self, db_path=None):
        # Get database path from environment
        if db_path is None:
            # Use session.db - ONE database for EVERYTHING
            if os.environ.get('UNIFIED_DB_PATH'):
                db_path = os.environ.get('UNIFIED_DB_PATH')
            elif os.environ.get('IPS_DATA_DB_PATH'):
                db_path = os.environ.get('IPS_DATA_DB_PATH')
            else:
                session_dir = os.environ.get('SESSION_LOG_DIR', 'logs')
                BASE_LOGS_DIR = os.environ.get('BASE_LOGS_DIR', os.path.dirname(session_dir))
                if BASE_LOGS_DIR and BASE_LOGS_DIR != session_dir:
                    db_path = os.path.join(BASE_LOGS_DIR, 'session.db')
                else:
                    db_path = os.path.join(session_dir, 'session.db')
        
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create detection state table"""
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS device_detection_state (
                    mac_address TEXT PRIMARY KEY,
                    device_ip TEXT,
                    stage INTEGER DEFAULT 0,
                    detection_count INTEGER DEFAULT 0,
                    first_detection_time DATETIME,
                    last_detection_time DATETIME,
                    last_command TEXT,
                    last_threat_level TEXT,
                    blocked_until DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster lookups
            c.execute('CREATE INDEX IF NOT EXISTS idx_detection_stage ON device_detection_state(stage)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_detection_time ON device_detection_state(last_detection_time)')
    
    def record_detection(self, mac_address, device_ip, command, threat_level, detection_type):
        """
        Record detection and escalate stage
        
        Args:
            mac_address: Device MAC address
            device_ip: Device IP address
            command: Command that triggered detection
            threat_level: 'critical', 'high', 'medium', 'low'
            detection_type: 'heuristic', 'ai_alert', 'drop', 'block'
        
        Returns:
            int: Current stage (0-4)
        """
        if not mac_address:
            return 0
        
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()
            
            # Get current state
            c.execute('''
                SELECT stage, detection_count FROM device_detection_state
                WHERE mac_address = ?
            ''', (mac_address,))
            
            existing = c.fetchone()
            
            if existing:
                current_stage, detection_count = existing
                new_count = detection_count + 1
                
                # Escalate stage based on detection count
                # Stage 1: First detection (heuristic flagging)
                # Stage 2: Second detection (AI alert)
                # Stage 3: Third detection (packet drop)
                # Stage 4: Fourth+ detection (device block)
                if new_count == 1:
                    new_stage = 1
                elif new_count == 2:
                    new_stage = 2
                elif new_count == 3:
                    new_stage = 3
                elif new_count >= 4:
                    new_stage = 4
                else:
                    new_stage = current_stage
                
                # Update state
                c.execute('''
                    UPDATE device_detection_state
                    SET stage = ?,
                        detection_count = ?,
                        last_detection_time = CURRENT_TIMESTAMP,
                        last_command = ?,
                        last_threat_level = ?,
                        device_ip = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE mac_address = ?
                ''', (new_stage, new_count, command[:500] if command else None, threat_level, device_ip, mac_address))
            else:
                # First detection - Stage 1
                c.execute('''
                    INSERT INTO device_detection_state (
                        mac_address, device_ip, stage, detection_count,
                        first_detection_time, last_detection_time,
                        last_command, last_threat_level
                    ) VALUES (?, ?, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
                ''', (mac_address, device_ip, command[:500] if command else None, threat_level))
                new_stage = 1
        
        return new_stage
    
    def get_current_stage(self, mac_address):
        """Get current enforcement stage for device"""
        if not mac_address:
            return 0
        
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()
            c.execute('SELECT stage FROM device_detection_state WHERE mac_address = ?', (mac_address,))
            result = c.fetchone()
        
        return result[0] if result else 0
    
    def set_blocked(self, mac_address, duration_minutes=60):
        """Mark device as blocked for specified duration"""
        if not mac_address:
            return False
        
        blocked_until = datetime.now() + timedelta(minutes=duration_minutes)
        
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                UPDATE device_detection_state
                SET blocked_until = ?,
                    stage = 4,
                    updated_at = CURRENT_TIMESTAMP
                WHERE mac_address = ?
            ''', (blocked_until.isoformat(), mac_address))
        
        return True
    
    def is_blocked(self, mac_address):
        """Check if device is currently blocked"""
        if not mac_address:
            return False
        
        with get_db_connection(self.db_path) as conn:
            c = conn.cursor()
            c.execute('''
                SELECT blocked_until FROM device_detection_state
                WHERE mac_address = ?
            ''', (mac_address,))
            result = c.fetchone()
        
        if not result or not result[0]:
            return False
        
        try:
            blocked_until = datetime.fromisoformat(result[0])
            return datetime.now() < blocked_until
        except:
            return False

if __name__ == "__main__":
    # Test
    import sys
    tracker = DetectionStateTracker()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "get":
            mac = sys.argv[2] if len(sys.argv) > 2 else "AA:BB:CC:DD:EE:FF"
            stage = tracker.get_current_stage(mac)
            print(stage)
        elif sys.argv[1] == "record":
            mac = sys.argv[2] if len(sys.argv) > 2 else "AA:BB:CC:DD:EE:FF"
            ip = sys.argv[3] if len(sys.argv) > 3 else "192.168.1.100"
            cmd = sys.argv[4] if len(sys.argv) > 4 else "test command"
            threat = sys.argv[5] if len(sys.argv) > 5 else "high"
            det_type = sys.argv[6] if len(sys.argv) > 6 else "heuristic"
            stage = tracker.record_detection(mac, ip, cmd, threat, det_type)
            print(stage)
    else:
        # Default test
        stage = tracker.record_detection("AA:BB:CC:DD:EE:FF", "192.168.1.100", "nc -l -p 4444", "high", "heuristic")
        print(f"Stage after detection: {stage}")
