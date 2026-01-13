#!/usr/bin/env python3
"""
Snort & MQTT Database Logger
Logs all Snort alerts and MQTT traffic to SQLite database
"""

import sqlite3
import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
import threading
import queue

class SnortMQTTLogger:
    def __init__(self, db_path=None):
        """
        Initialize logger with centralized session database
        
        Args:
            db_path: Path to database (default: session.db in SESSION_LOG_DIR)
        """
        # Get session directory from environment or use default
        if db_path is None:
            session_dir = os.environ.get('SESSION_LOG_DIR', '.')
            db_path = os.path.join(session_dir, 'session.db')
            # Always use session.db - no fallback to old database
        
        self.db_path = db_path
        self.conn = None
        
        # ASYNC DB LOGGING (Queueing Theory)
        # Decouple logging requests (Producer) from DB writes (Consumer)
        self.log_queue = queue.Queue()
        self.running = True
        self.worker_thread = threading.Thread(target=self.process_log_queue, daemon=True)
        self.worker_thread.start()
        
        self.setup_database()
        
    def process_log_queue(self):
        """Worker thread to process log entries sequentially with retry logic"""
        while self.running:
            try:
                # Get task from queue
                task = self.log_queue.get(timeout=1)
                
                # Unpack task
                method_name, args = task
                
                # Retry logic for robustness
                max_retries = 3
                retry_count = 0
                success = False
                
                while retry_count < max_retries and not success:
                    try:
                        # Execute the actual DB method
                        if method_name == 'log_snort_alert':
                            self._log_snort_alert_impl(args)
                        elif method_name == 'log_mqtt_traffic':
                            self._log_mqtt_traffic_impl(args)
                        elif method_name == 'log_ai_analysis':
                            self._log_ai_analysis_impl(args)
                        elif method_name == 'log_command_execution':
                            self._log_command_execution_impl(args)
                        
                        success = True
                        self.log_queue.task_done()
                        
                    except sqlite3.OperationalError as e:
                        retry_count += 1
                        if retry_count >= max_retries:
                            print(f"❌ DB Logger Error (max retries): {e}")
                            # Reconnect database
                            try:
                                self.conn.close()
                            except:
                                pass
                            self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
                            self.log_queue.task_done()  # Mark as done even if failed
                        else:
                            time.sleep(0.1 * retry_count)  # Exponential backoff
                    except Exception as e:
                        print(f"❌ DB Logger Error: {e}")
                        import traceback
                        traceback.print_exc()
                        self.log_queue.task_done()  # Mark as done even if failed
                        success = True  # Don't retry on non-db errors
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"❌ DB Logger Queue Error: {e}")
                import traceback
                traceback.print_exc()

    def setup_database(self):
        """Create database tables"""
        # Ensure directory exists and is writable
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Create database file with timeout for busy database handling
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        cursor = self.conn.cursor()
        
        # Snort alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snort_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                message TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                sid INTEGER,
                gid INTEGER,
                rev INTEGER,
                classification TEXT,
                priority INTEGER,
                raw_data TEXT,
                test_run_timestamp TEXT,
                heuristic_flag TEXT,
                ai_flag TEXT
            )
        ''')
        
        # Add columns if they don't exist (migration)
        try:
            cursor.execute('ALTER TABLE snort_alerts ADD COLUMN test_run_timestamp TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE snort_alerts ADD COLUMN heuristic_flag TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE snort_alerts ADD COLUMN ai_flag TEXT')
        except sqlite3.OperationalError:
            pass
        
        # MQTT traffic table (MAC-based tracking)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mqtt_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                packet_type TEXT,
                topic TEXT,
                payload TEXT,
                source_ip TEXT,
                source_mac TEXT,
                dest_ip TEXT,
                dest_mac TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                qos INTEGER,
                retain BOOLEAN,
                dup BOOLEAN,
                status TEXT,
                processed BOOLEAN,
                blocked BOOLEAN,
                dropped BOOLEAN,
                broadcasted BOOLEAN
            )
        ''')
        
        # Add MAC columns if they don't exist (migration)
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN source_mac TEXT')
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN dest_mac TEXT')
        except sqlite3.OperationalError:
            pass  # Column already exists
        # Add status tracking columns
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN status TEXT')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN processed BOOLEAN')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN blocked BOOLEAN')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN dropped BOOLEAN')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE mqtt_traffic ADD COLUMN broadcasted BOOLEAN')
        except sqlite3.OperationalError:
            pass
        
        # AI analysis table (MAC-based tracking)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                device_ip TEXT,
                device_mac TEXT,
                command TEXT,
                verdict TEXT,
                is_malicious BOOLEAN,
                confidence REAL,
                reason TEXT,
                user_id TEXT,
                profile_context TEXT
            )
        ''')
        
        # Add MAC column if it doesn't exist (migration)
        try:
            cursor.execute('ALTER TABLE ai_analysis ADD COLUMN device_mac TEXT')
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Command execution table (MAC-based tracking)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                device_ip TEXT,
                device_mac TEXT,
                command TEXT,
                result TEXT,
                success BOOLEAN,
                execution_time REAL,
                ai_verdict TEXT
            )
        ''')
        
        # Add MAC column if it doesn't exist (migration)
        try:
            cursor.execute('ALTER TABLE command_executions ADD COLUMN device_mac TEXT')
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_snort_timestamp ON snort_alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_mqtt_timestamp ON mqtt_traffic(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_timestamp ON ai_analysis(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_device_ip ON ai_analysis(device_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cmd_device_ip ON command_executions(device_ip)')
        
        self.conn.commit()
        print(f"✅ Database initialized: {self.db_path}")
        
    def log_snort_alert(self, alert_data):
        """Public API: Queue the alert for logging"""
        self.log_queue.put(('log_snort_alert', alert_data))
    
    def flush(self):
        """Wait for all queued logs to be processed"""
        self.log_queue.join()

    def _log_snort_alert_impl(self, alert_data):
        """Internal: Actual DB write (runs in worker thread) with transaction"""
        try:
            cursor = self.conn.cursor()
        
        # Get test_run_timestamp for unified logging
            test_run_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Check if test_run_timestamp column exists (for unified logging)
            cursor.execute("PRAGMA table_info(snort_alerts)")
            columns = [row[1] for row in cursor.fetchall()]
            has_test_run = 'test_run_timestamp' in columns
        
            if has_test_run:
                # Check for heuristic/ai columns
                has_flags = 'heuristic_flag' in columns
            
            if has_flags:
                cursor.execute('''
                    INSERT INTO snort_alerts 
                    (test_run_timestamp, alert_type, message, source_ip, dest_ip, source_port, dest_port, 
                     protocol, sid, gid, rev, classification, priority, raw_data, heuristic_flag, ai_flag)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    test_run_timestamp,
                    alert_data.get('alert_type'),
                    alert_data.get('message'),
                    alert_data.get('source_ip'),
                    alert_data.get('dest_ip'),
                    alert_data.get('source_port'),
                    alert_data.get('dest_port'),
                    alert_data.get('protocol'),
                    alert_data.get('sid'),
                    alert_data.get('gid'),
                    alert_data.get('rev'),
                    alert_data.get('classification'),
                    alert_data.get('priority'),
                    alert_data.get('raw_data'),
                    alert_data.get('heuristic_flag'),
                    alert_data.get('ai_flag')
                ))
            else:
                cursor.execute('''
                    INSERT INTO snort_alerts 
                    (test_run_timestamp, alert_type, message, source_ip, dest_ip, source_port, dest_port, 
                     protocol, sid, gid, rev, classification, priority, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    test_run_timestamp,
                    alert_data.get('alert_type'),
                    alert_data.get('message'),
                    alert_data.get('source_ip'),
                    alert_data.get('dest_ip'),
                    alert_data.get('source_port'),
                    alert_data.get('dest_port'),
                    alert_data.get('protocol'),
                    alert_data.get('sid'),
                    alert_data.get('gid'),
                    alert_data.get('rev'),
                    alert_data.get('classification'),
                    alert_data.get('priority'),
                    alert_data.get('raw_data')
                ))
                self.conn.commit()
            # Fallback for old schema
                cursor.execute('''
                INSERT INTO snort_alerts 
                (alert_type, message, source_ip, dest_ip, source_port, dest_port, 
                 protocol, sid, gid, rev, classification, priority, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                alert_data.get('alert_type'),
                alert_data.get('message'),
                alert_data.get('source_ip'),
                alert_data.get('dest_ip'),
                alert_data.get('source_port'),
                alert_data.get('dest_port'),
                alert_data.get('protocol'),
                alert_data.get('sid'),
                alert_data.get('gid'),
                alert_data.get('rev'),
                alert_data.get('classification'),
                alert_data.get('priority'),
                alert_data.get('raw_data')
                ))
                self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise
        
    def log_mqtt_traffic(self, mqtt_data):
        """Public API: Queue the traffic for logging"""
        self.log_queue.put(('log_mqtt_traffic', mqtt_data))

    def _log_mqtt_traffic_impl(self, mqtt_data):
        """Internal: Actual DB write (runs in worker thread) with transaction"""
        try:
            cursor = self.conn.cursor()
        
        # Check if MAC columns exist
            cursor.execute("PRAGMA table_info(mqtt_traffic)")
            columns = [row[1] for row in cursor.fetchall()]
            has_mac_columns = 'source_mac' in columns and 'dest_mac' in columns
        
        # Check for status columns
            cursor.execute("PRAGMA table_info(mqtt_traffic)")
            columns = [row[1] for row in cursor.fetchall()]
            has_status_columns = 'status' in columns
        
            if has_mac_columns and has_status_columns:
                # Insert with MAC addresses and status tracking
                cursor.execute('''
                INSERT INTO mqtt_traffic 
                (packet_type, topic, payload, source_ip, source_mac, dest_ip, dest_mac,
                 source_port, dest_port, qos, retain, dup, status, processed, blocked, dropped, broadcasted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mqtt_data.get('packet_type'),
                mqtt_data.get('topic'),
                mqtt_data.get('payload'),
                mqtt_data.get('source_ip'),
                mqtt_data.get('source_mac'),
                mqtt_data.get('dest_ip'),
                mqtt_data.get('dest_mac'),
                mqtt_data.get('source_port'),
                mqtt_data.get('dest_port'),
                mqtt_data.get('qos'),
                mqtt_data.get('retain'),
                mqtt_data.get('dup'),
                mqtt_data.get('status', 'received'),
                mqtt_data.get('processed', False),
                mqtt_data.get('blocked', False),
                mqtt_data.get('dropped', False),
                mqtt_data.get('broadcasted', False)
            ))
            elif has_mac_columns:
            # Insert with MAC addresses but no status columns
                cursor.execute('''
                INSERT INTO mqtt_traffic 
                (packet_type, topic, payload, source_ip, source_mac, dest_ip, dest_mac,
                 source_port, dest_port, qos, retain, dup)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mqtt_data.get('packet_type'),
                mqtt_data.get('topic'),
                mqtt_data.get('payload'),
                mqtt_data.get('source_ip'),
                mqtt_data.get('source_mac'),
                mqtt_data.get('dest_ip'),
                mqtt_data.get('dest_mac'),
                mqtt_data.get('source_port'),
                mqtt_data.get('dest_port'),
                mqtt_data.get('qos'),
                mqtt_data.get('retain'),
                mqtt_data.get('dup')
            ))
            else:
            # Fallback for old databases without MAC columns
                cursor.execute('''
                INSERT INTO mqtt_traffic 
                (packet_type, topic, payload, source_ip, dest_ip, source_port, 
                 dest_port, qos, retain, dup)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mqtt_data.get('packet_type'),
                mqtt_data.get('topic'),
                mqtt_data.get('payload'),
                mqtt_data.get('source_ip'),
            mqtt_data.get('dest_ip'),
            mqtt_data.get('source_port'),
            mqtt_data.get('dest_port'),
            mqtt_data.get('qos'),
            mqtt_data.get('retain'),
            mqtt_data.get('dup')
            ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise
        
    def log_ai_analysis(self, analysis_data):
        """Public API: Queue the analysis for logging"""
        self.log_queue.put(('log_ai_analysis', analysis_data))

    def _log_ai_analysis_impl(self, analysis_data):
        """Internal: Actual DB write (runs in worker thread) with transaction"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            INSERT INTO ai_analysis 
            (device_ip, device_mac, command, verdict, is_malicious, confidence, reason, user_id, profile_context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
            analysis_data.get('device_ip'),
            analysis_data.get('device_mac'),
            analysis_data.get('command'),
            analysis_data.get('verdict'),
            analysis_data.get('is_malicious'),
            analysis_data.get('confidence'),
            analysis_data.get('reason'),
            analysis_data.get('user_id'),
            analysis_data.get('profile_context')
            ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise
        
    def log_command_execution(self, exec_data):
        """Public API: Queue the execution for logging"""
        self.log_queue.put(('log_command_execution', exec_data))

    def _log_command_execution_impl(self, exec_data):
        """Internal: Actual DB write (runs in worker thread) with transaction"""
        try:
            cursor = self.conn.cursor()
        
        # Check if MAC column exists
            cursor.execute('''
            INSERT INTO command_executions 
            (device_ip, command, result, success, execution_time, ai_verdict)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
            exec_data.get('device_ip'),
            exec_data.get('command'),
            exec_data.get('result'),
            exec_data.get('success'),
            exec_data.get('execution_time'),
            exec_data.get('ai_verdict')
            ))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise
        
    def query(self, sql, params=None):
        """Execute query and return results"""
        cursor = self.conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        return cursor.fetchall()
        
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

# Parser for Snort alert_fast format
def parse_snort_alert_fast(line):
    """Parse Snort alert_fast format line"""
    # Actual Snort 3 format: MM/DD-HH:MM:SS.uuuuuu [**] [sid:gid:rev] "message" [**] [classification] [priority] {protocol} src_ip -> dst_ip
    # Example: 11/26-19:16:15.021610 [**] [1:9999999:1] "ICMP TEST DETECTED - Snort is working!" [**] [Priority: 0] {ICMP} fe80::ed:3941:5cf5:ac28 -> ff02::2
    
    if not line or len(line.strip()) == 0:
        return None
    
    # Try to parse Snort 3 format
    # Pattern: timestamp [**] [sid:gid:rev] "message" [**] [classification] [priority] {protocol} src -> dst
    # More flexible pattern that handles variations
    pattern1 = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+).*?\[(\d+):(\d+):(\d+)\].*?"([^"]+)".*?\{(\w+)\}\s+([^\s]+)\s+->\s+([^\s]+)'
    match1 = re.match(pattern1, line)
    
    if match1:
        timestamp_str = match1.group(1)
        sid = int(match1.group(2))
        gid = int(match1.group(3))
        rev = int(match1.group(4))
        message = match1.group(5)
        protocol = match1.group(6)
        src = match1.group(7)
        dst = match1.group(8)
        
        # Try to extract priority and classification from line
        priority_match = re.search(r'\[Priority:\s*(\d+)\]', line)
        priority = int(priority_match.group(1)) if priority_match else 0
        
        classification_match = re.search(r'\[\*\*\]\s+\[([^\]]+)\]\s+\[Priority:', line)
        classification = classification_match.group(1) if classification_match else ''
        
        # Parse source and destination (could be IP:port or just IP)
        src_ip = src.split(':')[0] if ':' in src else src
        src_port = int(src.split(':')[1]) if ':' in src and src.split(':')[1].isdigit() else 0
        
        # For IPv6, handle differently
        if '::' in src:
            src_ip = src.split(' ->')[0].strip()
            src_port = 0
        
        dst_ip = dst.split(':')[0] if ':' in dst else dst
        dst_port = int(dst.split(':')[1]) if ':' in dst and dst.split(':')[1].isdigit() else 0
        
        if '::' in dst:
                dst_ip = dst.strip()
        dst_port = 0
        
        # Convert timestamp to standard format
        try:
            # Parse MM/DD-HH:MM:SS.uuuuuu format
            # Add current year since Snort doesn't include it
            from datetime import datetime
            current_year = datetime.now().year
            timestamp_str_with_year = f"{current_year}/{timestamp_str}"
            timestamp = datetime.strptime(timestamp_str_with_year.split('.')[0], '%Y/%m/%d-%H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            timestamp = timestamp_str
        
        return {
            'timestamp': timestamp,
            'alert_type': 'alert',
            'message': message,
            'source_ip': src_ip,
            'source_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'protocol': protocol.lower(),
            'sid': sid,
            'gid': gid,
            'rev': rev,
            'classification': classification,
            'priority': priority,
            'raw_data': line
        }
    
    # Fallback: Try old format pattern
    pattern2 = r'\[(.*?)\]\s+\[(.*?)\]\s+(.*?)\s+\[(.*?):(\d+)\]\s+->\s+\[(.*?):(\d+)\]'
    match2 = re.match(pattern2, line)
    if match2:
        return {
            'timestamp': match2.group(1),
            'alert_type': match2.group(2),
            'message': match2.group(3),
            'source_ip': match2.group(4),
            'source_port': int(match2.group(5)),
            'dest_ip': match2.group(6),
            'dest_port': int(match2.group(7)),
            'raw_data': line
        }
    
    # If no match, return basic info
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'alert_type': 'alert',
        'message': line[:200],  # First 200 chars
        'source_ip': '',
        'source_port': 0,
        'dest_ip': '',
        'dest_port': 0,
        'protocol': '',
        'sid': 0,
        'gid': 0,
        'rev': 0,
        'classification': '',
        'priority': 0,
        'raw_data': line
    }

# Parser for Snort JSON alerts
def parse_snort_json(json_line):
    """Parse Snort JSON alert"""
    try:
        data = json.loads(json_line)
        return {
            'alert_type': data.get('action', 'alert'),
            'message': data.get('message', ''),
            'source_ip': data.get('src_ip', ''),
            'dest_ip': data.get('dst_ip', ''),
            'source_port': data.get('src_port', 0),
            'dest_port': data.get('dst_port', 0),
            'protocol': data.get('proto', ''),
            'sid': data.get('sid', 0),
            'gid': data.get('gid', 0),
            'rev': data.get('rev', 0),
            'classification': data.get('classification', ''),
            'priority': data.get('priority', 0),
            'raw_data': json_line
        }
    except:
        return None

if __name__ == "__main__":
    import sys
    
    # Use session.db (centralized database)
    logger = SnortMQTTLogger()
    
    print("📊 Snort & MQTT Database Logger")
    print("=" * 50)
    print(f"Database: {logger.db_path}")
    print("Ready to log data...")
    print("=" * 50)
    
    # Example: Log a test entry
    logger.log_snort_alert({
        'alert_type': 'test',
        'message': 'Database logger initialized',
        'source_ip': '127.0.0.1',
        'dest_ip': '127.0.0.1',
        'source_port': 0,
        'dest_port': 0,
        'protocol': 'tcp',
        'sid': 0,
        'gid': 0,
        'rev': 0,
        'classification': 'test',
        'priority': 0,
        'raw_data': 'test'
    })
    
    print("✅ Test entry logged")
    print("\n📋 Database tables:")
    print("  - snort_alerts: Snort IDS alerts")
    print("  - mqtt_traffic: MQTT packet data")
    print("  - ai_analysis: ML analysis results")
    print("  - command_executions: Command execution logs")
    
    logger.close()
