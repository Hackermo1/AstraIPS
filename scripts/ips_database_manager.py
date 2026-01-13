#!/usr/bin/env python3
"""
IPS Database Manager - Unified Database for All IPS/IDS Data
All flags, actions, heuristic flags, ML flags, MAC addresses, IPs, detection states, etc.
Everything goes into ONE database: ips_data.db
"""

import os
import sqlite3
from pathlib import Path

class IPSDatabaseManager:
    """Manages unified IPS data database"""
    
    def __init__(self, db_path=None):
        """
        Initialize IPS database manager
        
        Args:
            db_path: Path to database (default: ips_data.db in BASE_LOGS_DIR or current directory)
        """
        if db_path is None:
            # Use session.db - SAME database for everything
            if os.environ.get('UNIFIED_DB_PATH'):
                db_path = os.environ.get('UNIFIED_DB_PATH')
            elif os.environ.get('IPS_DATA_DB_PATH'):
                db_path = os.environ.get('IPS_DATA_DB_PATH')
            else:
                base_logs_dir = os.environ.get('BASE_LOGS_DIR', 'logs')
                if not os.path.exists(base_logs_dir):
                    base_logs_dir = os.getcwd()
                db_path = os.path.join(base_logs_dir, 'session.db')
        
        self.db_path = db_path
        self._ensure_directory()
        self._init_database()
        
        # Set environment variable so all components use this database
        os.environ['UNIFIED_DB_PATH'] = self.db_path  # Primary path
        os.environ['IPS_DATA_DB_PATH'] = self.db_path  # Alias for clarity
        
        print(f"✅ Unified Database (session.db) initialized: {self.db_path}")
        print(f"   📊 All flags, actions, MAC, IP, metrics in ONE database")
        print(f"   ✅ Works in both IDS and IPS modes - no data loss!")
    
    def _ensure_directory(self):
        """Ensure database directory exists"""
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    def _init_database(self):
        """Initialize all tables in IPS database"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        c = conn.cursor()
        
        # ============================================
        # DEVICE & NETWORK TABLES
        # ============================================
        
        # Device profiles (MAC, IP, device info)
        c.execute('''
            CREATE TABLE IF NOT EXISTS device_profiles (
                mac_address TEXT PRIMARY KEY,
                device_ip TEXT,
                device_name TEXT,
                device_type TEXT,
                vendor TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_connections INTEGER DEFAULT 0,
                total_messages INTEGER DEFAULT 0,
                total_commands INTEGER DEFAULT 0,
                trust_score REAL DEFAULT 50.0
            )
        ''')
        
        # IP-MAC mapping
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_mac_mapping (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                interface_name TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip_address, mac_address)
            )
        ''')
        
        # ============================================
        # FLAGS & DETECTION TABLES
        # ============================================
        
        # User flags (Heuristic + ML flags)
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT,
                device_ip TEXT,
                command TEXT NOT NULL,
                heuristic_flag TEXT,  -- 'MAL', 'NOR', 'BEN'
                ai_flag TEXT,  -- 'MAL', 'NOR', 'BEN'
                ai_verdict TEXT,  -- 'BLOCK', 'ALLOW'
                flag_category TEXT,  -- 'Scripting', 'Networking', etc.
                flag_number INTEGER,  -- Flag 2 (Scripting), Flag 9 (Networking)
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(mac_address, device_ip, command)
            )
        ''')
        
        # Detection state (4-stage enforcement)
        c.execute('''
            CREATE TABLE IF NOT EXISTS device_detection_state (
                mac_address TEXT PRIMARY KEY,
                device_ip TEXT,
                stage INTEGER DEFAULT 0,  -- 0=no detection, 1=heuristic, 2=ai_alert, 3=drop, 4=blocked
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
        
        # ============================================
        # MQTT & COMMAND TABLES
        # ============================================
        
        # MQTT traffic
        c.execute('''
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
                dup BOOLEAN
            )
        ''')
        
        # Command executions
        c.execute('''
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
        
        # AI analysis
        c.execute('''
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
        
        # ============================================
        # SECURITY TABLES
        # ============================================
        
        # Snort alerts
        c.execute('''
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
                raw_data TEXT
            )
        ''')
        
        # Security events
        c.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                test_run_timestamp TEXT,
                event_type TEXT NOT NULL,
                mac_address TEXT,
                device_ip TEXT,
                command TEXT,
                threat_level TEXT,
                detection_method TEXT,
                ai_confidence REAL,
                ai_flag TEXT,
                heuristic_flag TEXT,
                reason TEXT,
                blocked BOOLEAN DEFAULT 1,
                category TEXT
            )
        ''')
        
        # ============================================
        # SYSTEM METRICS TABLES
        # ============================================
        
        # System metrics
        c.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                ram_percent REAL,
                network_bytes_sent REAL,
                network_bytes_recv REAL
            )
        ''')
        
        # Component latency
        c.execute('''
            CREATE TABLE IF NOT EXISTS component_latency (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                component_name TEXT NOT NULL,
                operation_name TEXT,
                latency_ms REAL,
                success BOOLEAN,
                error_message TEXT
            )
        ''')
        
        # Queuing metrics
        c.execute('''
            CREATE TABLE IF NOT EXISTS queuing_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                message_queue_size INTEGER,
                message_queue_max INTEGER DEFAULT 1000,
                message_queue_utilization_percent REAL,
                message_queue_drops INTEGER DEFAULT 0,
                ai_queue_size INTEGER,
                ai_queue_max INTEGER DEFAULT 500,
                ai_queue_utilization_percent REAL,
                ai_queue_drops INTEGER DEFAULT 0,
                ai_queue_timeout_count INTEGER DEFAULT 0,
                db_queue_size INTEGER,
                db_queue_max INTEGER DEFAULT 1000,
                db_queue_utilization_percent REAL,
                db_queue_drops INTEGER DEFAULT 0,
                message_worker_active INTEGER,
                ai_worker_active INTEGER,
                db_worker_active INTEGER,
                avg_message_processing_time_ms REAL,
                avg_ai_query_time_ms REAL,
                avg_db_write_time_ms REAL,
                messages_processed_per_sec REAL,
                ai_queries_per_sec REAL,
                db_writes_per_sec REAL
            )
        ''')
        
        # MQTT protocol metrics
        c.execute('''
            CREATE TABLE IF NOT EXISTS mqtt_protocol_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                mqtt_version TEXT,
                qos0_messages INTEGER DEFAULT 0,
                qos1_messages INTEGER DEFAULT 0,
                qos2_messages INTEGER DEFAULT 0,
                qos0_percent REAL,
                qos1_percent REAL,
                qos2_percent REAL,
                retained_messages_count INTEGER DEFAULT 0,
                will_messages_count INTEGER DEFAULT 0,
                duplicate_messages_count INTEGER DEFAULT 0,
                compressed_messages_count INTEGER DEFAULT 0,
                avg_packet_size REAL,
                min_packet_size INTEGER,
                max_packet_size INTEGER
            )
        ''')
        
        # ============================================
        # INDEXES FOR PERFORMANCE
        # ============================================
        
        indexes = [
            ('idx_device_mac', 'device_profiles', 'mac_address'),
            ('idx_ip_mac_ip', 'ip_mac_mapping', 'ip_address'),
            ('idx_ip_mac_mac', 'ip_mac_mapping', 'mac_address'),
            ('idx_user_flags_mac', 'user_flags', 'mac_address'),
            ('idx_user_flags_ip', 'user_flags', 'device_ip'),
            ('idx_detection_stage', 'device_detection_state', 'stage'),
            ('idx_mqtt_traffic_mac', 'mqtt_traffic', 'source_mac'),
            ('idx_mqtt_traffic_ip', 'mqtt_traffic', 'source_ip'),
            ('idx_command_exec_mac', 'command_executions', 'device_mac'),
            ('idx_ai_analysis_mac', 'ai_analysis', 'device_mac'),
            ('idx_security_mac', 'security_events', 'mac_address'),
            ('idx_security_time', 'security_events', 'timestamp'),
            ('idx_snort_alerts_time', 'snort_alerts', 'timestamp'),
            ('idx_component_latency', 'component_latency', 'component_name'),
            ('idx_queuing_time', 'queuing_metrics', 'timestamp'),
        ]
        
        for idx_name, table, column in indexes:
            try:
                c.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({column})')
            except:
                pass  # Index may already exist
        
        conn.commit()
        conn.close()
        
        print(f"✅ All IPS tables initialized in: {self.db_path}")
    
    def get_db_path(self):
        """Get database path"""
        return self.db_path
    
    def get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path, timeout=30.0)

# Global instance
_ips_db_manager = None

def get_ips_database(db_path=None):
    """
    Get or create IPS database manager instance
    
    Args:
        db_path: Optional database path (default: ips_data.db in BASE_LOGS_DIR)
    
    Returns:
        IPSDatabaseManager instance
    """
    global _ips_db_manager
    if _ips_db_manager is None:
        _ips_db_manager = IPSDatabaseManager(db_path)
    return _ips_db_manager

if __name__ == "__main__":
    # Initialize database
    manager = get_ips_database()
    print(f"✅ IPS Database ready: {manager.get_db_path()}")
    print(f"   Environment variable set: IPS_DATA_DB_PATH={os.environ.get('IPS_DATA_DB_PATH')}")
