#!/usr/bin/env python3
"""
Unified Logging Manager - Single-file append-based logging system
ONE session.db for all test runs, ONE log file per type (append mode)
Date/time stamps in each entry to identify test runs
"""

import os
import sqlite3
import threading
import json
from datetime import datetime
from pathlib import Path

class UnifiedLoggingManager:
    """
    Unified logging system - ONE database, ONE file per log type (append mode)
    All test runs append to the same files, identified by date/time stamps
    """
    
    def __init__(self, base_dir="logs"):
        """
        Initialize Unified Logging Manager
        
        Args:
            base_dir: Base directory for all logs (default: logs)
        """
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True, mode=0o755)
        
        # ONE database for ALL test runs
        self.db_path = os.path.join(self.base_dir, "session.db")
        
        # ONE log file per type (append mode)
        self.log_files = {
            'alert_fast': os.path.join(self.base_dir, 'alert_fast'),
            'alert_json': os.path.join(self.base_dir, 'alert_json'),
            'alert_csv': os.path.join(self.base_dir, 'alert_csv'),
            'snort_console': os.path.join(self.base_dir, 'snort_console.log'),
            'snort_alert_logger': os.path.join(self.base_dir, 'snort_alert_logger.log'),
            'pcap_capture': os.path.join(self.base_dir, 'pcap_capture.log'),
            'mqtt_router': os.path.join(self.base_dir, 'mqtt_router.log'),
            'system_monitor': os.path.join(self.base_dir, 'system_monitor.log'),
            'ai_server': os.path.join(self.base_dir, 'ai_server.log'),
            'device_profiler': os.path.join(self.base_dir, 'device_profiler.log'),
        }
        
        # File locks for thread-safe appending
        self.file_locks = {log_type: threading.Lock() for log_type in self.log_files}
        
        # Database lock for thread-safe database operations
        self.db_lock = threading.Lock()
        
        # Initialize database
        self._init_database()
        
        print(f"✅ Unified Logging Manager initialized")
        print(f"   Base directory: {self.base_dir}")
        print(f"   Database: {self.db_path} (ONE database for ALL test runs)")
        print(f"   Log files: {len(self.log_files)} files (append mode)")
    
    def _init_database(self):
        """Initialize unified database with all tables"""
        with self.db_lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            c = conn.cursor()
            
            # Snort alerts table
            c.execute('''
                CREATE TABLE IF NOT EXISTS snort_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
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
            
            # Security events table
            c.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    event_type TEXT,
                    mac_address TEXT,
                    device_ip TEXT,
                    command TEXT,
                    threat_level TEXT,
                    detection_method TEXT,
                    ai_confidence REAL,
                    ai_flag TEXT,
                    heuristic_flag TEXT,
                    reason TEXT,
                    blocked BOOLEAN
                )
            ''')
            
            # MQTT traffic table
            c.execute('''
                CREATE TABLE IF NOT EXISTS mqtt_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
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
            
            # AI analysis table
            c.execute('''
                CREATE TABLE IF NOT EXISTS ai_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
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
            
            # Command executions table
            c.execute('''
                CREATE TABLE IF NOT EXISTS command_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    device_ip TEXT,
                    device_mac TEXT,
                    command TEXT,
                    result TEXT,
                    success BOOLEAN,
                    execution_time REAL,
                    ai_verdict TEXT
                )
            ''')
            
            # Device profiles table
            c.execute('''
                CREATE TABLE IF NOT EXISTS device_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    mac_address TEXT UNIQUE NOT NULL,
                    current_ip TEXT,
                    ip_history TEXT,
                    scan_results TEXT,
                    scan_timestamp DATETIME,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    device_name TEXT
                )
            ''')
            
            # IP-MAC mapping table
            c.execute('''
                CREATE TABLE IF NOT EXISTS ip_mac_mapping (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, mac_address)
                )
            ''')
            
            # User flags table
            c.execute('''
                CREATE TABLE IF NOT EXISTS user_flags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    user_id TEXT NOT NULL,
                    device_ip TEXT,
                    mac_address TEXT,
                    command TEXT NOT NULL,
                    heuristic_flag TEXT,
                    heuristic_flag_source TEXT DEFAULT 'heuristic',
                    ai_flag TEXT,
                    ai_flag_source TEXT DEFAULT 'ai',
                    command_hash TEXT,
                    UNIQUE(user_id, command_hash)
                )
            ''')
            
            # System metrics table (EXACT MATCH with system_monitor.py schema)
            c.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    
                    -- CPU Metrics
                    cpu_percent REAL,
                    cpu_per_core TEXT,
                    cpu_count_physical INTEGER,
                    cpu_count_logical INTEGER,
                    cpu_freq_current REAL,
                    cpu_freq_min REAL,
                    cpu_freq_max REAL,
                    load_avg_1min REAL,
                    load_avg_5min REAL,
                    load_avg_15min REAL,
                    
                    -- Memory Metrics
                    ram_total REAL,
                    ram_used REAL,
                    ram_free REAL,
                    ram_available REAL,
                    ram_percent REAL,
                    ram_cached REAL,
                    ram_buffers REAL,
                    swap_total REAL,
                    swap_used REAL,
                    swap_free REAL,
                    swap_percent REAL,
                    
                    -- Process Metrics
                    process_count_total INTEGER,
                    process_count_running INTEGER,
                    process_count_sleeping INTEGER,
                    process_count_zombie INTEGER,
                    thread_count_total INTEGER,
                    
                    -- Disk Metrics
                    disk_total REAL,
                    disk_used REAL,
                    disk_free REAL,
                    disk_percent REAL,
                    disk_read_bytes REAL,
                    disk_write_bytes REAL,
                    disk_read_count INTEGER,
                    disk_write_count INTEGER,
                    
                    -- Network Metrics
                    network_bytes_sent REAL,
                    network_bytes_recv REAL,
                    network_packets_sent INTEGER,
                    network_packets_recv INTEGER,
                    network_errin INTEGER,
                    network_errout INTEGER,
                    network_dropin INTEGER,
                    network_dropout INTEGER,
                    
                    -- System Info
                    boot_time DATETIME,
                    uptime_seconds REAL,
                    
                    -- Component-Specific Metrics
                    snort_packets_processed INTEGER,
                    snort_alerts_generated INTEGER,
                    mqtt_messages_total INTEGER,
                    mqtt_connections_active INTEGER,
                    ai_queries_processed INTEGER,
                    database_queries_count INTEGER,
                    database_query_avg_latency REAL
                )
            ''')
            
            # Device metrics table
            c.execute('''
                CREATE TABLE IF NOT EXISTS device_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    mac_address TEXT,
                    device_ip TEXT,
                    mqtt_messages INTEGER,
                    commands_executed INTEGER,
                    last_seen DATETIME
                )
            ''')
            
            # MQTT connections table
            c.execute('''
                CREATE TABLE IF NOT EXISTS mqtt_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    test_run_timestamp TEXT,
                    connection_id TEXT,
                    mac_address TEXT,
                    device_ip TEXT,
                    connect_time DATETIME,
                    disconnect_time DATETIME,
                    duration_seconds REAL,
                    packets_sent INTEGER,
                    packets_received INTEGER
                )
            ''')
            
            # Topic metrics table (matches system_monitor.py schema)
            c.execute('''
                CREATE TABLE IF NOT EXISTS topic_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    topic_name TEXT NOT NULL,
                    messages_published INTEGER DEFAULT 0,
                    messages_received INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    avg_message_size REAL DEFAULT 0,
                    subscriber_count INTEGER DEFAULT 0,
                    last_publish_time DATETIME,
                    last_receive_time DATETIME
                )
            ''')
            # Create index for topic_name
            c.execute('CREATE INDEX IF NOT EXISTS idx_topic_name ON topic_metrics(topic_name)')
            
            # Component latency table (matches system_monitor.py schema)
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
            
            # Error log table (matches system_monitor.py schema)
            c.execute('''
                CREATE TABLE IF NOT EXISTS error_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    component_name TEXT NOT NULL,
                    error_type TEXT,
                    error_message TEXT,
                    error_traceback TEXT,
                    mac_address TEXT,
                    device_ip TEXT,
                    operation_name TEXT,
                    recovery_time_ms REAL,
                    resolved BOOLEAN DEFAULT 0
                )
            ''')
            
            # Create index for component_name in error_log
            c.execute('CREATE INDEX IF NOT EXISTS idx_error_component ON error_log(component_name)')
            
            # Create indexes
            c.execute('CREATE INDEX IF NOT EXISTS idx_snort_timestamp ON snort_alerts(timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_snort_test_run ON snort_alerts(test_run_timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_security_test_run ON security_events(test_run_timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_mqtt_timestamp ON mqtt_traffic(timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_mqtt_test_run ON mqtt_traffic(test_run_timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_ai_timestamp ON ai_analysis(timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_ai_test_run ON ai_analysis(test_run_timestamp)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_device_mac ON device_profiles(mac_address)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_user_flags_user ON user_flags(user_id)')
            
            conn.commit()
            conn.close()
    
    def get_test_run_timestamp(self):
        """Get current test run timestamp (for identifying test runs)"""
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def append_log(self, log_type, message, include_timestamp=True):
        """
        Thread-safe append to log file
        
        Args:
            log_type: Type of log (alert_fast, alert_json, etc.)
            message: Message to append
            include_timestamp: Whether to include timestamp prefix
        """
        if log_type not in self.log_files:
            print(f"⚠️  Unknown log type: {log_type}")
            return
        
        log_path = self.log_files[log_type]
        
        with self.file_locks[log_type]:
            try:
                with open(log_path, 'a', encoding='utf-8') as f:
                    if include_timestamp:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        test_run = self.get_test_run_timestamp()
                        f.write(f"[{timestamp}] [TEST_RUN: {test_run}] {message}\n")
                    else:
                        f.write(f"{message}\n")
                    f.flush()  # Ensure immediate write
            except Exception as e:
                print(f"⚠️  Error appending to {log_type}: {e}")
    
    def get_db_path(self):
        """Get unified database path"""
        return self.db_path
    
    def get_db_lock(self):
        """Get database lock for thread-safe operations"""
        return self.db_lock
    
    def get_log_path(self, log_type):
        """Get log file path for a specific log type"""
        return self.log_files.get(log_type)
    
    def get_base_dir(self):
        """Get base directory"""
        return self.base_dir
    
    def get_pcap_dir(self):
        """Get PCAP directory (still separate files per capture)"""
        pcap_dir = os.path.join(self.base_dir, 'pcap')
        os.makedirs(pcap_dir, exist_ok=True)
        return pcap_dir
    
    def get_exports_dir(self):
        """Get exports directory"""
        exports_dir = os.path.join(self.base_dir, 'exports')
        os.makedirs(exports_dir, exist_ok=True)
        return exports_dir
    
    def get_scans_dir(self):
        """Get scans directory"""
        scans_dir = os.path.join(self.base_dir, 'scans')
        os.makedirs(scans_dir, exist_ok=True)
        return scans_dir


# Global instance
_unified_logger = None
_unified_logger_lock = threading.Lock()

def get_unified_logger(base_dir=None):
    """Get global unified logger instance (singleton)"""
    global _unified_logger
    if _unified_logger is None:
        with _unified_logger_lock:
            if _unified_logger is None:
                _unified_logger = UnifiedLoggingManager(base_dir=base_dir or "logs")
    return _unified_logger
