-- Snort3 IPS Database Schema
-- This file contains all table definitions for the IPS system

-- Device Profiles Table
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
);

-- IP-MAC Mapping Table
CREATE TABLE IF NOT EXISTS ip_mac_mapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    interface_name TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, mac_address)
);

-- User Flags Table (Heuristic + ML flags)
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
);

-- Device Detection State Table (4-stage enforcement)
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
);

-- MQTT Traffic Table
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
);

-- Command Executions Table
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
);

-- AI Analysis Table
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
);

-- Snort Alerts Table
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
);

-- Security Events Table
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
);

-- System Metrics Table
CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    cpu_percent REAL,
    ram_percent REAL,
    network_bytes_sent REAL,
    network_bytes_recv REAL
);

-- Component Latency Table
CREATE TABLE IF NOT EXISTS component_latency (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    component_name TEXT NOT NULL,
    operation_name TEXT,
    latency_ms REAL,
    success BOOLEAN,
    error_message TEXT
);

-- Queuing Metrics Table
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
);

-- MQTT Protocol Metrics Table
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
);

-- Indexes for Performance
CREATE INDEX IF NOT EXISTS idx_device_mac ON device_profiles(mac_address);
CREATE INDEX IF NOT EXISTS idx_ip_mac_ip ON ip_mac_mapping(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_mac_mac ON ip_mac_mapping(mac_address);
CREATE INDEX IF NOT EXISTS idx_user_flags_mac ON user_flags(mac_address);
CREATE INDEX IF NOT EXISTS idx_user_flags_ip ON user_flags(device_ip);
CREATE INDEX IF NOT EXISTS idx_detection_stage ON device_detection_state(stage);
CREATE INDEX IF NOT EXISTS idx_detection_time ON device_detection_state(last_detection_time);
CREATE INDEX IF NOT EXISTS idx_mqtt_traffic_mac ON mqtt_traffic(source_mac);
CREATE INDEX IF NOT EXISTS idx_mqtt_traffic_ip ON mqtt_traffic(source_ip);
CREATE INDEX IF NOT EXISTS idx_command_exec_mac ON command_executions(device_mac);
CREATE INDEX IF NOT EXISTS idx_ai_analysis_mac ON ai_analysis(device_mac);
CREATE INDEX IF NOT EXISTS idx_security_mac ON security_events(mac_address);
CREATE INDEX IF NOT EXISTS idx_security_time ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_snort_alerts_time ON snort_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_component_latency ON component_latency(component_name);
CREATE INDEX IF NOT EXISTS idx_queuing_time ON queuing_metrics(timestamp);
