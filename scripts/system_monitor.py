#!/usr/bin/env python3
"""
Comprehensive System Monitoring Script
Tracks RAM, CPU, throughput, latency, and all system metrics per user/device
"""

import os
import sys
import time
import sqlite3
import psutil
import threading
import json
import subprocess
import socket
from datetime import datetime
from collections import defaultdict

class SystemMonitor:
    def __init__(self, db_path=None, interval=5):
        """
        Initialize system monitor
        
        Args:
            db_path: Path to database (defaults to session.db - ALL metrics in one DB)
            interval: Collection interval in seconds (default: 5)
        """
        # Get session directory - use SESSION.DB (centralized database)
        session_dir = os.environ.get('SESSION_LOG_DIR', 'logs')
        # Validate session_dir is not empty
        if not session_dir or session_dir.strip() == '':
            session_dir = 'logs'
        if db_path is None:
            # Use the SAME session.db as everything else - ONE DATABASE FOR ALL METRICS
            db_path = os.path.join(session_dir, 'session.db')
        
        # Ensure directory exists
        if session_dir and session_dir.strip():
            # Use session_dir directly instead of os.path.dirname to avoid empty path issues
            os.makedirs(session_dir, exist_ok=True)
        
        self.db_path = db_path
        self.interval = interval
        self.running = False
        self.monitor_thread = None
        self.lock = threading.Lock()
        self.blocking_lock = threading.Lock()  # Lock for blocking operations
        
        # Initialize database
        self._init_database()
        
        # Restore blocks from database
        self._restore_blocks()
        
        # Track per-device metrics
        self.device_metrics = defaultdict(lambda: {
            'mqtt_messages': 0,
            'commands_executed': 0,
            'last_seen': None
        })
        
        # Track active connections
        self.active_connections = {}  # connection_id -> {mac_address, device_ip, connect_time, ...}
        
        # Track command patterns
        self.command_patterns_cache = defaultdict(lambda: {
            'count': 0,
            'success': 0,
            'failure': 0,
            'total_time': 0.0
        })
        
        print(f"   Database: {self.db_path} (ALL metrics in ONE database)")
        print(f"   Interval: {self.interval}s")
        
        # Topology tracking
        self.last_topology_state = {}
        self.last_topology_check = 0
        self.topology_check_interval = 10  # Check every 10 seconds
        self.last_heartbeat_time = 0
        self.heartbeat_interval = 60  # Log heartbeat every 60 seconds
    
    def _ensure_protocol_metrics_entry(self):
        """Ensure mqtt_protocol_metrics has at least one entry"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute('SELECT COUNT(*) FROM mqtt_protocol_metrics')
            count = c.fetchone()[0]
            if count == 0:
                # Create initial entry
                c.execute('''
                    INSERT INTO mqtt_protocol_metrics (
                        mqtt_version, qos0_messages, qos1_messages, qos2_messages,
                        qos0_percent, qos1_percent, qos2_percent,
                        retained_messages_count, will_messages_count,
                        duplicate_messages_count, compressed_messages_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (None, 0, 0, 0, 0.0, 0.0, 0.0, 0, 0, 0, 0))
                conn.commit()
                print("✅ Created initial mqtt_protocol_metrics entry")
        except Exception as e:
            print(f"⚠️  Error ensuring protocol metrics entry: {e}")
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize metrics database with comprehensive schema"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # System-wide metrics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                -- CPU Metrics
                cpu_percent REAL,
                cpu_per_core TEXT,  -- JSON array of per-core percentages
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
        
        # Per-device/user metrics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS device_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                mac_address TEXT NOT NULL,
                device_ip TEXT,
                
                -- Device Activity
                mqtt_messages_count INTEGER DEFAULT 0,
                commands_executed_count INTEGER DEFAULT 0,
                ai_queries_count INTEGER DEFAULT 0,
                snort_alerts_count INTEGER DEFAULT 0,
                
                -- Network Activity (per device)
                bytes_sent REAL DEFAULT 0,
                bytes_received REAL DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                
                -- Resource Usage (estimated per device)
                cpu_time_used REAL DEFAULT 0,
                memory_bytes_used REAL DEFAULT 0,
                
                -- Latency Metrics
                avg_response_latency_ms REAL,
                min_response_latency_ms REAL,
                max_response_latency_ms REAL,
                
                -- Throughput
                messages_per_second REAL,
                commands_per_second REAL,
                
                FOREIGN KEY (mac_address) REFERENCES device_profiles(mac_address)
            )
        ''')
        
        # Process-specific metrics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS process_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                process_name TEXT NOT NULL,
                pid INTEGER,
                
                -- CPU
                cpu_percent REAL,
                cpu_times_user REAL,
                cpu_times_system REAL,
                
                -- Memory
                memory_rss REAL,
                memory_vms REAL,
                memory_percent REAL,
                memory_available REAL,
                
                -- Threads
                num_threads INTEGER,
                
                -- I/O
                io_read_bytes REAL,
                io_write_bytes REAL,
                io_read_count INTEGER,
                io_write_count INTEGER,
                
                -- Network (if applicable)
                connections_count INTEGER,
                
                -- Status
                status TEXT,
                create_time REAL
            )
        ''')
        
        # Network interface metrics table (enhanced with physical properties)
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_interface_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                interface_name TEXT NOT NULL,
                
                -- Traffic Statistics
                bytes_sent REAL,
                bytes_recv REAL,
                packets_sent INTEGER,
                packets_recv INTEGER,
                errin INTEGER,
                errout INTEGER,
                dropin INTEGER,
                dropout INTEGER,
                
                -- Physical Link Properties
                speed INTEGER,  -- Link speed in Mbps
                duplex TEXT,  -- 'full', 'half', or None
                mtu INTEGER,  -- Maximum Transmission Unit
                isup BOOLEAN,  -- Interface is up
                carrier BOOLEAN,  -- Carrier detected
                
                -- Link Capacity & Utilization
                link_capacity_mbps REAL,  -- Theoretical max capacity
                utilization_percent REAL,  -- Current utilization percentage
                bandwidth_used_mbps REAL,  -- Current bandwidth usage
                
                -- Physical Errors
                collisions INTEGER,
                carrier_errors INTEGER,
                crc_errors INTEGER,
                frame_errors INTEGER,
                overrun_errors INTEGER,
                
                -- Interface Flags
                is_loopback BOOLEAN,
                is_wireless BOOLEAN,
                is_ethernet BOOLEAN,
                promiscuous_mode BOOLEAN
            )
        ''')
        
        # Network protocol distribution table
        c.execute('''
            CREATE TABLE IF NOT EXISTS protocol_distribution (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                interface_name TEXT,
                
                tcp_packets INTEGER DEFAULT 0,
                udp_packets INTEGER DEFAULT 0,
                icmp_packets INTEGER DEFAULT 0,
                other_packets INTEGER DEFAULT 0,
                
                tcp_bytes REAL DEFAULT 0,
                udp_bytes REAL DEFAULT 0,
                icmp_bytes REAL DEFAULT 0,
                other_bytes REAL DEFAULT 0,
                
                tcp_percent REAL,
                udp_percent REAL,
                icmp_percent REAL,
                other_percent REAL
            )
        ''')
        
        # TCP connection states table
        c.execute('''
            CREATE TABLE IF NOT EXISTS tcp_connection_states (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                established_count INTEGER DEFAULT 0,
                syn_sent_count INTEGER DEFAULT 0,
                syn_recv_count INTEGER DEFAULT 0,
                fin_wait1_count INTEGER DEFAULT 0,
                fin_wait2_count INTEGER DEFAULT 0,
                time_wait_count INTEGER DEFAULT 0,
                close_count INTEGER DEFAULT 0,
                close_wait_count INTEGER DEFAULT 0,
                last_ack_count INTEGER DEFAULT 0,
                listen_count INTEGER DEFAULT 0,
                closing_count INTEGER DEFAULT 0,
                
                total_connections INTEGER DEFAULT 0
            )
        ''')
        
        # Port usage statistics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS port_usage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,  -- 'tcp' or 'udp'
                
                connection_count INTEGER DEFAULT 0,
                bytes_sent REAL DEFAULT 0,
                bytes_received REAL DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                
                is_listening BOOLEAN DEFAULT 0,
                service_name TEXT,  -- Detected service name
                
                UNIQUE(port_number, protocol, timestamp)
            )
        ''')
        
        # Network topology changes table
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_topology_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                change_type TEXT NOT NULL,  -- 'interface_added', 'interface_removed', 'interface_state_change', 'ip_change'
                interface_name TEXT,
                old_state TEXT,
                new_state TEXT,
                old_ip TEXT,
                new_ip TEXT,
                mac_address TEXT,
                
                description TEXT
            )
        ''')
        
        # ARP table tracking
        c.execute('''
            CREATE TABLE IF NOT EXISTS arp_table_snapshot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                ip_address TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                interface_name TEXT,
                arp_type TEXT,  -- 'static', 'dynamic', 'permanent'
                
                UNIQUE(ip_address, mac_address, timestamp)
            )
        ''')
        
        # Network performance metrics
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                interface_name TEXT,
                
                -- Latency Metrics
                avg_latency_ms REAL,
                min_latency_ms REAL,
                max_latency_ms REAL,
                packet_loss_percent REAL,
                
                -- Throughput Metrics
                throughput_mbps REAL,
                goodput_mbps REAL,  -- Effective throughput excluding retransmissions
                
                -- Quality Metrics
                jitter_ms REAL,  -- Packet delay variation
                reorder_percent REAL,  -- Out-of-order packets
                duplicate_percent REAL,  -- Duplicate packets
                
                -- TCP-specific
                tcp_retransmissions INTEGER,
                tcp_retransmission_rate REAL,
                tcp_window_size_avg REAL,
                
                -- UDP-specific
                udp_loss_count INTEGER,
                udp_loss_rate REAL
            )
        ''')
        
        # MQTT protocol-specific metrics (enhanced)
        c.execute('''
            CREATE TABLE IF NOT EXISTS mqtt_protocol_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                -- Protocol Version
                mqtt_version TEXT,  -- '3.1', '3.1.1', '5.0'
                
                -- QoS Distribution
                qos0_messages INTEGER DEFAULT 0,
                qos1_messages INTEGER DEFAULT 0,
                qos2_messages INTEGER DEFAULT 0,
                qos0_percent REAL,
                qos1_percent REAL,
                qos2_percent REAL,
                
                -- Message Flags
                retained_messages_count INTEGER DEFAULT 0,
                will_messages_count INTEGER DEFAULT 0,
                duplicate_messages_count INTEGER DEFAULT 0,
                
                -- Compression
                compressed_messages_count INTEGER DEFAULT 0,
                compression_ratio REAL,  -- Compressed size / Original size
                
                -- Connection Quality
                clean_session_count INTEGER DEFAULT 0,
                persistent_session_count INTEGER DEFAULT 0,
                keep_alive_violations INTEGER DEFAULT 0,
                
                -- Packet Size Distribution
                avg_packet_size REAL,
                min_packet_size INTEGER,
                max_packet_size INTEGER,
                large_packet_count INTEGER DEFAULT 0  -- Packets > 1KB
            )
        ''')
        
        # Network security events (enhanced)
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                event_type TEXT NOT NULL,  -- 'port_scan', 'syn_flood', 'ddos', 'unusual_protocol', 'arp_spoofing'
                source_ip TEXT,
                dest_ip TEXT,
                source_mac TEXT,
                dest_mac TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                
                severity TEXT,  -- 'low', 'medium', 'high', 'critical'
                packet_count INTEGER,
                duration_seconds REAL,
                description TEXT,
                
                blocked BOOLEAN DEFAULT 0
            )
        ''')
        
        # Component latency tracking table
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
        
        # MQTT Connection Lifecycle table
        c.execute('''
            CREATE TABLE IF NOT EXISTS mqtt_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                device_ip TEXT,
                source_port INTEGER,
                connect_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                disconnect_time DATETIME,
                connection_duration_seconds REAL,
                disconnect_reason TEXT,
                messages_sent INTEGER DEFAULT 0,
                messages_received INTEGER DEFAULT 0,
                topics_subscribed TEXT,  -- JSON array
                is_reconnection BOOLEAN DEFAULT 0
            )
        ''')
        
        # Security Events table
        c.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,  -- 'blocked_command', 'threat_detected', 'suspicious_behavior'
                mac_address TEXT,
                device_ip TEXT,
                command TEXT,
                threat_level TEXT,  -- 'low', 'medium', 'high', 'critical'
                detection_method TEXT,  -- 'heuristic', 'ai', 'both'
                ai_confidence REAL,
                heuristic_flag TEXT,
                ai_flag TEXT,
                reason TEXT,
                blocked BOOLEAN DEFAULT 1
            )
        ''')
        
        # Command Patterns table (what commands each device runs)
        c.execute('''
            CREATE TABLE IF NOT EXISTS command_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                mac_address TEXT NOT NULL,
                device_ip TEXT,
                command TEXT NOT NULL,
                command_hash TEXT,
                execution_count INTEGER DEFAULT 1,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                avg_execution_time_ms REAL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_suspicious BOOLEAN DEFAULT 0,
                UNIQUE(mac_address, command_hash)
            )
        ''')
        
        # Error Tracking table
        c.execute('''
            CREATE TABLE IF NOT EXISTS error_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                component_name TEXT NOT NULL,
                error_type TEXT,  -- 'timeout', 'connection', 'parsing', 'execution', 'database'
                error_message TEXT,
                error_traceback TEXT,
                mac_address TEXT,
                device_ip TEXT,
                operation_name TEXT,
                recovery_time_ms REAL,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Topic Metrics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS topic_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                topic_name TEXT NOT NULL,
                subscriber_count INTEGER DEFAULT 0,
                messages_published INTEGER DEFAULT 0,
                messages_received INTEGER DEFAULT 0,
                total_bytes_sent REAL DEFAULT 0,
                total_bytes_received REAL DEFAULT 0,
                avg_message_size REAL,
                last_message_time DATETIME,
                is_wildcard BOOLEAN DEFAULT 0  -- Contains # or +
            )
        ''')
        
        # Device Behavior Profile table
        c.execute('''
            CREATE TABLE IF NOT EXISTS device_behavior_profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                device_ip TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_connections INTEGER DEFAULT 0,
                total_messages INTEGER DEFAULT 0,
                total_commands INTEGER DEFAULT 0,
                avg_connection_duration REAL,
                avg_messages_per_session REAL,
                peak_usage_hour INTEGER,  -- Hour of day (0-23)
                typical_topics TEXT,  -- JSON array
                typical_commands TEXT,  -- JSON array
                trust_score REAL DEFAULT 50.0,  -- 0-100
                anomaly_count INTEGER DEFAULT 0,
                last_anomaly_time DATETIME
            )
        ''')
        
        # Create indexes for performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_mqtt_conn_mac ON mqtt_connections(mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_mqtt_conn_time ON mqtt_connections(connect_time)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_security_mac ON security_events(mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_security_time ON security_events(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_cmd_patterns_mac ON command_patterns(mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_error_component ON error_log(component_name)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_topic_name ON topic_metrics(topic_name)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_device_behavior_mac ON device_behavior_profile(mac_address)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_network_if_name ON network_interface_metrics(interface_name)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_protocol_time ON protocol_distribution(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_port_usage ON port_usage_stats(port_number)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_network_security_time ON network_security_events(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_arp_ip ON arp_table_snapshot(ip_address)')
        
        conn.commit()
        conn.close()
        
        # Ensure protocol metrics has initial entry
        self._ensure_protocol_metrics_entry()
        print(f"✅ All metrics tables initialized in: {self.db_path}")
        print(f"   📊 CPU, RAM, Network, Physical, Security - ALL in ONE database")
    
    def _restore_blocks(self):
        """Restore blocking rules from database on startup"""
        try:
            print("🔄 Restoring blocked devices from database...")
            conn = sqlite3.connect(self.db_path, timeout=5)
            c = conn.cursor()
            
            # Check if security_events table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
            if not c.fetchone():
                return

            # Get all blocked MACs
            c.execute('''
                SELECT DISTINCT mac_address, device_ip 
                FROM security_events 
                WHERE blocked = 1 AND event_type = 'mac_blocked'
            ''')
            
            blocked_devices = c.fetchall()
            conn.close()
            
            count = 0
            for mac, ip in blocked_devices:
                if mac and mac != 'N/A':
                    # Use the existing blocking function to re-apply rules
                    # This handles iptables checks and redundancy
                    print(f"   Restoring block for MAC: {mac} (IP: {ip})")
                    self._block_mac_address(mac, ip)
                    count += 1
            
            print(f"✅ Restored {count} blocked devices")
            
        except Exception as e:
            print(f"⚠️  Error restoring blocks: {e}")

    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            print(f"🚀 System Monitor started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("🛑 System Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._collect_system_metrics()
                self._collect_process_metrics()
                self._collect_network_interface_metrics()  # Includes TCP states, protocols, ports, ARP
                self._collect_topology_changes()  # Track network changes
                self.update_device_metrics()  # Update device metrics periodically
                self.update_topic_metrics()   # Update topic metrics periodically
                time.sleep(self.interval)
            except Exception as e:
                print(f"❌ Error in monitor loop: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(self.interval)
    
    def _collect_system_metrics(self):
        """Collect system-wide metrics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # CPU Metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            cpu_count_physical = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            # Memory Metrics
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Process Metrics
            process_count = len(psutil.pids())
            processes = psutil.process_iter(['pid', 'status'])
            status_counts = defaultdict(int)
            thread_count = 0
            
            for proc in processes:
                try:
                    status_counts[proc.info['status']] += 1
                    thread_count += proc.num_threads()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Disk Metrics
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network Metrics
            net_io = psutil.net_io_counters()
            
            # System Info
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = time.time() - psutil.boot_time()
            
            # Component-specific metrics (from database if available)
            snort_packets = self._get_snort_packets_count()
            snort_alerts = self._get_snort_alerts_count()
            mqtt_messages = self._get_mqtt_messages_count()
            mqtt_connections = self._get_mqtt_connections_count()
            ai_queries = self._get_ai_queries_count()
            db_queries, db_latency = self._get_database_stats()
            
            # Insert system metrics
            c.execute('''
                INSERT INTO system_metrics (
                    cpu_percent, cpu_per_core, cpu_count_physical, cpu_count_logical,
                    cpu_freq_current, cpu_freq_min, cpu_freq_max,
                    load_avg_1min, load_avg_5min, load_avg_15min,
                    ram_total, ram_used, ram_free, ram_available, ram_percent,
                    ram_cached, ram_buffers,
                    swap_total, swap_used, swap_free, swap_percent,
                    process_count_total, process_count_running, process_count_sleeping,
                    process_count_zombie, thread_count_total,
                    disk_total, disk_used, disk_free, disk_percent,
                    disk_read_bytes, disk_write_bytes, disk_read_count, disk_write_count,
                    network_bytes_sent, network_bytes_recv,
                    network_packets_sent, network_packets_recv,
                    network_errin, network_errout, network_dropin, network_dropout,
                    boot_time, uptime_seconds,
                    snort_packets_processed, snort_alerts_generated,
                    mqtt_messages_total, mqtt_connections_active,
                    ai_queries_processed, database_queries_count, database_query_avg_latency
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cpu_percent, json.dumps(cpu_per_core), cpu_count_physical, cpu_count_logical,
                cpu_freq.current if cpu_freq else 0, cpu_freq.min if cpu_freq else 0, cpu_freq.max if cpu_freq else 0,
                load_avg[0], load_avg[1], load_avg[2],
                mem.total, mem.used, mem.free, mem.available, mem.percent,
                getattr(mem, 'cached', 0), getattr(mem, 'buffers', 0),
                swap.total, swap.used, swap.free, swap.percent,
                process_count, status_counts.get('running', 0), status_counts.get('sleeping', 0),
                status_counts.get('zombie', 0), thread_count,
                disk.total, disk.used, disk.free, disk.percent,
                disk_io.read_bytes if disk_io else 0, disk_io.write_bytes if disk_io else 0,
                disk_io.read_count if disk_io else 0, disk_io.write_count if disk_io else 0,
                net_io.bytes_sent if net_io else 0, net_io.bytes_recv if net_io else 0,
                net_io.packets_sent if net_io else 0, net_io.packets_recv if net_io else 0,
                net_io.errin if net_io else 0, net_io.errout if net_io else 0,
                net_io.dropin if net_io else 0, net_io.dropout if net_io else 0,
                boot_time, uptime,
                snort_packets, snort_alerts,
                mqtt_messages, mqtt_connections,
                ai_queries, db_queries, db_latency
            ))
            
            conn.commit()
        except Exception as e:
            print(f"❌ Error collecting system metrics: {e}")
        finally:
            conn.close()
    
    def _collect_process_metrics(self):
        """Collect metrics for specific processes"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Monitor key processes
        key_processes = ['snort', 'mosquitto', 'python3', 'mqtt_router', 'ai_decision_server']
        
        for proc_name in key_processes:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 
                                                  'num_threads', 'io_counters', 'connections', 
                                                  'status', 'create_time']):
                    try:
                        if proc_name.lower() in proc.info['name'].lower():
                            proc_info = proc.info
                            
                            # Get CPU times
                            cpu_times = proc.cpu_times()
                            
                            # Get memory info
                            mem_info = proc_info.get('memory_info')
                            
                            # Get I/O counters
                            io_counters = proc_info.get('io_counters')
                            
                            # Get connections
                            connections = proc_info.get('connections')
                            
                            # Process memory doesn't have 'available' attribute - use 0
                            memory_available = 0  # Process memory doesn't have available attribute
                            
                            c.execute('''
                                INSERT INTO process_metrics (
                                    process_name, pid, cpu_percent,
                                    cpu_times_user, cpu_times_system,
                                    memory_rss, memory_vms, memory_percent, memory_available,
                                    num_threads,
                                    io_read_bytes, io_write_bytes, io_read_count, io_write_count,
                                    connections_count, status, create_time
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                proc_name, proc_info['pid'], proc.cpu_percent(interval=0.1),
                                cpu_times.user, cpu_times.system,
                                mem_info.rss if mem_info else 0, mem_info.vms if mem_info else 0,
                                proc.memory_percent(), memory_available,
                                proc_info.get('num_threads', 0),
                                io_counters.read_bytes if io_counters else 0,
                                io_counters.write_bytes if io_counters else 0,
                                io_counters.read_count if io_counters else 0,
                                io_counters.write_count if io_counters else 0,
                                len(connections) if connections else 0,
                                proc_info.get('status', 'unknown'),
                                proc_info.get('create_time', 0)
                            ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except Exception as e:
                print(f"⚠️  Error collecting metrics for {proc_name}: {e}")
        
        conn.commit()
        conn.close()
    
    def _collect_network_interface_metrics(self):
        """Collect comprehensive metrics per network interface including physical properties"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            net_io = psutil.net_io_counters(pernic=True)
            net_if_stats = psutil.net_if_stats()
            net_if_addrs = psutil.net_if_addrs()
            
            for interface_name, stats in net_io.items():
                if_stats = net_if_stats.get(interface_name)
                if_addrs = net_if_addrs.get(interface_name, [])
                
                # Get physical properties
                speed = if_stats.speed if if_stats else 0
                mtu = if_stats.mtu if if_stats else 1500
                isup = if_stats.isup if if_stats else False
                
                # Determine duplex mode (requires ethtool or system-specific call)
                duplex = self._get_duplex_mode(interface_name)
                
                # Check if carrier is present
                carrier = if_stats.isup if if_stats else False
                
                # Calculate link capacity and utilization
                link_capacity_mbps = speed if speed > 0 else 1000  # Default to 1Gbps if unknown
                
                # Calculate bandwidth used (bytes per second over interval)
                # Note: This is approximate, actual calculation needs previous values
                bandwidth_used_mbps = 0  # Will be calculated if we track deltas
                utilization_percent = 0  # Will be calculated
                
                # Determine interface type
                is_loopback = interface_name.startswith('lo')
                is_wireless = 'wlan' in interface_name.lower() or 'wifi' in interface_name.lower() or 'wlx' in interface_name.lower()
                is_ethernet = 'eth' in interface_name.lower() or 'enp' in interface_name.lower() or 'ens' in interface_name.lower()
                
                # Get promiscuous mode (requires root, approximate check)
                promiscuous_mode = False  # Would need root to check properly
                
                # Physical errors (from stats if available)
                collisions = getattr(stats, 'collisions', 0) if hasattr(stats, 'collisions') else 0
                carrier_errors = 0  # Would need system-specific calls
                crc_errors = 0  # Would need system-specific calls
                frame_errors = 0  # Would need system-specific calls
                overrun_errors = stats.dropin + stats.dropout  # Approximate
                
                c.execute('''
                    INSERT INTO network_interface_metrics (
                        interface_name, bytes_sent, bytes_recv,
                        packets_sent, packets_recv,
                        errin, errout, dropin, dropout,
                        speed, duplex, mtu, isup, carrier,
                        link_capacity_mbps, utilization_percent, bandwidth_used_mbps,
                        collisions, carrier_errors, crc_errors, frame_errors, overrun_errors,
                        is_loopback, is_wireless, is_ethernet, promiscuous_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    interface_name, stats.bytes_sent, stats.bytes_recv,
                    stats.packets_sent, stats.packets_recv,
                    stats.errin, stats.errout, stats.dropin, stats.dropout,
                    speed, duplex, mtu, isup, carrier,
                    link_capacity_mbps, utilization_percent, bandwidth_used_mbps,
                    collisions, carrier_errors, crc_errors, frame_errors, overrun_errors,
                    is_loopback, is_wireless, is_ethernet, promiscuous_mode
                ))
            
            # Collect TCP connection states
            self._collect_tcp_connection_states(c)
            
            # Collect protocol distribution (approximate from connections)
            self._collect_protocol_distribution(c)
            
            # Collect port usage statistics
            self._collect_port_usage_stats(c)
            
            # Collect ARP table snapshot
            self._collect_arp_table_snapshot(c)
            
            conn.commit()
        except Exception as e:
            print(f"⚠️  Error collecting network interface metrics: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def _get_duplex_mode(self, interface_name):
        """Get duplex mode for interface (requires system command)"""
        try:
            # Try to get duplex mode using ethtool (Linux)
            result = subprocess.run(
                ['ethtool', interface_name],
                capture_output=True,
                text=True,
                timeout=2
            )
            if 'Full duplex' in result.stdout:
                return 'full'
            elif 'Half duplex' in result.stdout:
                return 'half'
        except:
            pass
        return None
    
    def _collect_tcp_connection_states(self, c):
        """Collect TCP connection state distribution"""
        try:
            connections = psutil.net_connections(kind='tcp')
            state_counts = defaultdict(int)
            
            for conn in connections:
                state = conn.status
                state_counts[state] += 1
            
            total = len(connections)
            
            c.execute('''
                INSERT INTO tcp_connection_states (
                    established_count, syn_sent_count, syn_recv_count,
                    fin_wait1_count, fin_wait2_count, time_wait_count,
                    close_count, close_wait_count, last_ack_count,
                    listen_count, closing_count, total_connections
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                state_counts.get('ESTABLISHED', 0),
                state_counts.get('SYN_SENT', 0),
                state_counts.get('SYN_RECV', 0),
                state_counts.get('FIN_WAIT1', 0),
                state_counts.get('FIN_WAIT2', 0),
                state_counts.get('TIME_WAIT', 0),
                state_counts.get('CLOSE', 0),
                state_counts.get('CLOSE_WAIT', 0),
                state_counts.get('LAST_ACK', 0),
                state_counts.get('LISTEN', 0),
                state_counts.get('CLOSING', 0),
                total
            ))
        except Exception as e:
            print(f"⚠️  Error collecting TCP states: {e}")
    
    def _collect_protocol_distribution(self, c):
        """Collect protocol distribution (TCP/UDP/ICMP)"""
        try:
            tcp_conns = psutil.net_connections(kind='tcp')
            udp_conns = psutil.net_connections(kind='udp')
            
            tcp_count = len(tcp_conns)
            udp_count = len(udp_conns)
            icmp_count = 0  # ICMP doesn't have persistent connections
            other_count = 0
            
            total = tcp_count + udp_count + icmp_count + other_count
            
            if total > 0:
                tcp_pct = (tcp_count / total) * 100
                udp_pct = (udp_count / total) * 100
                icmp_pct = (icmp_count / total) * 100
                other_pct = (other_count / total) * 100
            else:
                tcp_pct = udp_pct = icmp_pct = other_pct = 0
            
            c.execute('''
                INSERT INTO protocol_distribution (
                    tcp_packets, udp_packets, icmp_packets, other_packets,
                    tcp_percent, udp_percent, icmp_percent, other_percent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tcp_count, udp_count, icmp_count, other_count,
                tcp_pct, udp_pct, icmp_pct, other_pct
            ))
        except Exception as e:
            print(f"⚠️  Error collecting protocol distribution: {e}")
    
    def _collect_port_usage_stats(self, c):
        """Collect port usage statistics"""
        try:
            connections = psutil.net_connections()
            port_stats = defaultdict(lambda: {
                'tcp': {'count': 0, 'listening': 0},
                'udp': {'count': 0, 'listening': 0}
            })
            
            for conn in connections:
                if conn.status == 'NONE':
                    continue
                
                protocol = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
                port = conn.laddr.port if conn.laddr else None
                
                if port:
                    port_stats[port][protocol]['count'] += 1
                    if conn.status == 'LISTEN':
                        port_stats[port][protocol]['listening'] += 1
            
            # Store top ports (limit to avoid too much data)
            for port, stats in list(port_stats.items())[:100]:  # Top 100 ports
                for protocol in ['tcp', 'udp']:
                    if stats[protocol]['count'] > 0:
                        # Try to detect service name
                        service_name = self._detect_service_name(port, protocol)
                        
                        c.execute('''
                            INSERT INTO port_usage_stats (
                                port_number, protocol, connection_count,
                                is_listening, service_name
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', (
                            port, protocol, stats[protocol]['count'],
                            stats[protocol]['listening'] > 0,
                            service_name
                        ))
        except Exception as e:
            print(f"⚠️  Error collecting port usage: {e}")
    
    def _detect_service_name(self, port, protocol):
        """Detect service name for common ports"""
        common_ports = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            443: 'HTTPS', 1883: 'MQTT', 8883: 'MQTTS', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            9998: 'Custom', 9999: 'Custom'
        }
        return common_ports.get(port, None)
    
    def _collect_arp_table_snapshot(self, c):
        """Collect ARP table snapshot"""
        try:
            # Read ARP table from /proc/net/arp (Linux)
            try:
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6:
                            ip_address = parts[0]
                            mac_address = parts[3]
                            interface_name = parts[5]
                            arp_type = 'dynamic' if parts[2] == '0x2' else 'static'
                            
                            c.execute('''
                                INSERT OR IGNORE INTO arp_table_snapshot (
                                    ip_address, mac_address, interface_name, arp_type
                                ) VALUES (?, ?, ?, ?)
                            ''', (ip_address, mac_address, interface_name, arp_type))
            except FileNotFoundError:
                # Not Linux, skip ARP table
                pass
        except Exception as e:
            print(f"⚠️  Error collecting ARP table: {e}")
    
    def record_device_activity(self, mac_address, device_ip, activity_type, value=1):
        """Record activity for a specific device"""
        with self.lock:
            if mac_address not in self.device_metrics:
                self.device_metrics[mac_address] = {
                    'mqtt_messages': 0,
                    'commands_executed': 0,
                    'last_seen': None
                }
            
            if activity_type == 'mqtt_message':
                self.device_metrics[mac_address]['mqtt_messages'] += value
            elif activity_type == 'command':
                self.device_metrics[mac_address]['commands_executed'] += value
            
            self.device_metrics[mac_address]['last_seen'] = datetime.now()
    
    def record_latency(self, component_name, operation_name, latency_ms, success=True, error_message=None):
        """Record latency for a component operation"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute('''
                INSERT INTO component_latency (
                    component_name, operation_name, latency_ms, success, error_message
                ) VALUES (?, ?, ?, ?, ?)
            ''', (component_name, operation_name, latency_ms, success, error_message))
            conn.commit()
        except Exception as e:
            print(f"❌ Error recording latency: {e}")
        finally:
            conn.close()
    
    def update_device_metrics(self):
        """Update device metrics in database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Get all known devices
            c.execute("SELECT mac_address, current_ip FROM device_profiles")
            known_devices = c.fetchall()
            
            for mac_address, device_ip in known_devices:
                # Get metrics from memory, default to 0
                metrics = self.device_metrics.get(mac_address, {'mqtt_messages': 0, 'commands_executed': 0, 'last_seen': None})
                
                # Calculate throughput
                time_diff = self.interval
                messages_per_sec = metrics['mqtt_messages'] / time_diff
                commands_per_sec = metrics['commands_executed'] / time_diff
                
                # ALWAYS insert, even if 0, to keep the sheet filled as requested
                c.execute('''
                    INSERT INTO device_metrics (
                        mac_address, device_ip,
                        mqtt_messages_count, commands_executed_count,
                        messages_per_second, commands_per_second
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    mac_address, device_ip,
                    metrics['mqtt_messages'], metrics['commands_executed'],
                    messages_per_sec, commands_per_sec
                ))
                
                # Reset counters in memory
                if mac_address in self.device_metrics:
                    self.device_metrics[mac_address]['mqtt_messages'] = 0
                    self.device_metrics[mac_address]['commands_executed'] = 0

            conn.commit()
        except Exception as e:
            print(f"❌ Error updating device metrics: {e}")
        finally:
            conn.close()
    
    def _get_snort_packets_count(self):
        """Get Snort packets processed count from session database"""
        return self._get_count_from_session_db('snort_alerts', 'COUNT(*)')
    
    def _get_snort_alerts_count(self):
        """Get Snort alerts count from session database"""
        return self._get_count_from_session_db('snort_alerts', 'COUNT(*)')
    
    def _get_mqtt_messages_count(self):
        """Get MQTT messages count from session database"""
        return self._get_count_from_session_db('mqtt_traffic', 'COUNT(*)')
    
    def _get_mqtt_connections_count(self):
        """Get active MQTT connections count"""
        return len(self.active_connections)
    
    def _get_ai_queries_count(self):
        """Get AI queries count from session database"""
        return self._get_count_from_session_db('ai_analysis', 'COUNT(*)')
    
    def _get_database_stats(self):
        """Get database query statistics"""
        # This would need to be tracked separately
        return 0, 0.0
    
    def _get_count_from_session_db(self, table_name, query):
        """Helper to get count from session database (now uses same db_path)"""
        # Use the same database (session.db) - everything is in one place
        if not os.path.exists(self.db_path):
            return 0
        
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(f'SELECT {query} FROM {table_name}')
            result = c.fetchone()
            conn.close()
            return result[0] if result else 0
        except:
            return 0
    
    def record_connection_start(self, connection_id, mac_address, device_ip, source_port):
        """Record MQTT connection start"""
        with self.lock:
            self.active_connections[connection_id] = {
                'mac_address': mac_address,
                'device_ip': device_ip,
                'source_port': source_port,
                'connect_time': datetime.now(),
                'messages_sent': 0,
                'messages_received': 0,
                'topics': set()
            }
    
    def record_connection_end(self, connection_id, disconnect_reason='normal'):
        """Record MQTT connection end"""
        with self.lock:
            if connection_id not in self.active_connections:
                return
            
            conn_data = self.active_connections.pop(connection_id)
            connect_time = conn_data['connect_time']
            disconnect_time = datetime.now()
            duration = (disconnect_time - connect_time).total_seconds()
            
            # Check if reconnection (same MAC connected recently)
            is_reconnection = False
            if conn_data['mac_address']:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute('''
                    SELECT COUNT(*) FROM mqtt_connections 
                    WHERE mac_address = ? AND disconnect_time > datetime('now', '-5 minutes')
                ''', (conn_data['mac_address'],))
                if c.fetchone()[0] > 0:
                    is_reconnection = True
                conn.close()
            
            # Store in database - handle schema mismatch gracefully
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Check which columns exist
            c.execute("PRAGMA table_info(mqtt_connections)")
            columns = [row[1] for row in c.fetchall()]
            
            # Build INSERT statement based on available columns
            if 'source_port' in columns:
                # New schema with all columns
                c.execute('''
                    INSERT INTO mqtt_connections (
                        connection_id, mac_address, device_ip, source_port,
                        connect_time, disconnect_time, connection_duration_seconds,
                        disconnect_reason, messages_sent, messages_received,
                        topics_subscribed, is_reconnection
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    connection_id,
                    conn_data['mac_address'],
                    conn_data['device_ip'],
                    conn_data['source_port'],
                    connect_time,
                    disconnect_time,
                    duration,
                    disconnect_reason,
                    conn_data['messages_sent'],
                    conn_data['messages_received'],
                    json.dumps(list(conn_data['topics'])),
                    is_reconnection
                ))
            else:
                # Old schema - use available columns only
                c.execute('''
                    INSERT INTO mqtt_connections (
                        connection_id, mac_address, device_ip,
                        connect_time, disconnect_time, duration_seconds,
                        packets_sent, packets_received
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    connection_id,
                    conn_data['mac_address'],
                    conn_data['device_ip'],
                    connect_time,
                    disconnect_time,
                    duration,
                    conn_data['messages_sent'],
                    conn_data['messages_received']
                ))
            conn.commit()
            conn.close()
    
    def record_security_event(self, event_type, mac_address, device_ip, command=None,
                             threat_level='medium', detection_method='ai', ai_confidence=None,
                             heuristic_flag=None, ai_flag=None, reason=None, blocked=True):
        """Record security event and enforce Stage 4 blocking"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Insert event
            c.execute('''
                INSERT INTO security_events (
                    event_type, mac_address, device_ip, command,
                    threat_level, detection_method, ai_confidence,
                    heuristic_flag, ai_flag, reason, blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_type, mac_address, device_ip, command,
                threat_level, detection_method, ai_confidence,
                heuristic_flag, ai_flag, reason, blocked
            ))
            conn.commit()
            
            # STAGE 4 ENFORCEMENT: Check violation count
            if blocked and mac_address:
                # Count recent blocked events (last 5 minutes)
                c.execute('''
                    SELECT COUNT(*) FROM security_events
                    WHERE mac_address = ? AND blocked = 1
                    AND timestamp > datetime('now', '-5 minutes')
                ''', (mac_address,))
                violation_count = c.fetchone()[0]
                
                if violation_count >= 4:
                    print(f"🔒 STAGE 4 TRIGGERED: Blocking MAC {mac_address} (Violations: {violation_count})")
                    self._block_mac_address(mac_address)
                    
        except Exception as e:
            print(f"❌ Error recording security event: {e}")
        finally:
            conn.close()

    def _block_mac_address(self, mac_address, device_ip=None):
        """Block MAC address using iptables (Stage 4) - Drops all connections including MQTT
        Runs in a separate thread to avoid blocking the main loop.
        """
        def _blocking_task(mac, ip):
            # Acquire lock to prevent concurrent blocking operations
            # This prevents iptables lock contention and DB locking issues
            with self.blocking_lock:
                try:
                    print(f"🔒 Starting blocking task for MAC={mac}, IP={ip}")
                    
                    # WHITELIST CHECK: Prevent blocking the admin IP
                    admin_ip = os.environ.get('ADMIN_IP')
                    if admin_ip and ip and ip == admin_ip:
                        print(f"🛡️  WHITELIST: Skipping block for Admin IP {ip}")
                        
                        # Log whitelist event so it shows in display
                        try:
                            conn = sqlite3.connect(self.db_path, timeout=5)
                            c = conn.cursor()
                            # Check if already logged recently to avoid spam
                            c.execute('''
                                SELECT id FROM security_events 
                                WHERE event_type = 'mac_whitelisted' AND device_ip = ? 
                                AND timestamp > datetime('now', '-1 minute')
                            ''', (ip,))
                            if not c.fetchone():
                                c.execute('''
                                    INSERT INTO security_events (
                                        event_type, mac_address, device_ip, threat_level, reason, blocked
                                    ) VALUES (?, ?, ?, ?, ?, ?)
                                ''', ('mac_whitelisted', mac or 'N/A', ip, 'high', 'Whitelisted Admin IP', False))
                                conn.commit()
                        except Exception as e:
                            print(f"⚠️  DB Error logging whitelist: {e}")
                        finally:
                            if 'conn' in locals(): conn.close()
                        return
                    
                    if admin_ip and mac:
                        # Also check if MAC resolves to admin IP (optional, but good for safety)
                        pass
                    
                    # If MAC is missing but IP is provided, fallback to IP blocking
                    if not mac and ip:
                        print(f"⚠️  MAC address missing, falling back to IP blocking for {ip}")
                        # Block INPUT (incoming from IP)
                        subprocess.run(
                            ['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                            check=False, timeout=5
                        )
                        # Block OUTPUT (responses to IP)
                        subprocess.run(
                            ['sudo', 'iptables', '-I', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                            check=False, timeout=5
                        )
                        print(f"✅ IPTABLES: Blocked IP {ip} (MAC unavailable)")
                        
                        # Kill connections
                        for port in [1883, 1889]:
                            subprocess.run(['sudo', 'ss', '-K', 'dst', f'{ip}:{port}'], 
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                        return

                    # Check if already blocked (MAC)
                    # Use -w to wait for xtables lock
                    check = subprocess.run(
                        ['sudo', 'iptables', '-w', '2', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
                    )
                    
                    if check.returncode != 0:
                        # Not blocked yet, add rule
                        # Block INPUT (incoming from device)
                        subprocess.run(
                            ['sudo', 'iptables', '-w', '2', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            check=True, timeout=5
                        )
                        # Also block OUTPUT to device (drop responses)
                        subprocess.run(
                            ['sudo', 'iptables', '-w', '2', '-I', 'OUTPUT', '-m', 'mac', '--mac-destination', mac, '-j', 'DROP'],
                            check=True, timeout=5
                        )
                        print(f"✅ IPTABLES: Blocked MAC {mac} - All connections dropped")
                        
                        # Also block by IP if provided (Redundancy)
                        if ip:
                            subprocess.run(
                                ['sudo', 'iptables', '-w', '2', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                                check=False, timeout=5
                            )
                            subprocess.run(
                                ['sudo', 'iptables', '-w', '2', '-I', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                                check=False, timeout=5
                            )
                            print(f"✅ IPTABLES: Also blocked IP {ip} for redundancy")
                        
                        # Kill existing MQTT connections from this MAC
                        try:
                            # If device_ip is provided, use it directly
                            target_ips = [ip] if ip else []
                            
                            # If no IP provided, try to find it via ARP
                            if not target_ips:
                                import subprocess as sp
                                arp_result = sp.run(['arp', '-n'], capture_output=True, text=True, timeout=2)
                                if arp_result.returncode == 0:
                                    for line in arp_result.stdout.split('\n'):
                                        if mac.lower() in line.lower():
                                            parts = line.split()
                                            if len(parts) >= 1:
                                                target_ips.append(parts[0])
                            
                            # Kill connections for all found IPs
                            for target_ip in target_ips:
                                # Kill connections on MQTT port (1883, 1889)
                                for port in [1883, 1889]:
                                    sp.run(['sudo', 'ss', '-K', 'dst', f'{target_ip}:{port}'], 
                                          stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=2)
                                print(f"✅ Killed MQTT connections for {target_ip} (MAC: {mac})")
                        except Exception as e:
                            print(f"⚠️  Could not kill connections: {e}")
                        
                        # Log the blocking action
                        # Use a short timeout for DB connection
                        try:
                            conn = sqlite3.connect(self.db_path, timeout=5)
                            c = conn.cursor()
                            c.execute('''
                                INSERT INTO security_events (
                                    event_type, mac_address, threat_level, reason, blocked
                                ) VALUES (?, ?, ?, ?, ?)
                            ''', ('mac_blocked', mac, 'critical', 'Stage 4: Excessive Violations', True))
                            conn.commit()
                            conn.close()
                        except Exception as e:
                            print(f"⚠️  DB Error logging block: {e}")
                    else:
                        print(f"ℹ️  MAC {mac} is already blocked")
                        
                except Exception as e:
                    print(f"❌ Error blocking MAC: {e}")

        # Start blocking in a separate thread
        threading.Thread(target=_blocking_task, args=(mac_address, device_ip), daemon=True).start()
    
    def is_blocked(self, mac_address):
        """Check if MAC address is blocked in iptables"""
        if not mac_address:
            return False
        try:
            # Check iptables first
            check = subprocess.run(
                ['sudo', 'iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            iptables_blocked = check.returncode == 0
            
            # Also check database for consistency
            try:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                c.execute('SELECT is_active FROM blocked_mac_addresses WHERE mac_address = ? AND is_active = 1', (mac_address,))
                db_blocked = c.fetchone() is not None
                conn.close()
                return iptables_blocked or db_blocked
            except:
                return iptables_blocked
        except:
            return False
    
    def get_blocked_macs(self):
        """Get list of all blocked MAC addresses with their IPs"""
        try:
            self._init_blocked_mac_table()
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                SELECT mac_address, device_ip, blocked_at, reason, stage, detection_count
                FROM blocked_mac_addresses
                WHERE is_active = 1
                ORDER BY blocked_at DESC
            ''')
            results = c.fetchall()
            conn.close()
            return results
        except Exception as e:
            print(f"⚠️  Error getting blocked MACs: {e}")
            return []
    
    def record_command_pattern(self, mac_address, device_ip, command, success, execution_time_ms):
        """Record command pattern for device behavior analysis"""
        import hashlib
        command_hash = hashlib.md5(command.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Check if pattern exists
            c.execute('''
                SELECT execution_count, success_count, failure_count, avg_execution_time_ms
                FROM command_patterns
                WHERE mac_address = ? AND command_hash = ?
            ''', (mac_address, command_hash))
            
            existing = c.fetchone()
            
            if existing:
                # Update existing pattern
                exec_count, success_count, failure_count, avg_time = existing
                new_exec_count = exec_count + 1
                new_success_count = success_count + (1 if success else 0)
                new_failure_count = failure_count + (0 if success else 1)
                new_avg_time = ((avg_time * exec_count) + execution_time_ms) / new_exec_count
                
                c.execute('''
                    UPDATE command_patterns
                    SET execution_count = ?,
                        success_count = ?,
                        failure_count = ?,
                        avg_execution_time_ms = ?,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE mac_address = ? AND command_hash = ?
                ''', (new_exec_count, new_success_count, new_failure_count, new_avg_time,
                      mac_address, command_hash))
            else:
                # Insert new pattern
                c.execute('''
                    INSERT INTO command_patterns (
                        mac_address, device_ip, command, command_hash,
                        execution_count, success_count, failure_count,
                        avg_execution_time_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mac_address, device_ip, command[:500], command_hash,
                    1, 1 if success else 0, 0 if success else 1,
                    execution_time_ms
                ))
            
            conn.commit()
        except Exception as e:
            print(f"❌ Error recording command pattern: {e}")
        finally:
            conn.close()
    
    def record_error(self, component_name, error_type, error_message, error_traceback=None,
                    mac_address=None, device_ip=None, operation_name=None):
        """Record error for component"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute('''
                INSERT INTO error_log (
                    component_name, error_type, error_message, error_traceback,
                    mac_address, device_ip, operation_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                component_name, error_type, error_message[:1000],
                error_traceback[:5000] if error_traceback else None,
                mac_address, device_ip, operation_name
            ))
            conn.commit()
        except Exception as e:
            print(f"❌ Error recording error log: {e}")
        finally:
            conn.close()
    
    def record_topic_activity(self, topic_name, message_size, is_publish=True):
        """Record topic activity (subscriptions, messages)"""
        import re
        is_wildcard = bool(re.search(r'[#+]', topic_name))
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Get or create topic metrics
            c.execute('''
                SELECT messages_published, messages_received, total_bytes_sent,
                       total_bytes_received, avg_message_size
                FROM topic_metrics
                WHERE topic_name = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (topic_name,))
            
            existing = c.fetchone()
            
            if existing:
                msg_pub, msg_rec, bytes_sent, bytes_rec, avg_size = existing
                new_msg_pub = msg_pub + (1 if is_publish else 0)
                new_msg_rec = msg_rec + (0 if is_publish else 1)
                new_bytes_sent = bytes_sent + (message_size if is_publish else 0)
                new_bytes_rec = bytes_rec + (message_size if not is_publish else 0)
                new_avg_size = ((avg_size * (msg_pub + msg_rec)) + message_size) / (new_msg_pub + new_msg_rec)
                
                # Update the most recent entry for this topic
                c.execute('''
                    UPDATE topic_metrics
                    SET messages_published = ?,
                        messages_received = ?,
                        total_bytes_sent = ?,
                        total_bytes_received = ?,
                        avg_message_size = ?,
                        last_message_time = CURRENT_TIMESTAMP,
                        timestamp = CURRENT_TIMESTAMP
                    WHERE topic_name = ? AND id = (
                        SELECT id FROM topic_metrics 
                        WHERE topic_name = ? 
                        ORDER BY timestamp DESC LIMIT 1
                    )
                ''', (new_msg_pub, new_msg_rec, new_bytes_sent, new_bytes_rec, new_avg_size, topic_name, topic_name))
            else:
                # Insert new topic
                c.execute('''
                    INSERT INTO topic_metrics (
                        topic_name, messages_published, messages_received,
                        total_bytes_sent, total_bytes_received,
                        avg_message_size, is_wildcard
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    topic_name,
                    1 if is_publish else 0,
                    0 if is_publish else 1,
                    message_size if is_publish else 0,
                    message_size if not is_publish else 0,
                    message_size,
                    is_wildcard
                ))
            
            conn.commit()
        except Exception as e:
            print(f"❌ Error recording topic activity: {e}")
        finally:
            conn.close()
    
    def update_topic_subscribers(self, topic_name, subscriber_count):
        """Update subscriber count for topic"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute('''
                UPDATE topic_metrics
                SET subscriber_count = ?
                WHERE topic_name = ?
            ''', (subscriber_count, topic_name))
            conn.commit()
        except:
            pass
        finally:
            conn.close()
    
    def record_network_security_event(self, event_type, source_ip, dest_ip=None,
                                     source_mac=None, dest_mac=None, source_port=None,
                                     dest_port=None, protocol=None, severity='medium',
                                     packet_count=1, duration_seconds=0, description=None,
                                     blocked=False):
        """Record network security event (port scan, DDoS, etc.)"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute('''
                INSERT INTO network_security_events (
                    event_type, source_ip, dest_ip, source_mac, dest_mac,
                    source_port, dest_port, protocol, severity,
                    packet_count, duration_seconds, description, blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_type, source_ip, dest_ip, source_mac, dest_mac,
                source_port, dest_port, protocol, severity,
                packet_count, duration_seconds, description, blocked
            ))
            conn.commit()
        except Exception as e:
            print(f"❌ Error recording network security event: {e}")
        finally:
            conn.close()
    
    def record_mqtt_protocol_metrics(self, mqtt_version=None, qos_level=None,
                                    is_retained=False, is_will=False, is_duplicate=False,
                                    packet_size=0, is_compressed=False):
        """Record MQTT protocol-specific metrics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            # Get current metrics or create new
            c.execute('''
                SELECT id, qos0_messages, qos1_messages, qos2_messages,
                       retained_messages_count, will_messages_count,
                       duplicate_messages_count, compressed_messages_count,
                       mqtt_version, avg_packet_size, min_packet_size, max_packet_size
                FROM mqtt_protocol_metrics
                ORDER BY timestamp DESC
                LIMIT 1
            ''')
            
            existing = c.fetchone()
            
            if existing:
                entry_id, qos0, qos1, qos2, retained, will, dup, compressed, existing_version, avg_size, min_size, max_size = existing
                
                # Update counts only if qos_level is provided
                if qos_level is not None:
                    if qos_level == 0:
                        qos0 += 1
                    elif qos_level == 1:
                        qos1 += 1
                    elif qos_level == 2:
                        qos2 += 1
                
                if is_retained:
                    retained += 1
                if is_will:
                    will += 1
                if is_duplicate:
                    dup += 1
                if is_compressed:
                    compressed += 1
                
                # Update version if provided
                if mqtt_version:
                    existing_version = mqtt_version
                
                # Update packet size stats
                if packet_size > 0:
                    if avg_size is None or avg_size == 0:
                        avg_size = packet_size
                    else:
                        total_packets = qos0 + qos1 + qos2
                        if total_packets > 0:
                            avg_size = ((avg_size * (total_packets - 1)) + packet_size) / total_packets
                    
                    if min_size is None or packet_size < min_size:
                        min_size = packet_size
                    if max_size is None or packet_size > max_size:
                        max_size = packet_size
                
                total = qos0 + qos1 + qos2
                if total > 0:
                    qos0_pct = (qos0 / total) * 100
                    qos1_pct = (qos1 / total) * 100
                    qos2_pct = (qos2 / total) * 100
                else:
                    qos0_pct = qos1_pct = qos2_pct = 0
                
                c.execute('''
                    UPDATE mqtt_protocol_metrics
                    SET mqtt_version = ?,
                        qos0_messages = ?, qos1_messages = ?, qos2_messages = ?,
                        qos0_percent = ?, qos1_percent = ?, qos2_percent = ?,
                        retained_messages_count = ?, will_messages_count = ?,
                        duplicate_messages_count = ?, compressed_messages_count = ?,
                        avg_packet_size = ?, min_packet_size = ?, max_packet_size = ?,
                        timestamp = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (existing_version, qos0, qos1, qos2, qos0_pct, qos1_pct, qos2_pct,
                      retained, will, dup, compressed, avg_size, min_size, max_size, entry_id))
            else:
                # Create new entry - always create one even if no QoS provided
                qos0 = 1 if qos_level == 0 else 0
                qos1 = 1 if qos_level == 1 else 0
                qos2 = 1 if qos_level == 2 else 0
                total = qos0 + qos1 + qos2
                
                # Set packet size defaults
                avg_size = packet_size if packet_size > 0 else None
                min_size = packet_size if packet_size > 0 else None
                max_size = packet_size if packet_size > 0 else None
                
                # Calculate percentages (avoid division by zero)
                if total > 0:
                    qos0_pct = (qos0 / total) * 100
                    qos1_pct = (qos1 / total) * 100
                    qos2_pct = (qos2 / total) * 100
                else:
                    qos0_pct = qos1_pct = qos2_pct = 0.0
                
                c.execute('''
                    INSERT INTO mqtt_protocol_metrics (
                        mqtt_version, qos0_messages, qos1_messages, qos2_messages,
                        qos0_percent, qos1_percent, qos2_percent,
                        retained_messages_count, will_messages_count,
                        duplicate_messages_count, compressed_messages_count,
                        avg_packet_size, min_packet_size, max_packet_size
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mqtt_version, qos0, qos1, qos2,
                    qos0_pct, qos1_pct, qos2_pct,
                    1 if is_retained else 0,
                    1 if is_will else 0,
                    1 if is_duplicate else 0,
                    1 if is_compressed else 0,
                    avg_size, min_size, max_size
                ))
            
            conn.commit()
        except Exception as e:
            import traceback
            print(f"❌ Error recording MQTT protocol metrics: {e}")
            print(f"   Traceback: {traceback.format_exc()}")
        finally:
            conn.close()

    def _collect_topology_changes(self):
        """Track network topology changes and log heartbeats"""
        try:
            current_time = time.time()
            
            # Only check periodically
            if current_time - self.last_topology_check < self.topology_check_interval:
                return
            
            self.last_topology_check = current_time
            
            # Get current state
            current_state = {}
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for iface, addrs in interfaces.items():
                if_stats = stats.get(iface)
                is_up = if_stats.isup if if_stats else False
                
                # Get IPv4 address
                ip_addr = None
                mac_addr = None
                
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip_addr = addr.address
                    elif addr.family == psutil.AF_LINK:
                        mac_addr = addr.address
                
                current_state[iface] = {
                    'is_up': is_up,
                    'ip': ip_addr,
                    'mac': mac_addr
                }
            
            # Compare with last state
            changes_detected = False
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            try:
                # Check for new or changed interfaces
                for iface, state in current_state.items():
                    old_state = self.last_topology_state.get(iface)
                    
                    if not old_state:
                        # New interface
                        c.execute('''
                            INSERT INTO network_topology_changes (
                                change_type, interface_name, new_state, new_ip, mac_address, description
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        ''', ('interface_added', iface, 'UP' if state['is_up'] else 'DOWN', 
                              state['ip'], state['mac'], f"Interface {iface} detected"))
                        changes_detected = True
                        print(f"📡 Topology Change: New interface {iface} detected")
                        
                    elif old_state['is_up'] != state['is_up']:
                        # State change
                        c.execute('''
                            INSERT INTO network_topology_changes (
                                change_type, interface_name, old_state, new_state, description
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', ('interface_state_change', iface, 'UP' if old_state['is_up'] else 'DOWN',
                              'UP' if state['is_up'] else 'DOWN', f"Interface {iface} changed state"))
                        changes_detected = True
                        print(f"📡 Topology Change: Interface {iface} changed state")
                        
                    elif old_state['ip'] != state['ip']:
                        # IP change
                        c.execute('''
                            INSERT INTO network_topology_changes (
                                change_type, interface_name, old_ip, new_ip, description
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', ('ip_change', iface, old_state['ip'], state['ip'], 
                              f"Interface {iface} IP changed"))
                        changes_detected = True
                        print(f"📡 Topology Change: Interface {iface} IP changed")
                
                # Check for removed interfaces
                for iface in self.last_topology_state:
                    if iface not in current_state:
                        c.execute('''
                            INSERT INTO network_topology_changes (
                                change_type, interface_name, description
                            ) VALUES (?, ?, ?)
                        ''', ('interface_removed', iface, f"Interface {iface} removed"))
                        changes_detected = True
                        print(f"📡 Topology Change: Interface {iface} removed")
                
                # Heartbeat logging (if no changes and interval passed)
                if not changes_detected and (current_time - self.last_heartbeat_time >= self.heartbeat_interval):
                    c.execute('''
                        INSERT INTO network_topology_changes (
                            change_type, description
                        ) VALUES (?, ?)
                    ''', ('heartbeat', 'No topology changes detected - System operational'))
                    self.last_heartbeat_time = current_time
                    # print("💓 Topology Heartbeat: System operational") # Uncomment if too verbose
                
                if changes_detected:
                    conn.commit()
                    # Update last state
                    self.last_topology_state = current_state
                elif current_time - self.last_heartbeat_time < 1: # Just committed heartbeat
                    conn.commit()
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"⚠️  Error collecting topology changes: {e}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='System Monitor')
    parser.add_argument('--interval', type=int, default=5, help='Collection interval in seconds')
    parser.add_argument('--db-path', type=str, help='Path to metrics database')
    
    args = parser.parse_args()
    
    monitor = SystemMonitor(db_path=args.db_path, interval=args.interval)
    monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n✅ Monitor stopped")

