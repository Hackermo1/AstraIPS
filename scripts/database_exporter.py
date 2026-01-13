#!/usr/bin/env python3
"""
Database Exporter - Exports session database to Excel and SQL
Each table becomes a separate Excel sheet
Includes two comprehensive thesis analysis sheets
"""

import os
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import numpy as np

class DatabaseExporter:
    def __init__(self, db_path):
        """
        Initialize Database Exporter
        
        Args:
            db_path: Path to session database
        """
        self.db_path = db_path
        self.session_dir = os.path.dirname(db_path)
        self.exports_dir = os.path.join(self.session_dir, "exports")
        os.makedirs(self.exports_dir, exist_ok=True)
    
    def _get_active_devices_count(self, conn, timestamp):
        """
        Calculate active devices count at a given timestamp
        Active = unique MAC addresses or IPs that sent/received MQTT traffic in last 5 minutes
        """
        try:
            # Convert timestamp to datetime if string
            if isinstance(timestamp, str):
                try:
                    dt = pd.to_datetime(timestamp)
                except:
                    return 0
            else:
                dt = timestamp
            
            # Look back 5 minutes for active devices
            window_start = dt - timedelta(minutes=5)
            
            # Query for unique devices (MAC preferred, fallback to IP)
            query = """
                SELECT COUNT(DISTINCT COALESCE(source_mac, source_ip, dest_mac, dest_ip)) as active_count
                FROM mqtt_traffic
                WHERE timestamp >= ? AND timestamp <= ?
            """
            cursor = conn.cursor()
            cursor.execute(query, (window_start.strftime('%Y-%m-%d %H:%M:%S'), dt.strftime('%Y-%m-%d %H:%M:%S')))
            result = cursor.fetchone()
            return result[0] if result else 0
        except Exception as e:
            return 0
    
    def _add_active_devices_column(self, df, conn, timestamp_col='timestamp'):
        """Add active_devices column to DataFrame"""
        if df.empty or timestamp_col not in df.columns:
            df['active_devices'] = 0
            return df
        
        active_devices = []
        for idx, row in df.iterrows():
            ts = row[timestamp_col]
            count = self._get_active_devices_count(conn, ts)
            active_devices.append(count)
        
        df['active_devices'] = active_devices
        return df
    
    def _create_thesis_sheet_one(self, conn):
        """
        Create IPS Results Thesis One sheet
        Focus: Device count vs all metrics, Snort decisions, command patterns
        """
        print("   📊 Creating IPS Results Thesis One...")
        
        data_rows = []
        
        # Get all unique timestamps from mqtt_traffic (time series)
        try:
            time_query = """
                SELECT DISTINCT timestamp 
                FROM mqtt_traffic 
                WHERE timestamp IS NOT NULL
                ORDER BY timestamp
            """
            timestamps_df = pd.read_sql_query(time_query, conn)
            
            if timestamps_df.empty:
                # Fallback: use snort_alerts timestamps
                time_query = """
                    SELECT DISTINCT timestamp 
                    FROM snort_alerts 
                    WHERE timestamp IS NOT NULL
                    ORDER BY timestamp
                """
                timestamps_df = pd.read_sql_query(time_query, conn)
        except:
            timestamps_df = pd.DataFrame()
        
        # If still empty, create a single row with current time
        if timestamps_df.empty:
            timestamps_df = pd.DataFrame({'timestamp': [datetime.now()]})
        
        # Process each timestamp
        for _, row in timestamps_df.iterrows():
            ts = row['timestamp']
            
            # Get active devices count
            active_devices = self._get_active_devices_count(conn, ts)
            
            # Get device count from device_detection_state
            try:
                device_query = """
                    SELECT COUNT(DISTINCT mac_address) as device_count
                    FROM device_detection_state
                    WHERE last_detection_time <= ?
                """
                cursor = conn.cursor()
                cursor.execute(device_query, (ts,))
                device_count_result = cursor.fetchone()
                total_devices = device_count_result[0] if device_count_result else active_devices
            except:
                total_devices = active_devices
            
            # Get Snort decisions up to this timestamp
            try:
                snort_query = """
                    SELECT 
                        COUNT(*) as total_alerts,
                        SUM(CASE WHEN ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as blocks,
                        SUM(CASE WHEN heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as heuristic_flags,
                        SUM(CASE WHEN ai_flag = 'BLOCK' AND heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as confirmed_malicious,
                        SUM(CASE WHEN ai_flag = 'BLOCK' AND heuristic_flag IS NULL THEN 1 ELSE 0 END) as ai_only_blocks,
                        SUM(CASE WHEN priority = 1 THEN 1 ELSE 0 END) as critical_alerts,
                        SUM(CASE WHEN priority = 2 THEN 1 ELSE 0 END) as high_alerts,
                        SUM(CASE WHEN priority = 3 THEN 1 ELSE 0 END) as medium_alerts,
                        SUM(CASE WHEN priority = 4 THEN 1 ELSE 0 END) as low_alerts
                    FROM snort_alerts
                    WHERE timestamp <= ?
                """
                snort_df = pd.read_sql_query(snort_query, conn, params=(ts,))
                if not snort_df.empty:
                    snort_row = snort_df.iloc[0]
                    total_alerts = int(snort_row['total_alerts']) if pd.notna(snort_row['total_alerts']) else 0
                    snort_blocks = int(snort_row['blocks']) if pd.notna(snort_row['blocks']) else 0
                    heuristic_flags = int(snort_row['heuristic_flags']) if pd.notna(snort_row['heuristic_flags']) else 0
                    confirmed_malicious = int(snort_row['confirmed_malicious']) if pd.notna(snort_row['confirmed_malicious']) else 0
                    ai_only_blocks = int(snort_row['ai_only_blocks']) if pd.notna(snort_row['ai_only_blocks']) else 0
                    critical_alerts = int(snort_row['critical_alerts']) if pd.notna(snort_row['critical_alerts']) else 0
                    high_alerts = int(snort_row['high_alerts']) if pd.notna(snort_row['high_alerts']) else 0
                    medium_alerts = int(snort_row['medium_alerts']) if pd.notna(snort_row['medium_alerts']) else 0
                    low_alerts = int(snort_row['low_alerts']) if pd.notna(snort_row['low_alerts']) else 0
                else:
                    total_alerts = snort_blocks = heuristic_flags = confirmed_malicious = ai_only_blocks = 0
                    critical_alerts = high_alerts = medium_alerts = low_alerts = 0
            except Exception as e:
                total_alerts = snort_blocks = heuristic_flags = confirmed_malicious = ai_only_blocks = 0
                critical_alerts = high_alerts = medium_alerts = low_alerts = 0
            
            # Get blocked IPs/MACs
            try:
                blocked_query = """
                    SELECT COUNT(DISTINCT mac_address) as blocked_devices
                    FROM security_events
                    WHERE event_type = 'mac_blocked' AND timestamp <= ?
                """
                cursor = conn.cursor()
                cursor.execute(blocked_query, (ts,))
                blocked_result = cursor.fetchone()
                blocked_devices = blocked_result[0] if blocked_result else 0
            except:
                blocked_devices = 0
            
            # Get detection stages distribution
            try:
                stage_query = """
                    SELECT 
                        SUM(CASE WHEN stage = 1 THEN 1 ELSE 0 END) as stage1_count,
                        SUM(CASE WHEN stage = 2 THEN 1 ELSE 0 END) as stage2_count,
                        SUM(CASE WHEN stage = 3 THEN 1 ELSE 0 END) as stage3_count,
                        SUM(CASE WHEN stage = 4 THEN 1 ELSE 0 END) as stage4_count,
                        AVG(detection_count) as avg_detection_count
                    FROM device_detection_state
                    WHERE last_detection_time <= ?
                """
                stage_df = pd.read_sql_query(stage_query, conn, params=(ts,))
                if not stage_df.empty:
                    stage_row = stage_df.iloc[0]
                    stage1 = int(stage_row['stage1_count']) if pd.notna(stage_row['stage1_count']) else 0
                    stage2 = int(stage_row['stage2_count']) if pd.notna(stage_row['stage2_count']) else 0
                    stage3 = int(stage_row['stage3_count']) if pd.notna(stage_row['stage3_count']) else 0
                    stage4 = int(stage_row['stage4_count']) if pd.notna(stage_row['stage4_count']) else 0
                    avg_detections = float(stage_row['avg_detection_count']) if pd.notna(stage_row['avg_detection_count']) else 0.0
                else:
                    stage1 = stage2 = stage3 = stage4 = 0
                    avg_detections = 0.0
            except:
                stage1 = stage2 = stage3 = stage4 = 0
                avg_detections = 0.0
            
            # Get command patterns
            try:
                pattern_query = """
                    SELECT 
                        command,
                        COUNT(*) as pattern_count
                    FROM ai_analysis
                    WHERE timestamp <= ?
                    GROUP BY command
                    ORDER BY pattern_count DESC
                """
                patterns_df = pd.read_sql_query(pattern_query, conn, params=(ts,))
                top_patterns = '; '.join([f"{row['command'][:30]}({int(row['pattern_count'])})" for _, row in patterns_df.iterrows()]) if not patterns_df.empty else ""
            except:
                top_patterns = ""
            
            # Get MQTT traffic stats
            try:
                mqtt_query = """
                    SELECT 
                        COUNT(*) as total_packets,
                        COUNT(DISTINCT source_ip) as unique_ips,
                        COUNT(DISTINCT topic) as unique_topics
                    FROM mqtt_traffic
                    WHERE timestamp <= ?
                """
                mqtt_df = pd.read_sql_query(mqtt_query, conn, params=(ts,))
                if not mqtt_df.empty:
                    mqtt_row = mqtt_df.iloc[0]
                    total_packets = int(mqtt_row['total_packets']) if pd.notna(mqtt_row['total_packets']) else 0
                    unique_ips = int(mqtt_row['unique_ips']) if pd.notna(mqtt_row['unique_ips']) else 0
                    unique_topics = int(mqtt_row['unique_topics']) if pd.notna(mqtt_row['unique_topics']) else 0
                else:
                    total_packets = unique_ips = unique_topics = 0
            except:
                total_packets = unique_ips = unique_topics = 0
            
            # Calculate false positive rate (heuristic flagged but AI allowed)
            try:
                fp_query = """
                    SELECT COUNT(*) as false_positives
                    FROM snort_alerts
                    WHERE heuristic_flag = 'MAL' 
                    AND (ai_flag IS NULL OR ai_flag != 'BLOCK')
                    AND timestamp <= ?
                """
                cursor = conn.cursor()
                cursor.execute(fp_query, (ts,))
                fp_result = cursor.fetchone()
                false_positives = fp_result[0] if fp_result else 0
            except:
                false_positives = 0
            
            # Get Snort decision breakdown
            try:
                snort_decision_query = """
                    SELECT 
                        COUNT(*) as total_decisions,
                        SUM(CASE WHEN ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as snort_blocked_packets,
                        SUM(CASE WHEN heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as snort_heuristic_flags,
                        SUM(CASE WHEN ai_flag = 'BLOCK' AND heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as snort_confirmed_blocks,
                        SUM(CASE WHEN priority = 1 THEN 1 ELSE 0 END) as snort_critical_decisions,
                        SUM(CASE WHEN priority = 2 THEN 1 ELSE 0 END) as snort_high_decisions,
                        SUM(CASE WHEN message LIKE '%DROP%' OR message LIKE '%drop%' THEN 1 ELSE 0 END) as snort_drops,
                        SUM(CASE WHEN message LIKE '%BLOCK%' OR message LIKE '%block%' THEN 1 ELSE 0 END) as snort_block_messages
                    FROM snort_alerts
                    WHERE timestamp <= ?
                """
                snort_dec_df = pd.read_sql_query(snort_decision_query, conn, params=(ts,))
                if not snort_dec_df.empty:
                    dec_row = snort_dec_df.iloc[0]
                    snort_total_decisions = int(dec_row['total_decisions']) if pd.notna(dec_row['total_decisions']) else 0
                    snort_blocked_packets = int(dec_row['snort_blocked_packets']) if pd.notna(dec_row['snort_blocked_packets']) else 0
                    snort_confirmed_blocks = int(dec_row['snort_confirmed_blocks']) if pd.notna(dec_row['snort_confirmed_blocks']) else 0
                    snort_drops = int(dec_row['snort_drops']) if pd.notna(dec_row['snort_drops']) else 0
                    snort_block_messages = int(dec_row['snort_block_messages']) if pd.notna(dec_row['snort_block_messages']) else 0
                else:
                    snort_total_decisions = snort_blocked_packets = snort_confirmed_blocks = snort_drops = snort_block_messages = 0
            except:
                snort_total_decisions = snort_blocked_packets = snort_confirmed_blocks = snort_drops = snort_block_messages = 0
            
            # Create row with comprehensive Snort decision data
            data_rows.append({
                'timestamp': ts,
                'active_devices': active_devices,
                'total_devices': total_devices,
                'total_alerts': total_alerts,
                'snort_blocks': snort_blocks,
                'snort_blocked_packets': snort_blocked_packets,
                'snort_confirmed_blocks': snort_confirmed_blocks,
                'snort_drops': snort_drops,
                'snort_block_messages': snort_block_messages,
                'snort_total_decisions': snort_total_decisions,
                'heuristic_flags': heuristic_flags,
                'confirmed_malicious': confirmed_malicious,
                'ai_only_blocks': ai_only_blocks,
                'false_positives': false_positives,
                'blocked_devices': blocked_devices,
                'critical_alerts': critical_alerts,
                'high_alerts': high_alerts,
                'medium_alerts': medium_alerts,
                'low_alerts': low_alerts,
                'stage1_devices': stage1,
                'stage2_devices': stage2,
                'stage3_devices': stage3,
                'stage4_devices': stage4,
                'avg_detections_per_device': round(avg_detections, 2),
                'total_mqtt_packets': total_packets,
                'unique_source_ips': unique_ips,
                'unique_topics': unique_topics,
                'top_command_patterns': top_patterns
            })
        
        return pd.DataFrame(data_rows)
    
    def _create_thesis_sheet_two(self, conn):
        """
        Create IPS Results Thesis Two sheet
        Focus: Per-device analysis, individual cases, detailed decision tracking
        """
        print("   📊 Creating IPS Results Thesis Two...")
        
        data_rows = []
        
        # Get all devices with their complete history
        try:
            devices_query = """
                SELECT 
                    dds.mac_address,
                    dds.device_ip,
                    dds.stage,
                    dds.detection_count,
                    dds.first_detection_time,
                    dds.last_detection_time,
                    dds.last_command,
                    dds.last_threat_level,
                    COUNT(DISTINCT sa.id) as total_alerts,
                    SUM(CASE WHEN sa.ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as snort_blocks,
                    SUM(CASE WHEN sa.heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as heuristic_flags,
                    SUM(CASE WHEN sa.priority = 1 THEN 1 ELSE 0 END) as critical_alerts,
                    SUM(CASE WHEN sa.priority = 2 THEN 1 ELSE 0 END) as high_alerts,
                    COUNT(DISTINCT aa.id) as ai_analyses,
                    SUM(CASE WHEN aa.verdict = 'BLOCK' THEN 1 ELSE 0 END) as ai_blocks,
                    SUM(CASE WHEN aa.verdict = 'ALLOW' THEN 1 ELSE 0 END) as ai_allows,
                    COUNT(DISTINCT ce.id) as commands_executed,
                    SUM(CASE WHEN ce.success = 1 THEN 1 ELSE 0 END) as successful_commands,
                    COUNT(DISTINCT mt.id) as mqtt_packets,
                    COUNT(DISTINCT mt.topic) as unique_topics,
                    MAX(CASE WHEN se.event_type = 'mac_blocked' THEN 1 ELSE 0 END) as is_blocked
                FROM device_detection_state dds
                LEFT JOIN snort_alerts sa ON (sa.source_ip = dds.device_ip OR sa.dest_ip = dds.device_ip)
                LEFT JOIN ai_analysis aa ON aa.device_mac = dds.mac_address
                LEFT JOIN command_executions ce ON ce.device_mac = dds.mac_address
                LEFT JOIN mqtt_traffic mt ON (mt.source_ip = dds.device_ip OR mt.dest_ip = dds.device_ip)
                LEFT JOIN security_events se ON se.mac_address = dds.mac_address AND se.event_type = 'mac_blocked'
                GROUP BY dds.mac_address, dds.device_ip, dds.stage, dds.detection_count,
                         dds.first_detection_time, dds.last_detection_time, dds.last_command, dds.last_threat_level
            """
            devices_df = pd.read_sql_query(devices_query, conn)
        except Exception as e:
            print(f"      ⚠️  Error querying devices: {e}")
            devices_df = pd.DataFrame()
        
        if devices_df.empty:
            # Fallback: create from mqtt_traffic
            try:
                fallback_query = """
                    SELECT DISTINCT
                        COALESCE(source_mac, 'UNKNOWN') as mac_address,
                        source_ip as device_ip,
                        0 as stage,
                        0 as detection_count,
                        MIN(timestamp) as first_detection_time,
                        MAX(timestamp) as last_detection_time,
                        '' as last_command,
                        '' as last_threat_level
                    FROM mqtt_traffic
                    WHERE source_ip IS NOT NULL
                    GROUP BY source_mac, source_ip
                """
                devices_df = pd.read_sql_query(fallback_query, conn)
                devices_df['total_alerts'] = 0
                devices_df['snort_blocks'] = 0
                devices_df['heuristic_flags'] = 0
                devices_df['critical_alerts'] = 0
                devices_df['high_alerts'] = 0
                devices_df['ai_analyses'] = 0
                devices_df['ai_blocks'] = 0
                devices_df['ai_allows'] = 0
                devices_df['commands_executed'] = 0
                devices_df['successful_commands'] = 0
                devices_df['mqtt_packets'] = 0
                devices_df['unique_topics'] = 0
                devices_df['is_blocked'] = 0
            except:
                devices_df = pd.DataFrame()
        
        # Process each device
        for _, device_row in devices_df.iterrows():
            mac = device_row['mac_address']
            ip = device_row['device_ip']
            
            # Get detailed command history
            try:
                cmd_query = """
                    SELECT command, verdict, is_malicious, confidence, timestamp
                    FROM ai_analysis
                    WHERE device_mac = ? OR device_ip = ?
                    ORDER BY timestamp DESC
                """
                cmd_df = pd.read_sql_query(cmd_query, conn, params=(mac, ip))
                command_history = '; '.join([f"{row['command'][:40]}({row['verdict']})" for _, row in cmd_df.iterrows()]) if not cmd_df.empty else ""
            except:
                command_history = ""
            
            # Get detailed Snort decision breakdown
            try:
                decision_query = """
                    SELECT 
                        COUNT(*) as total_decisions,
                        SUM(CASE WHEN heuristic_flag = 'MAL' AND ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as both_flagged,
                        SUM(CASE WHEN heuristic_flag = 'MAL' AND (ai_flag IS NULL OR ai_flag != 'BLOCK') THEN 1 ELSE 0 END) as heuristic_only,
                        SUM(CASE WHEN (heuristic_flag IS NULL OR heuristic_flag != 'MAL') AND ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as ai_only,
                        SUM(CASE WHEN heuristic_flag IS NULL AND ai_flag IS NULL THEN 1 ELSE 0 END) as no_flags,
                        SUM(CASE WHEN priority = 1 THEN 1 ELSE 0 END) as snort_critical_decisions,
                        SUM(CASE WHEN priority = 2 THEN 1 ELSE 0 END) as snort_high_decisions,
                        SUM(CASE WHEN message LIKE '%DROP%' OR message LIKE '%drop%' THEN 1 ELSE 0 END) as snort_drop_decisions,
                        SUM(CASE WHEN message LIKE '%BLOCK%' OR message LIKE '%block%' THEN 1 ELSE 0 END) as snort_block_decisions,
                        GROUP_CONCAT(DISTINCT message) as snort_decision_messages
                    FROM snort_alerts
                    WHERE source_ip = ? OR dest_ip = ?
                """
                decision_df = pd.read_sql_query(decision_query, conn, params=(ip, ip))
                if not decision_df.empty:
                    dec_row = decision_df.iloc[0]
                    total_decisions = int(dec_row['total_decisions']) if pd.notna(dec_row['total_decisions']) else 0
                    both_flagged = int(dec_row['both_flagged']) if pd.notna(dec_row['both_flagged']) else 0
                    heuristic_only = int(dec_row['heuristic_only']) if pd.notna(dec_row['heuristic_only']) else 0
                    ai_only = int(dec_row['ai_only']) if pd.notna(dec_row['ai_only']) else 0
                    no_flags = int(dec_row['no_flags']) if pd.notna(dec_row['no_flags']) else 0
                    snort_critical = int(dec_row['snort_critical_decisions']) if pd.notna(dec_row['snort_critical_decisions']) else 0
                    snort_high = int(dec_row['snort_high_decisions']) if pd.notna(dec_row['snort_high_decisions']) else 0
                    snort_drops = int(dec_row['snort_drop_decisions']) if pd.notna(dec_row['snort_drop_decisions']) else 0
                    snort_blocks = int(dec_row['snort_block_decisions']) if pd.notna(dec_row['snort_block_decisions']) else 0
                    snort_messages = str(dec_row['snort_decision_messages'])[:200] if pd.notna(dec_row['snort_decision_messages']) else ""
                else:
                    total_decisions = both_flagged = heuristic_only = ai_only = no_flags = 0
                    snort_critical = snort_high = snort_drops = snort_blocks = 0
                    snort_messages = ""
            except Exception as e:
                total_decisions = both_flagged = heuristic_only = ai_only = no_flags = 0
                snort_critical = snort_high = snort_drops = snort_blocks = 0
                snort_messages = ""
            
            # Calculate time between first and last detection
            try:
                first_det = pd.to_datetime(device_row['first_detection_time']) if pd.notna(device_row['first_detection_time']) else None
                last_det = pd.to_datetime(device_row['last_detection_time']) if pd.notna(device_row['last_detection_time']) else None
                if first_det and last_det:
                    detection_duration_minutes = (last_det - first_det).total_seconds() / 60
                else:
                    detection_duration_minutes = 0
            except:
                detection_duration_minutes = 0
            
            data_rows.append({
                'mac_address': mac,
                'device_ip': ip,
                'current_stage': int(device_row['stage']) if pd.notna(device_row['stage']) else 0,
                'detection_count': int(device_row['detection_count']) if pd.notna(device_row['detection_count']) else 0,
                'first_detection_time': device_row['first_detection_time'],
                'last_detection_time': device_row['last_detection_time'],
                'detection_duration_minutes': round(detection_duration_minutes, 2),
                'last_command': device_row['last_command'] if pd.notna(device_row['last_command']) else "",
                'last_threat_level': device_row['last_threat_level'] if pd.notna(device_row['last_threat_level']) else "",
                'total_alerts': int(device_row['total_alerts']) if pd.notna(device_row['total_alerts']) else 0,
                'snort_blocks': int(device_row['snort_blocks']) if pd.notna(device_row['snort_blocks']) else 0,
                'heuristic_flags': int(device_row['heuristic_flags']) if pd.notna(device_row['heuristic_flags']) else 0,
                'critical_alerts': int(device_row['critical_alerts']) if pd.notna(device_row['critical_alerts']) else 0,
                'high_alerts': int(device_row['high_alerts']) if pd.notna(device_row['high_alerts']) else 0,
                'ai_analyses': int(device_row['ai_analyses']) if pd.notna(device_row['ai_analyses']) else 0,
                'ai_blocks': int(device_row['ai_blocks']) if pd.notna(device_row['ai_blocks']) else 0,
                'ai_allows': int(device_row['ai_allows']) if pd.notna(device_row['ai_allows']) else 0,
                'commands_executed': int(device_row['commands_executed']) if pd.notna(device_row['commands_executed']) else 0,
                'successful_commands': int(device_row['successful_commands']) if pd.notna(device_row['successful_commands']) else 0,
                'mqtt_packets': int(device_row['mqtt_packets']) if pd.notna(device_row['mqtt_packets']) else 0,
                'unique_topics': int(device_row['unique_topics']) if pd.notna(device_row['unique_topics']) else 0,
                'is_blocked': int(device_row['is_blocked']) if pd.notna(device_row['is_blocked']) else 0,
                'decision_both_flagged': both_flagged,
                'decision_heuristic_only': heuristic_only,
                'decision_ai_only': ai_only,
                'decision_no_flags': no_flags,
                'snort_critical_decisions': snort_critical,
                'snort_high_decisions': snort_high,
                'snort_drop_decisions': snort_drops,
                'snort_block_decisions': snort_blocks,
                'snort_decision_messages': snort_messages,
                'command_history': command_history
            })
        
        return pd.DataFrame(data_rows)
    
    def export_to_excel(self, filename=None):
        """
        Export all tables to Excel (one sheet per table)
        Adds two thesis sheets and active_devices column to existing sheets
        
        Args:
            filename: Optional Excel filename (default: session_timestamp.xlsx)
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"session_export_{timestamp}.xlsx"
        
        excel_path = os.path.join(self.exports_dir, filename)
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get all table names
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Remove system tables
            tables = [t for t in tables if not t.startswith('sqlite_')]
            
            print(f"📊 Exporting {len(tables)} tables to Excel...")
            
            # Create Excel writer
            with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
                # Export regular tables with active_devices column
                for table in tables:
                    try:
                        # Read table to DataFrame
                        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
                        
                        # Add active_devices column if timestamp column exists
                        if not df.empty and 'timestamp' in df.columns:
                            df = self._add_active_devices_column(df, conn, 'timestamp')
                        
                        # Write to Excel sheet
                        df.to_excel(writer, sheet_name=table, index=False)
                        print(f"   ✅ {table}: {len(df)} rows")
                    except Exception as e:
                        print(f"   ⚠️  {table}: Error - {e}")
                
                # Add thesis sheets
                try:
                    thesis_one_df = self._create_thesis_sheet_one(conn)
                    thesis_one_df.to_excel(writer, sheet_name='IPS Results Thesis One', index=False)
                    print(f"   ✅ IPS Results Thesis One: {len(thesis_one_df)} rows")
                except Exception as e:
                    print(f"   ⚠️  IPS Results Thesis One: Error - {e}")
                    import traceback
                    traceback.print_exc()
                
                try:
                    thesis_two_df = self._create_thesis_sheet_two(conn)
                    thesis_two_df.to_excel(writer, sheet_name='IPS Results Thesis Two', index=False)
                    print(f"   ✅ IPS Results Thesis Two: {len(thesis_two_df)} rows")
                except Exception as e:
                    print(f"   ⚠️  IPS Results Thesis Two: Error - {e}")
                    import traceback
                    traceback.print_exc()
            
            conn.close()
            print(f"✅ Excel export complete: {excel_path}")
            return excel_path
            
        except Exception as e:
            print(f"❌ Excel export error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def export_to_sql(self, filename=None):
        """
        Export database to SQL dump file
        
        Args:
            filename: Optional SQL filename (default: session_dump_timestamp.sql)
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"session_dump_{timestamp}.sql"
        
        sql_path = os.path.join(self.exports_dir, filename)
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            print(f"📊 Exporting database to SQL dump...")
            
            with open(sql_path, 'w') as f:
                # Write header
                f.write(f"-- SQL Dump from session database\n")
                f.write(f"-- Generated: {datetime.now().isoformat()}\n")
                f.write(f"-- Database: {self.db_path}\n\n")
                
                # Iterate through tables
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                tables = [t for t in tables if not t.startswith('sqlite_')]
                
                for table in tables:
                    # Get table schema
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table}'")
                    schema = cursor.fetchone()[0]
                    f.write(f"\n-- Table: {table}\n")
                    f.write(f"{schema};\n\n")
                    
                    # Get table data
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    
                    if rows:
                        # Get column names
                        cursor.execute(f"PRAGMA table_info({table})")
                        columns = [row[1] for row in cursor.fetchall()]
                        
                        f.write(f"-- Data for {table} ({len(rows)} rows)\n")
                        f.write(f"INSERT INTO {table} ({', '.join(columns)}) VALUES\n")
                        
                        # Write data
                        for i, row in enumerate(rows):
                            values = []
                            for val in row:
                                if val is None:
                                    values.append("NULL")
                                elif isinstance(val, str):
                                    val_escaped = val.replace("'", "''")
                                    values.append(f"'{val_escaped}'")
                                else:
                                    values.append(str(val))
                            
                            comma = "," if i < len(rows) - 1 else ";"
                            f.write(f"({', '.join(values)}){comma}\n")
                        
                        f.write("\n")
            
            conn.close()
            print(f"✅ SQL dump complete: {sql_path}")
            return sql_path
            
        except Exception as e:
            print(f"❌ SQL export error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def export_all(self):
        """Export both Excel and SQL"""
        print("\n" + "="*60)
        print("EXPORTING SESSION DATABASE")
        print("="*60)
        
        excel_path = self.export_to_excel()
        sql_path = self.export_to_sql()
        
        return {
            'excel': excel_path,
            'sql': sql_path,
            'exports_dir': self.exports_dir
        }
