#!/usr/bin/env python3
"""
Query Snort & MQTT Database
View and search logged data
"""

import sqlite3
import sys
import os
import time
from datetime import datetime
from tabulate import tabulate

# Get database path from environment or use latest session directory
DB_PATH = os.environ.get('SESSION_LOG_DIR', None)
if DB_PATH and os.path.exists(DB_PATH):
    DB_PATH = os.path.join(DB_PATH, 'session.db')
else:
    # Find latest session directory
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    if os.path.exists(logs_dir):
        session_dirs = [d for d in os.listdir(logs_dir) if os.path.isdir(os.path.join(logs_dir, d)) and d.startswith('2025-')]
        if session_dirs:
            latest_session = sorted(session_dirs)[-1]
            DB_PATH = os.path.join(logs_dir, latest_session, 'session.db')
        else:
            DB_PATH = os.path.join(logs_dir, 'session.db')
    else:
        DB_PATH = "session.db"

def query_database(sql, params=None, timeout=30.0):
    """Execute query and return results with timeout"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=timeout)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
        return results
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            print(f"⚠️  Database locked, retrying with timeout {timeout}s...")
            time.sleep(0.5)
            return query_database(sql, params, timeout=timeout)
        raise
    except Exception as e:
        print(f"❌ Database query error: {e}")
        raise

def show_recent_alerts(limit=20):
    """Show recent Snort alerts"""
    results = query_database('''
        SELECT timestamp, alert_type, message, source_ip, dest_ip, protocol, sid
        FROM snort_alerts
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    if not results:
        print("No Snort alerts found")
        return
    
    print(f"\n📊 Recent Snort Alerts (last {limit}):")
    print("=" * 100)
    
    data = []
    for row in results:
        data.append([
            row['timestamp'],
            row['alert_type'],
            row['message'][:40] + "..." if len(row['message']) > 40 else row['message'],
            row['source_ip'],
            row['dest_ip'],
            row['protocol'],
            row['sid']
        ])
    
    print(tabulate(data, headers=['Timestamp', 'Type', 'Message', 'Source IP', 'Dest IP', 'Protocol', 'SID'], tablefmt='grid'))

def show_recent_mqtt(limit=20):
    """Show recent MQTT traffic"""
    results = query_database('''
        SELECT timestamp, packet_type, topic, payload, source_ip, dest_ip
        FROM mqtt_traffic
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    if not results:
        print("No MQTT traffic found")
        return
    
    print(f"\n📡 Recent MQTT Traffic (last {limit}):")
    print("=" * 100)
    
    data = []
    for row in results:
        payload_preview = row['payload'][:30] + "..." if row['payload'] and len(row['payload']) > 30 else (row['payload'] or "")
        data.append([
            row['timestamp'],
            row['packet_type'],
            row['topic'],
            payload_preview,
            row['source_ip'],
            row['dest_ip']
        ])
    
    print(tabulate(data, headers=['Timestamp', 'Type', 'Topic', 'Payload', 'Source IP', 'Dest IP'], tablefmt='grid'))

def show_ai_analysis(limit=20):
    """Show recent AI analysis"""
    results = query_database('''
        SELECT timestamp, device_ip, command, verdict, is_malicious, confidence, reason
        FROM ai_analysis
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    if not results:
        print("No AI analysis found")
        return
    
    print(f"\n🤖 Recent AI Analysis (last {limit}):")
    print("=" * 100)
    
    data = []
    for row in results:
        cmd_preview = row['command'][:30] + "..." if row['command'] and len(row['command']) > 30 else (row['command'] or "")
        data.append([
            row['timestamp'],
            row['device_ip'],
            cmd_preview,
            row['verdict'],
            "🚫 YES" if row['is_malicious'] else "✅ NO",
            f"{row['confidence']:.2f}" if row['confidence'] else "N/A",
            row['reason'][:30] + "..." if row['reason'] and len(row['reason']) > 30 else (row['reason'] or "")
        ])
    
    print(tabulate(data, headers=['Timestamp', 'Device IP', 'Command', 'Verdict', 'Malicious', 'Confidence', 'Reason'], tablefmt='grid'))

def show_command_executions(limit=20):
    """Show recent command executions"""
    results = query_database('''
        SELECT timestamp, device_ip, command, success, execution_time, ai_verdict
        FROM command_executions
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    if not results:
        print("No command executions found")
        return
    
    print(f"\n⚡ Recent Command Executions (last {limit}):")
    print("=" * 100)
    
    data = []
    for row in results:
        cmd_preview = row['command'][:40] + "..." if row['command'] and len(row['command']) > 40 else (row['command'] or "")
        data.append([
            row['timestamp'],
            row['device_ip'],
            cmd_preview,
            "✅" if row['success'] else "❌",
            f"{row['execution_time']:.3f}s",
            row['ai_verdict'] or "N/A"
        ])
    
    print(tabulate(data, headers=['Timestamp', 'Device IP', 'Command', 'Success', 'Time', 'AI Verdict'], tablefmt='grid'))

def show_stats():
    """Show database statistics"""
    print("\n📈 Database Statistics:")
    print("=" * 50)
    
    stats = {
        'Snort Alerts': query_database('SELECT COUNT(*) as count FROM snort_alerts')[0]['count'],
        'MQTT Traffic': query_database('SELECT COUNT(*) as count FROM mqtt_traffic')[0]['count'],
        'AI Analysis': query_database('SELECT COUNT(*) as count FROM ai_analysis')[0]['count'],
        'Command Executions': query_database('SELECT COUNT(*) as count FROM command_executions')[0]['count'],
        'Malicious Commands': query_database('SELECT COUNT(*) as count FROM ai_analysis WHERE is_malicious = 1')[0]['count'],
        'Blocked Commands': query_database('SELECT COUNT(*) as count FROM command_executions WHERE ai_verdict = "BLOCK"')[0]['count']
    }
    
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Query Snort & MQTT Database')
    parser.add_argument('--alerts', '-a', action='store_true', help='Show Snort alerts')
    parser.add_argument('--mqtt', '-m', action='store_true', help='Show MQTT traffic')
    parser.add_argument('--ai', action='store_true', help='Show AI analysis')
    parser.add_argument('--commands', '-c', action='store_true', help='Show command executions')
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics')
    parser.add_argument('--limit', '-n', type=int, default=20, help='Number of results (default: 20)')
    parser.add_argument('--all', action='store_true', help='Show everything')
    
    args = parser.parse_args()
    
    if args.all or (not args.alerts and not args.mqtt and not args.ai and not args.commands and not args.stats):
        show_stats()
        show_recent_alerts(args.limit)
        show_recent_mqtt(args.limit)
        show_ai_analysis(args.limit)
        show_command_executions(args.limit)
    else:
        if args.stats:
            show_stats()
        if args.alerts:
            show_recent_alerts(args.limit)
        if args.mqtt:
            show_recent_mqtt(args.limit)
        if args.ai:
            show_ai_analysis(args.limit)
        if args.commands:
            show_command_executions(args.limit)
