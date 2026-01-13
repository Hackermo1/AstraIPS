#!/usr/bin/env python3
"""
Clean Terminal Display - Table Format Output
Shows Snort alerts, MQTT traffic, and system status in clean table format
"""

import os
import sys
import time
import sqlite3
import subprocess
import signal
from datetime import datetime
from collections import deque
import threading

class CleanTerminalDisplay:
    def __init__(self, session_log_dir):
        self.session_log_dir = session_log_dir
        self.db_path = os.path.join(session_log_dir, 'session.db')
        self.running = True
        self.last_alert_id = 0
        self.last_mqtt_id = 0
        self.display_thread = None
        
        # Status tracking
        self.snort_running = False
        self.snort_pid = None
        self.last_snort_check = 0
        self.snort_mode = "UNKNOWN"  # IPS or IDS
        self.snort_daq = "UNKNOWN"   # nfq, afpacket, pcap
        self.interface = "UNKNOWN"
        
        # Recent alerts queue (for table display)
        self.recent_alerts = deque(maxlen=10)
        self.recent_mqtt = deque(maxlen=10)
        
        # Setup signal handlers for clean exit
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C and termination signals"""
        print("\n\n🛑 Shutting down display...")
        self.running = False
        sys.exit(0)
        
    def check_snort_status(self):
        """Check if Snort is running and detect mode"""
        try:
            # Check for snort process
            result = subprocess.run(['pgrep', '-f', 'snort'], 
                                   capture_output=True, text=True)
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                if pids:
                    self.snort_running = True
                    self.snort_pid = pids[0]
                    
                    # Get full command line from ps
                    try:
                        ps_result = subprocess.run(['ps', '-p', self.snort_pid, '-o', 'args='], 
                                                   capture_output=True, text=True)
                        if ps_result.returncode == 0:
                            cmdline = ps_result.stdout.strip()
                            
                            # Detect DAQ type from command line
                            if '--daq nfq' in cmdline or 'daq nfq' in cmdline or 'daq_nfq' in cmdline:
                                self.snort_daq = "NFQUEUE"
                                self.snort_mode = "IPS"
                            elif '--daq afpacket' in cmdline or 'daq afpacket' in cmdline or 'daq_afpacket' in cmdline:
                                self.snort_daq = "AFPACKET"
                                self.snort_mode = "IPS"
                            elif '--daq pcap' in cmdline or 'daq pcap' in cmdline:
                                self.snort_daq = "PCAP"
                                self.snort_mode = "IDS"
                            
                            # Detect interface from command line
                            import re
                            # Look for -i interface or --interface interface
                            interface_match = re.search(r'(?:-i|--interface)\s+(\S+)', cmdline)
                            if interface_match:
                                self.interface = interface_match.group(1)
                            # Also check for interface in afpacket format (eth0:eth0)
                            elif 'afpacket' in cmdline.lower():
                                afpacket_match = re.search(r'afpacket[^:]*:([^,\s]+)', cmdline)
                                if afpacket_match:
                                    self.interface = afpacket_match.group(1).split(':')[0]
                            
                            # If still no interface, check parent process (snortlive.sh or mqttlive)
                            if self.interface == "UNKNOWN":
                                try:
                                    # Get parent PID
                                    ppid_result = subprocess.run(['ps', '-p', self.snort_pid, '-o', 'ppid='], 
                                                                 capture_output=True, text=True)
                                    if ppid_result.returncode == 0:
                                        ppid = ppid_result.stdout.strip()
                                        if ppid:
                                            # Get parent command line
                                            parent_result = subprocess.run(['ps', '-p', ppid, '-o', 'args='], 
                                                                          capture_output=True, text=True)
                                            if parent_result.returncode == 0:
                                                parent_cmdline = parent_result.stdout.strip()
                                                # Look for --interface in parent (snortlive.sh or mqttlive)
                                                parent_interface_match = re.search(r'--interface\s+(\S+)', parent_cmdline)
                                                if parent_interface_match:
                                                    self.interface = parent_interface_match.group(1)
                                                # Also check for interface as direct argument (mqttlive eth0)
                                                elif not parent_interface_match:
                                                    # Check if parent is mqttlive with interface as argument
                                                    mqttlive_match = re.search(r'mqttlive\s+(\S+)', parent_cmdline)
                                                    if mqttlive_match:
                                                        potential_iface = mqttlive_match.group(1)
                                                        # Verify it's a valid interface name (not a flag)
                                                        if potential_iface and not potential_iface.startswith('-'):
                                                            # Check if it's actually an interface
                                                            iface_check = subprocess.run(['ip', 'link', 'show', potential_iface], 
                                                                                        capture_output=True, text=True, timeout=1)
                                                            if iface_check.returncode == 0:
                                                                self.interface = potential_iface
                                except:
                                    pass
                    except:
                        pass
                    
                    # Fallback: Detect IPS/IDS mode from environment
                    snort_daq_mode = os.environ.get('SNORT_DAQ_MODE', '')
                    if snort_daq_mode == 'inline' and self.snort_daq == "UNKNOWN":
                        self.snort_mode = "IPS"
                        self.snort_daq = "NFQUEUE"  # Assume NFQUEUE for inline
                    elif self.snort_mode == "UNKNOWN":
                        self.snort_mode = "IDS"
                    
                    # Fallback: Check Snort console log for DAQ type and interface
                    if self.snort_daq == "UNKNOWN" or self.interface == "UNKNOWN":
                        console_log = os.path.join(self.session_log_dir, 'snort_console.log')
                        if os.path.exists(console_log):
                            try:
                                with open(console_log, 'r') as f:
                                    log_content = f.read()
                                    # Check for DAQ type
                                    if self.snort_daq == "UNKNOWN":
                                        if 'nfq DAQ' in log_content or 'NFQUEUE' in log_content or 'nfq' in log_content.lower():
                                            self.snort_daq = "NFQUEUE"
                                            self.snort_mode = "IPS"
                                        elif 'afpacket' in log_content.lower():
                                            self.snort_daq = "AFPACKET"
                                            self.snort_mode = "IPS"
                                        elif 'pcap' in log_content.lower():
                                            self.snort_daq = "PCAP"
                                            self.snort_mode = "IDS"
                                    
                                    # Try to detect interface from log
                                    if self.interface == "UNKNOWN":
                                        import re
                                        interface_match = re.search(r'(?:-i|--interface|interface)\s+(\S+)', log_content)
                                        if interface_match:
                                            self.interface = interface_match.group(1)
                            except:
                                pass
                    
                    # Final fallback: Check environment variables or common interface names
                    if self.interface == "UNKNOWN":
                        # For NFQUEUE, check iptables rules to see which interface traffic is coming from
                        if self.snort_daq == "NFQUEUE":
                            try:
                                # Check iptables OUTPUT rules for NFQUEUE on port 1889
                                iptables_result = subprocess.run(['sudo', 'iptables', '-L', 'OUTPUT', '-n', '-v'], 
                                                                capture_output=True, text=True, timeout=2)
                                if iptables_result.returncode == 0:
                                    # Look for NFQUEUE rules and extract interface
                                    for line in iptables_result.stdout.split('\n'):
                                        if 'NFQUEUE' in line and '1889' in line:
                                            # Extract interface from rule (usually shows dev interface)
                                            iface_match = re.search(r'dev\s+(\S+)', line)
                                            if iface_match:
                                                self.interface = iface_match.group(1)
                                                break
                            except:
                                pass
                        
                        # Check if there's an interface in the log directory path
                        if self.interface == "UNKNOWN":
                            if 'eth0' in self.session_log_dir.lower():
                                self.interface = "eth0"
                            elif 'wlan0' in self.session_log_dir.lower():
                                self.interface = "wlan0"
                            elif 'lo' in self.session_log_dir.lower():
                                self.interface = "lo"
                            else:
                                # Try to detect from system interfaces (default route)
                                try:
                                    result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                                           capture_output=True, text=True, timeout=2)
                                    if result.returncode == 0:
                                        import re
                                        match = re.search(r'dev\s+(\S+)', result.stdout)
                                        if match:
                                            detected_iface = match.group(1)
                                            # Don't use lo as fallback - prefer eth0/wlan0
                                            if detected_iface != 'lo':
                                                self.interface = detected_iface
                                            else:
                                                # If lo, try to find eth0 or wlan0
                                                iface_list = subprocess.run(['ip', 'link', 'show'], 
                                                                          capture_output=True, text=True, timeout=2)
                                                if iface_list.returncode == 0:
                                                    if 'eth0' in iface_list.stdout:
                                                        self.interface = "eth0"
                                                    elif 'wlan0' in iface_list.stdout:
                                                        self.interface = "wlan0"
                                except:
                                    pass
                    
                    return True
            self.snort_running = False
            self.snort_pid = None
            self.snort_mode = "STOPPED"
            self.snort_daq = "UNKNOWN"
            self.interface = "UNKNOWN"
            return False
        except Exception:
            self.snort_running = False
            self.snort_mode = "ERROR"
            return False
    
    def get_recent_alerts(self):
        """Get recent alerts from database - joins with security_events for flags"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            c = conn.cursor()
            
            # First check if security_events table exists and has required columns
            try:
                c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
                has_security_events = c.fetchone() is not None
                
                if has_security_events:
                    # Check if columns exist
                    c.execute("PRAGMA table_info(security_events)")
                    columns = [row[1] for row in c.fetchall()]
                    has_reason = 'reason' in columns
                    has_device_ip = 'device_ip' in columns
                    has_detection_method = 'detection_method' in columns
                    has_heuristic_flag = 'heuristic_flag' in columns
                    has_ai_flag = 'ai_flag' in columns
                    
                    if has_heuristic_flag and has_ai_flag:
                        # Query directly from snort_alerts (preferred)
                        c.execute('''
                            SELECT id, timestamp, priority, message, source_ip,
                                   'none' as detection_method,
                                   COALESCE(heuristic_flag, 'N/A') as heuristic_flag,
                                   COALESCE(ai_flag, 'N/A') as ai_flag
                            FROM snort_alerts
                            WHERE id > ?
                            ORDER BY id DESC
                            LIMIT 20
                        ''', (self.last_alert_id,))
                        alerts = c.fetchall()
                        if alerts:
                            self.last_alert_id = alerts[0][0]
                            for alert in reversed(alerts):
                                alert_id, timestamp, priority, message, source_ip, detection_method, heuristic_flag, ai_flag = alert
                                self.recent_alerts.append({
                                    'id': alert_id,
                                    'timestamp': timestamp,
                                    'priority': priority or 4,
                                    'message': message or '',
                                    'source_ip': source_ip or 'N/A',
                                    'detection_method': detection_method,
                                    'heuristic_flag': heuristic_flag,
                                    'ai_flag': ai_flag
                                })
                        conn.close()
                        return

                    elif has_reason and has_device_ip and has_detection_method:
                        # Fallback to JOIN if columns missing in snort_alerts (legacy)
                        c.execute('''
                            SELECT sa.id, sa.timestamp, sa.priority, sa.message, sa.source_ip,
                                   COALESCE(se.detection_method, 'none') as detection_method,
                                   COALESCE(se.heuristic_flag, 'N/A') as heuristic_flag,
                                   COALESCE(se.ai_flag, 'N/A') as ai_flag
                            FROM snort_alerts sa
                            LEFT JOIN security_events se ON sa.message = se.reason AND sa.source_ip = se.device_ip
                            WHERE sa.id > ?
                            ORDER BY sa.id DESC
                            LIMIT 20
                        ''', (self.last_alert_id,))
                        alerts = c.fetchall()
                        if alerts:
                            self.last_alert_id = alerts[0][0]
                            for alert in reversed(alerts):
                                alert_id, timestamp, priority, message, source_ip, detection_method, heuristic_flag, ai_flag = alert
                                self.recent_alerts.append({
                                    'id': alert_id,
                                    'timestamp': timestamp,
                                    'priority': priority or 4,
                                    'message': message or '',
                                    'source_ip': source_ip or 'N/A',
                                    'detection_method': detection_method or 'none',
                                    'heuristic_flag': heuristic_flag or 'N/A',
                                    'ai_flag': ai_flag or 'N/A'
                                })
                        conn.close()
                        return
            except:
                pass  # Fall through to simple query
            
            # Simple query without join (fallback)
            c.execute('''
                SELECT id, timestamp, priority, message, source_ip
                FROM snort_alerts
                WHERE id > ?
                ORDER BY id DESC
                LIMIT 20
            ''', (self.last_alert_id,))
            alerts = c.fetchall()
            if alerts:
                self.last_alert_id = alerts[0][0]
                for alert in reversed(alerts):
                    alert_id, timestamp, priority, message, source_ip = alert
                    self.recent_alerts.append({
                        'id': alert_id,
                        'timestamp': timestamp,
                        'priority': priority or 4,
                        'message': message or '',
                        'source_ip': source_ip or 'N/A',
                        'detection_method': 'none',
                        'heuristic_flag': 'N/A',
                        'ai_flag': 'N/A'
                    })
            conn.close()
        except Exception as e:
            # Silently handle errors - don't crash the display
            pass
    
    def get_recent_mqtt(self):
        """Get recent MQTT traffic from database"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            c = conn.cursor()
            
            # Get MQTT traffic since last check
            c.execute('''
                SELECT id, timestamp, packet_type, topic, source_ip
                FROM mqtt_traffic
                WHERE id > ?
                ORDER BY id DESC
                LIMIT 10
            ''', (self.last_mqtt_id,))
            
            mqtt_traffic = c.fetchall()
            if mqtt_traffic:
                self.last_mqtt_id = mqtt_traffic[0][0]
                for mqtt in reversed(mqtt_traffic):
                    mqtt_id, timestamp, packet_type, topic, source_ip = mqtt
                    self.recent_mqtt.append({
                        'id': mqtt_id,
                        'timestamp': timestamp,
                        'packet_type': packet_type or 'N/A',
                        'topic': topic or 'N/A',
                        'source_ip': source_ip or 'N/A'
                    })
            
            conn.close()
        except Exception as e:
            pass  # Silently handle errors
    
    def format_priority(self, priority):
        """Format priority with color"""
        priority_map = {
            1: ('🔴 CRITICAL', 'red'),
            2: ('🟠 HIGH', 'yellow'),
            3: ('🟡 MEDIUM', 'yellow'),
            4: ('⚪ LOW', 'white')
        }
        return priority_map.get(priority, ('⚪ UNKNOWN', 'white'))
    
    def format_detection_method(self, method):
        """Format detection method"""
        method_map = {
            'both': '🤖+📊 AI+Heuristic',
            'ai': '🤖 AI',
            'heuristic': '📊 Heuristic',
            'pattern': '🔍 Pattern',
            'none': '⚪ None'
        }
        return method_map.get(method, '⚪ Unknown')
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def display_header(self):
        """Display header with system status and mode"""
        # Check Snort status every 5 seconds
        current_time = time.time()
        if current_time - self.last_snort_check > 5:
            self.check_snort_status()
            self.last_snort_check = current_time
        
        snort_status = "🟢 RUNNING" if self.snort_running else "🔴 STOPPED"
        snort_pid_info = f" (PID: {self.snort_pid})" if self.snort_pid else ""
        
        # Mode display with color
        if self.snort_mode == "IPS":
            mode_display = "🛡️  IPS MODE (INLINE BLOCKING)"
            mode_color = "\033[1;31m"  # Red/bold
        elif self.snort_mode == "IDS":
            mode_display = "👁️  IDS MODE (PASSIVE MONITORING)"
            mode_color = "\033[1;33m"  # Yellow/bold
        else:
            mode_display = f"❓ {self.snort_mode}"
            mode_color = "\033[1;37m"  # White
        
        reset_color = "\033[0m"
        
        print("=" * 100)
        print(f"{mode_color}{mode_display}{reset_color}")
        print("=" * 100)
        print(f"📊 Database: {self.db_path}")
        print(f"🛡️  Snort Status: {snort_status}{snort_pid_info}")
        print(f"🔧 Mode: {self.snort_mode} | DAQ: {self.snort_daq} | Interface: {self.interface}")
        print(f"⚙️  SNORT_DAQ_MODE: {os.environ.get('SNORT_DAQ_MODE', 'not set')}")
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 100)
        print()
    
    def display_alerts_table(self):
        """Display recent alerts in table format"""
        if not self.recent_alerts:
            return
        
        print("📋 RECENT SNORT ALERTS")
        print("-" * 100)
        print(f"{'Time':<12} {'Priority':<12} {'IP':<18} {'Detection':<20} {'Heuristic':<10} {'AI':<10} {'Message':<30}")
        print("-" * 100)
        
        for alert in list(self.recent_alerts)[-10:]:  # Show last 10
            timestamp = alert['timestamp'][:19] if alert['timestamp'] else 'N/A'
            priority_str, _ = self.format_priority(alert['priority'])
            detection = self.format_detection_method(alert['detection_method'])
            heuristic = alert['heuristic_flag']
            ai_flag = alert['ai_flag']
            message = (alert['message'][:27] + '...') if len(alert['message']) > 30 else alert['message']
            
            print(f"{timestamp:<12} {priority_str:<12} {alert['source_ip']:<18} {detection:<20} {heuristic:<10} {ai_flag:<10} {message:<30}")
        
        print("-" * 100)
        print()
    
    def display_mqtt_table(self):
        """Display recent MQTT traffic in table format"""
        if not self.recent_mqtt:
            return
        
        print("📡 RECENT MQTT TRAFFIC")
        print("-" * 100)
        print(f"{'Time':<12} {'Type':<12} {'Topic':<30} {'Source IP':<18}")
        print("-" * 100)
        
        for mqtt in list(self.recent_mqtt)[-10:]:  # Show last 10
            timestamp = mqtt['timestamp'][:19] if mqtt['timestamp'] else 'N/A'
            topic = (mqtt['topic'][:27] + '...') if len(mqtt['topic']) > 30 else mqtt['topic']
            
            print(f"{timestamp:<12} {mqtt['packet_type']:<12} {topic:<30} {mqtt['source_ip']:<18}")
        
        print("-" * 100)
        print()
    
    def display_summary(self):
        """Display summary statistics"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            c = conn.cursor()
            
            # Get counts
            c.execute('SELECT COUNT(*) FROM snort_alerts')
            total_alerts = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM snort_alerts WHERE priority = 1')
            critical_alerts = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM snort_alerts WHERE priority = 2')
            high_alerts = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM mqtt_traffic')
            total_mqtt = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM security_events')
            security_events = c.fetchone()[0]
            
            conn.close()
            
            print("📊 SUMMARY STATISTICS")
            print("-" * 100)
            print(f"Total Alerts: {total_alerts} | Critical: {critical_alerts} | High: {high_alerts} | Security Events: {security_events} | MQTT Packets: {total_mqtt}")
            print("-" * 100)
            print()
            
        except Exception:
            pass
    
    def get_blocked_devices(self):
        """Get list of blocked and whitelisted devices from iptables and database"""
        devices = []
        
        # 1. Get blocked MACs from iptables
        try:
            cmd = "sudo iptables -L INPUT -n -v | grep 'MAC' | grep 'DROP'"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
            
            for line in output.split('\n'):
                if 'MAC' in line:
                    parts = line.split('MAC')
                    if len(parts) > 1:
                        mac = parts[1].strip().split()[0]
                        devices.append({
                            'mac': mac,
                            'ip': 'Unknown',
                            'stage': 4,
                            'reason': 'Firewall Block (Active)',
                            'blocked_at': 'Now'
                        })
        except:
            pass

        # 2. Get whitelisted/blocked events from database
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            c = conn.cursor()
            
            # Check if table exists
            c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
            if c.fetchone():
                # Get recent events
                c.execute('''
                    SELECT mac_address, device_ip, timestamp, reason, event_type
                    FROM security_events 
                    WHERE event_type IN ('mac_blocked', 'mac_whitelisted')
                    ORDER BY id DESC LIMIT 10
                ''')
                
                for row in c.fetchall():
                    mac, ip, timestamp, reason, event_type = row
                    
                    # Determine status
                    if event_type == 'mac_whitelisted':
                        status = "🛡️ WHITELISTED"
                    else:
                        status = "⛔ BLOCKED"
                        
                    # Check if already in list (deduplicate by MAC)
                    existing = next((d for d in devices if d['mac'] == mac), None)
                    if existing:
                        if existing['ip'] == 'Unknown': existing['ip'] = ip
                        if existing['reason'] == 'Firewall Block (Active)': existing['reason'] = reason
                    else:
                        devices.append({
                            'mac': mac,
                            'ip': ip,
                            'stage': status,
                            'reason': reason,
                            'blocked_at': timestamp
                        })
            conn.close()
        except Exception as e:
            pass
            
        return devices

    def display_blocked_devices(self):
        """Display blocked devices table"""
        blocked = self.get_blocked_devices()
        if not blocked:
            return

        print("⛔ BLOCKED DEVICES (Firewall)")
        print("-" * 100)
        print(f"{'MAC Address':<20} {'IP Address':<18} {'Blocked At':<12} {'Stage':<8} {'Reason':<30}")
        print("-" * 100)
        
        for device in blocked:
            mac = device.get('mac', 'N/A')
            ip = device.get('ip', 'N/A')
            blocked_at = device.get('blocked_at', 'N/A')
            if blocked_at and blocked_at != 'N/A':
                blocked_at = blocked_at[:19] if len(blocked_at) > 19 else blocked_at
            stage = device.get('stage', 4)
            reason = device.get('reason', 'Stage 4 Detection')
            if len(reason) > 28:
                reason = reason[:25] + '...'
            
            print(f"{mac:<20} {ip:<18} {blocked_at:<12} {stage:<8} {reason:<30}")
        
        print("-" * 100)
        print()

    def display_loop(self):
        """Main display loop"""
        while self.running:
            try:
                self.clear_screen()
                self.display_header()
                self.get_recent_alerts()
                self.get_recent_mqtt()
                self.display_alerts_table()
                self.display_mqtt_table()
                self.display_blocked_devices()
                self.display_summary()
                print("💡 Press Ctrl+C to stop monitoring")
                time.sleep(2)  # Update every 2 seconds
            except KeyboardInterrupt:
                print("\n\n🛑 Shutting down display...")
                self.running = False
                break
            except Exception as e:
                if not self.running:
                    break
                time.sleep(2)
    
    def start(self):
        """Start the display"""
        self.display_thread = threading.Thread(target=self.display_loop, daemon=True)
        self.display_thread.start()
    
    def stop(self):
        """Stop the display"""
        self.running = False
        if self.display_thread:
            self.display_thread.join(timeout=2)

if __name__ == "__main__":
    session_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('SESSION_LOG_DIR', 'logs')
    display = CleanTerminalDisplay(session_dir)
    try:
        display.display_loop()
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down...")
        display.stop()
        print("✅ Monitoring stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        display.stop()
        sys.exit(1)
