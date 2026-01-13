#!/usr/bin/env python3
"""
MAC-Based Network Scanner
Scans devices by IP, tracks by MAC address, stores multiple IPs per MAC
"""

import paramiko
import time
import os
import datetime
import json
import sqlite3
import threading
from typing import Dict, Optional, Tuple

# Configuration - find config in project's router-config directory
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)
ROUTER_CONFIG_FILE = os.path.join(project_dir, "router-config", "router_config.json")

class MACBasedScanner:
    def __init__(self, config_file=None):
        """Initialize MAC-based scanner"""
        self.config_file = config_file or ROUTER_CONFIG_FILE
        self.config = self._load_config()
        self.ssh_client = None
        self.lock = threading.Lock()
        self.last_connection_check = 0
        self.connection_check_interval = 60  # Check connection health every 60 seconds
        
        # Database setup - use session database if available
        session_dir = os.environ.get('SESSION_LOG_DIR')
        if session_dir and os.path.exists(session_dir):
            # Use centralized session database
            self.db_file = os.path.join(session_dir, "session.db")
            # Also create scans subdirectory for scan history
            scans_dir = os.path.join(session_dir, "scans")
            os.makedirs(scans_dir, exist_ok=True)
        else:
            # Fallback to old location
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_file = os.path.join(base_dir, "router config", "Thesis_Scans", "mac_device_profiles.db")
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
        
        self._init_database()
    
    def _load_config(self):
        """Load router configuration from config file (no hardcoded credentials)"""
        default_config = {
            "enabled": False,
            "router_ip": "",
            "router_user": "",
            "router_pass": ""
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"⚠️  Error loading router config: {e}")
                print("   Run installer/setup_router.sh to configure router scanning")
        else:
            print("⚠️  Router config not found: {self.config_file}")
            print("   Run installer/setup_router.sh to configure router scanning")
        
        return default_config
    
    def _init_database(self):
        """Initialize MAC-based device profile database"""
        conn = sqlite3.connect(self.db_file, timeout=30.0)
        c = conn.cursor()
        
        # Device profiles table: MAC-based with multiple IPs
        # Use schema compatible with session_manager (includes timestamp column)
        c.execute('''
            CREATE TABLE IF NOT EXISTS device_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                mac_address TEXT UNIQUE NOT NULL,
                current_ip TEXT,
                ip_history TEXT,  -- JSON array of IPs
                scan_results TEXT,  -- JSON of latest Nmap scan
                scan_timestamp DATETIME,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                device_name TEXT,
                UNIQUE(mac_address)
            )
        ''')
        
        # IP to MAC mapping (for quick lookups)
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_mac_mapping (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT NOT NULL,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mac_address) REFERENCES device_profiles(mac_address)
            )
        ''')
        
        # Scan history (one entry per scan)
        c.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                scan_results TEXT,  -- Full Nmap output
                FOREIGN KEY (mac_address) REFERENCES device_profiles(mac_address)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _extract_device_name(self, nmap_output, ip_address, mac_address):
        """
        Extract device name/type from nmap scan output
        
        Tries to extract:
        1. Hostname from nmap output
        2. Device type from MAC address vendor lookup
        3. OS/Device type from nmap OS detection
        4. Service names (e.g., "Raspberry Pi", "iPhone", etc.)
        """
        if not nmap_output:
            return None
        
        device_name = None
        
        # Try to extract hostname from nmap output
        # Look for patterns like "Nmap scan report for hostname (IP)"
        import re
        hostname_pattern = r'Nmap scan report for ([^(]+)'
        match = re.search(hostname_pattern, nmap_output)
        if match:
            hostname = match.group(1).strip()
            if hostname and hostname != ip_address:
                device_name = hostname
        
        # Try to extract device type from OS detection
        if not device_name:
            # Look for common device indicators
            nmap_lower = nmap_output.lower()
            
            # Check for common device types
            device_keywords = {
                'raspberry pi': 'Raspberry Pi',
                'iphone': 'iPhone',
                'ipad': 'iPad',
                'android': 'Android Device',
                'windows': 'Windows Device',
                'linux': 'Linux Device',
                'mac os': 'Mac OS Device',
                'router': 'Router',
                'switch': 'Network Switch',
                'printer': 'Printer',
                'camera': 'Camera',
                'tv': 'Smart TV',
                'chromecast': 'Chromecast',
                'fire tv': 'Fire TV',
                'roku': 'Roku',
                'alexa': 'Amazon Echo',
                'google home': 'Google Home',
                'nest': 'Nest Device',
                'ring': 'Ring Device',
                'smart': 'Smart Device'
            }
            
            for keyword, name in device_keywords.items():
                if keyword in nmap_lower:
                    device_name = name
                    break
        
        # Try MAC vendor lookup as fallback
        if not device_name:
            # Extract vendor from MAC (first 3 octets)
            mac_prefix = ':'.join(mac_address.split(':')[:3]).upper()
            # Common vendor prefixes (simplified lookup)
            vendor_map = {
                '00:50:56': 'VMware',
                '00:0C:29': 'VMware',
                '00:1B:21': 'Cisco',
                '00:1E:13': 'Cisco',
                'B8:27:EB': 'Raspberry Pi',
                'DC:A6:32': 'Raspberry Pi',
                'E4:5F:01': 'Raspberry Pi',
                '28:E0:2C': 'Apple',
                'F0:DB:E2': 'Apple',
                'AC:DE:48': 'Apple',
                'D8:A2:5E': 'Apple',
                '00:1E:C2': 'Apple',
                '00:23:DF': 'Apple',
                '00:25:00': 'Apple',
                '00:25:4B': 'Apple',
                '00:26:08': 'Apple',
                '00:26:4A': 'Apple',
                '00:26:BB': 'Apple',
                '00:26:C7': 'Apple',
                '00:50:E4': 'Apple',
                '00:56:CD': 'Apple',
                '00:61:71': 'Apple',
                '00:7D:60': 'Apple',
                '00:A0:40': 'Apple',
                '00:C6:10': 'Apple',
                '00:F4:B9': 'Apple',
                '04:0C:CE': 'Apple',
                '04:15:52': 'Apple',
                '04:1E:64': 'Apple',
                '04:26:65': 'Apple',
                '04:4C:59': 'Apple',
                '04:52:C7': 'Apple',
                '04:54:53': 'Apple',
                '04:69:F8': 'Apple',
                '04:DB:56': 'Apple',
                '08:00:07': 'Apple',
                '08:66:98': 'Apple',
                '08:74:02': 'Apple',
                '08:87:C4': 'Apple',
                '0C:3E:9F': 'Apple',
                '0C:4D:E9': 'Apple',
                '0C:74:C2': 'Apple',
                '0C:BC:9F': 'Apple',
                '0C:D7:46': 'Apple',
                '10:93:E9': 'Apple',
                '10:9A:DD': 'Apple',
                '10:DD:B1': 'Apple',
                '14:10:9F': 'Apple',
                '14:7D:DA': 'Apple',
                '14:99:E2': 'Apple',
                '18:65:90': 'Apple',
                '18:9E:FC': 'Apple',
                '18:E7:F4': 'Apple',
                '1C:1A:C0': 'Apple',
                '1C:AB:A7': 'Apple',
                '20:78:F0': 'Apple',
                '20:C9:D0': 'Apple',
                '24:A0:74': 'Apple',
                '24:AB:81': 'Apple',
                '24:E3:14': 'Apple',
                '28:37:37': 'Apple',
                '28:6A:B8': 'Apple',
                '28:CF:DA': 'Apple',
                '2C:1F:23': 'Apple',
                '2C:33:7A': 'Apple',
                '2C:BE:08': 'Apple',
                '30:90:AB': 'Apple',
                '34:15:9E': 'Apple',
                '34:A3:95': 'Apple',
                '38:CA:DA': 'Apple',
                '3C:07:54': 'Apple',
                '3C:AB:8E': 'Apple',
                '40:33:1A': 'Apple',
                '40:6C:8F': 'Apple',
                '40:CB:C0': 'Apple',
                '44:FB:42': 'Apple',
                '48:43:7C': 'Apple',
                '48:A1:95': 'Apple',
                '4C:8D:79': 'Apple',
                '50:EA:D6': 'Apple',
                '54:26:96': 'Apple',
                '54:72:4F': 'Apple',
                '58:55:CA': 'Apple',
                '5C:59:48': 'Apple',
                '5C:95:AE': 'Apple',
                '60:33:4B': 'Apple',
                '60:C5:47': 'Apple',
                '64:B9:E8': 'Apple',
                '68:96:7B': 'Apple',
                '6C:40:08': 'Apple',
                '6C:72:20': 'Apple',
                '6C:8D:C1': 'Apple',
                '70:48:0F': 'Apple',
                '74:E2:F5': 'Apple',
                '78:4F:43': 'Apple',
                '7C:6D:62': 'Apple',
                '7C:D1:C3': 'Apple',
                '80:BE:05': 'Apple',
                '84:38:35': 'Apple',
                '84:FC:FE': 'Apple',
                '88:63:DF': 'Apple',
                '8C:85:90': 'Apple',
                '90:72:40': 'Apple',
                '94:E9:6A': 'Apple',
                '98:01:A7': 'Apple',
                '98:F0:AB': 'Apple',
                '9C:20:7B': 'Apple',
                '9C:84:BF': 'Apple',
                'A0:99:9B': 'Apple',
                'A4:5E:60': 'Apple',
                'A4:C3:61': 'Apple',
                'A8:60:B6': 'Apple',
                'A8:96:8A': 'Apple',
                'AC:1F:74': 'Apple',
                'AC:BC:32': 'Apple',
                'B0:65:BD': 'Apple',
                'B4:F0:AB': 'Apple',
                'B8:53:AC': 'Apple',
                'B8:C7:5D': 'Apple',
                'BC:3B:AF': 'Apple',
                'BC:52:B7': 'Apple',
                'C0:25:E9': 'Apple',
                'C4:2C:03': 'Apple',
                'C8:1E:E7': 'Apple',
                'C8:BC:C8': 'Apple',
                'CC:08:E0': 'Apple',
                'CC:78:5F': 'Apple',
                'D0:03:4B': 'Apple',
                'D0:23:DB': 'Apple',
                'D4:9A:20': 'Apple',
                'D8:30:62': 'Apple',
                'D8:A2:5E': 'Apple',
                'DC:A6:32': 'Raspberry Pi',
                'E0:AC:CB': 'Apple',
                'E4:CE:8F': 'Apple',
                'E8:40:40': 'Apple',
                'EC:35:86': 'Apple',
                'F0:DB:E2': 'Apple',
                'F4:F1:5A': 'Apple',
                'F8:1E:DF': 'Apple',
                'FC:25:3F': 'Apple',
            }
            
            if mac_prefix in vendor_map:
                device_name = vendor_map[mac_prefix]
        
        # Final fallback: use MAC address formatted nicely
        if not device_name:
            device_name = f"Device-{mac_address.replace(':', '')[:6]}"
        
        return device_name
    
    def _is_ssh_connection_alive(self):
        """Check if SSH connection is still alive"""
        if self.ssh_client is None:
            return False
        try:
            # Try to get transport and check if it's active
            transport = self.ssh_client.get_transport()
            if transport is None:
                return False
            return transport.is_active()
        except Exception:
            return False
    
    def _reset_ssh_connection(self):
        """Close and reset SSH connection"""
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
    
    def _get_ssh_connection(self):
        """Get or create SSH connection to router with keepalive and health checks"""
        import time
        current_time = time.time()
        
        # Periodic connection health check (don't check every call to avoid overhead)
        if self.ssh_client is not None:
            if current_time - self.last_connection_check > self.connection_check_interval:
                self.last_connection_check = current_time
                if not self._is_ssh_connection_alive():
                    print("⚠️  SSH connection dead, reconnecting...")
                    self._reset_ssh_connection()
        elif self.ssh_client is None:
            # Always check if None (immediate check)
            self.last_connection_check = current_time
        
        # Create new connection if needed
        if self.ssh_client is None:
            try:
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connect with timeout and keepalive
                self.ssh_client.connect(
                    self.config['router_ip'],
                    username=self.config['router_user'],
                    password=self.config['router_pass'],
                    timeout=10,  # Increased timeout
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Set keepalive to prevent connection timeout
                transport = self.ssh_client.get_transport()
                if transport:
                    transport.set_keepalive(30)  # Send keepalive every 30 seconds
                
                print(f"✅ SSH connected to router: {self.config['router_ip']}")
            except Exception as e:
                print(f"❌ SSH connection failed: {e}")
                self.ssh_client = None
                return None
        
        return self.ssh_client
    
    def _ssh_exec(self, command, timeout=10):
        """Execute command on router via SSH with proper error handling"""
        ssh = self._get_ssh_connection()
        if not ssh:
            return None
        
        try:
            # Execute command with timeout
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            
            # Read output with timeout
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            # Check for errors
            if error and "error" in error.lower():
                print(f"⚠️  SSH command warning: {error[:100]}")
            
            return output
        except paramiko.SSHException as e:
            print(f"⚠️  SSH exec error (SSHException): {e}")
            # Reset connection on SSH errors
            self._reset_ssh_connection()
            return None
        except Exception as e:
            print(f"⚠️  SSH exec error: {e}")
            # Reset connection on other errors
            self._reset_ssh_connection()
            return None
    
    def _ensure_nmap(self):
        """Ensure Nmap is installed on router"""
        check = self._ssh_exec("which nmap")
        if "nmap" not in check:
            print("🔧 Installing Nmap on router...")
            self._ssh_exec("opkg update > /dev/null 2>&1")
            self._ssh_exec("opkg install nmap > /dev/null 2>&1")
    
    def get_mac_from_ip(self, ip_address: str) -> Optional[str]:
        """Get MAC address for a given IP from router ARP table"""
        arp_output = self._ssh_exec("cat /proc/net/arp")
        if not arp_output:
            return None
        
        for line in arp_output.split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3].lower()
                if ip == ip_address and "00:00:00:00:00:00" not in mac:
                    return mac
        return None
    
    def scan_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Scan a specific IP address and return results with MAC
        
        Returns:
            {
                'mac_address': str,
                'ip_address': str,
                'scan_results': str,  # Nmap output
                'is_new_device': bool,
                'device_profile': dict
            }
        """
        with self.lock:
            # Get MAC address for this IP
            mac_address = self.get_mac_from_ip(ip_address)
            if not mac_address:
                print(f"⚠️  Could not find MAC for IP {ip_address}")
                return None
            
            # Check if device already exists (MAC-based tracking)
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT * FROM device_profiles WHERE mac_address = ?', (mac_address,))
            existing = c.fetchone()
            
            is_new_device = existing is None
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if is_new_device:
                # NEW MAC ADDRESS - Perform scan
                print(f"🆕 New MAC detected: {mac_address} (IP: {ip_address})")
                print(f"🔍 Scanning {ip_address} (MAC: {mac_address})...")
                self._ensure_nmap()
                
                nmap_cmd = f"nmap -sV -O -F -Pn --version-light {ip_address}"
                scan_start = time.time()
                scan_output = self._ssh_exec(nmap_cmd)
                scan_duration = round(time.time() - scan_start, 2)
                
                # Extract device name from nmap output
                # Extract device name (with fallback if method doesn't exist)
                try:
                    device_name = self._extract_device_name(scan_output, ip_address, mac_address)
                except AttributeError:
                    # Fallback if method doesn't exist (for old installations)
                    device_name = None
                    if mac_address:
                        # Simple MAC-based name
                        mac_prefix = ':'.join(mac_address.split(':')[:3]).upper()
                        device_name = f"Device-{mac_prefix}"
                
                if not scan_output:
                    print(f"⚠️  Scan failed for {ip_address} (device may not respond to nmap)")
                    print(f"   📝 Adding device to database anyway (without scan results)")
                    scan_output = None  # No scan results, but still add device
                    scan_timestamp = None
                else:
                    print(f"✅ Scan complete ({scan_duration}s)")
                    if device_name:
                        print(f"   📱 Device name: {device_name}")
                    scan_timestamp = timestamp
                
                # Create new device profile (even if scan failed)
                ip_history = json.dumps([ip_address])
                c.execute('''
                    INSERT INTO device_profiles 
                    (mac_address, current_ip, ip_history, scan_results, scan_timestamp, first_seen, last_seen, device_name)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (mac_address, ip_address, ip_history, scan_output, scan_timestamp, timestamp, timestamp, device_name))
                print(f"📝 New device registered: MAC={mac_address}, IP={ip_address}")
            else:
                # EXISTING MAC ADDRESS - NO RESCAN (just update IP history)
                print(f"✅ Known MAC: {mac_address} (IP: {ip_address})")
                print(f"   ⏭️  Skipping scan (MAC already profiled)")
                
                # Get current IP history and scan results
                c.execute('SELECT ip_history, scan_results FROM device_profiles WHERE mac_address = ?', (mac_address,))
                result = c.fetchone()
                ip_history_json = result[0]
                existing_scan_results = result[1]
                ip_history = json.loads(ip_history_json) if ip_history_json else []
                
                # Add new IP if not in history
                if ip_address not in ip_history:
                    ip_history.append(ip_address)
                    print(f"📝 New IP added to device {mac_address}: {ip_address}")
                else:
                    print(f"📝 IP {ip_address} already in history for MAC {mac_address}")
                
                # Update profile (keep existing scan_results, just update IP and timestamp)
                c.execute('''
                    UPDATE device_profiles 
                    SET current_ip = ?,
                        ip_history = ?,
                        last_seen = ?
                    WHERE mac_address = ?
                ''', (ip_address, json.dumps(ip_history), timestamp, mac_address))
                
                # Use existing scan results
                scan_output = existing_scan_results
            
            # Update IP-MAC mapping
            c.execute('''
                INSERT OR REPLACE INTO ip_mac_mapping (ip_address, mac_address, last_seen)
                VALUES (?, ?, ?)
            ''', (ip_address, mac_address, timestamp))
            
            # Add to scan history (only if new device or new IP)
            if is_new_device or ip_address not in ip_history:
                c.execute('''
                    INSERT INTO scan_history (mac_address, ip_address, scan_timestamp, scan_results)
                    VALUES (?, ?, ?, ?)
                ''', (mac_address, ip_address, timestamp, scan_output))
            
            conn.commit()
            
            # Get device profile (handle both old and new schema)
            c.execute('SELECT * FROM device_profiles WHERE mac_address = ?', (mac_address,))
            profile_row = c.fetchone()
            conn.close()
            
            if profile_row:
                # Handle schema with timestamp column (new) or without (old)
                # New schema: id, timestamp, mac_address, current_ip, ip_history, scan_results, scan_timestamp, first_seen, last_seen, device_name
                # Old schema: id, mac_address, first_seen, last_seen, current_ip, ip_history, scan_results, scan_timestamp, device_name
                if len(profile_row) >= 10:
                    # New schema with timestamp
                    profile = {
                        'mac_address': profile_row[2],
                        'first_seen': profile_row[7],
                        'last_seen': profile_row[8],
                        'current_ip': profile_row[3],
                        'ip_history': json.loads(profile_row[4]) if profile_row[4] else [],
                        'scan_results': profile_row[5],
                        'scan_timestamp': profile_row[6],
                        'device_name': profile_row[9] if len(profile_row) > 9 else None
                    }
                else:
                    # Old schema
                    profile = {
                        'mac_address': profile_row[1],
                        'first_seen': profile_row[2],
                        'last_seen': profile_row[3],
                        'current_ip': profile_row[4],
                        'ip_history': json.loads(profile_row[5]) if profile_row[5] else [],
                        'scan_results': profile_row[6],
                        'scan_timestamp': profile_row[7],
                        'device_name': profile_row[8] if len(profile_row) > 8 else None
                    }
            else:
                profile = None
            
            return {
                'mac_address': mac_address,
                'ip_address': ip_address,
                'scan_results': scan_output,
                'is_new_device': is_new_device,
                'device_profile': profile
            }
    
    def get_all_devices_initial_scan(self, own_ip: Optional[str] = None) -> Dict[str, Dict]:
        """
        Scan all devices from router ARP table (for initial startup scan)
        If own_ip is provided, scans it first to ensure it's in the ARP table
        
        Returns dict mapping MAC -> device info
        """
        print("🔍 Performing initial network scan...")
        
        # If own IP provided, scan it first to ensure it's in ARP table
        scanned_devices = {}
        if own_ip and own_ip != "127.0.0.1" and own_ip != "":
            print(f"🎯 Scanning own IP first: {own_ip}")
            try:
                own_mac = self.get_mac_from_ip(own_ip)
                if own_mac:
                    print(f"   ✅ Found own MAC: {own_mac}")
                    result = self.scan_ip(own_ip)
                    if result:
                        scanned_devices[own_mac] = result
                        print(f"   ✅ Own IP scan complete and added to ARP table")
                else:
                    # Try to get MAC from local interface (own IP might not be in router ARP yet)
                    print(f"   ℹ️  Own IP not in router ARP table, will scan after other devices")
                    # We'll scan it after getting all devices from ARP table
            except Exception as e:
                print(f"   ⚠️  Own IP scan error: {e} (continuing)")
        
        # Get ARP table from router
        arp_output = self._ssh_exec("cat /proc/net/arp")
        if not arp_output:
            return scanned_devices
        
        devices = {}
        for line in arp_output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                mac = parts[3].lower()
                if "00:00:00:00:00:00" not in mac and not ip.startswith("127."):
                    devices[mac] = {'ip': ip, 'mac': mac}
        
        print(f"📡 Found {len(devices)} devices on network")
        
        # Scan each device (skip own IP if already scanned)
        for mac, info in devices.items():
            if mac not in scanned_devices:  # Skip if already scanned
                ip = info['ip']
                result = self.scan_ip(ip)
                if result:
                    scanned_devices[mac] = result
        
        # If own IP wasn't scanned yet, try to scan it now (it might be in ARP now)
        if own_ip and own_ip != "127.0.0.1" and own_ip != "":
            own_mac = self.get_mac_from_ip(own_ip)
            if own_mac and own_mac not in scanned_devices:
                print(f"🎯 Scanning own IP now: {own_ip} (MAC: {own_mac})")
                result = self.scan_ip(own_ip)
                if result:
                    scanned_devices[own_mac] = result
                    print(f"   ✅ Own IP scan complete")
        
        return scanned_devices
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict]:
        """Get device profile by MAC address"""
        conn = sqlite3.connect(self.db_file, timeout=30.0)
        c = conn.cursor()
        c.execute('SELECT * FROM device_profiles WHERE mac_address = ?', (mac_address,))
        row = c.fetchone()
        conn.close()
        
        if row:
            # Handle both old and new schema
            if len(row) >= 10:
                # New schema with timestamp
                return {
                    'mac_address': row[2],
                    'first_seen': row[7],
                    'last_seen': row[8],
                    'current_ip': row[3],
                    'ip_history': json.loads(row[4]) if row[4] else [],
                    'scan_results': row[5],
                    'scan_timestamp': row[6],
                    'device_name': row[9] if len(row) > 9 else None
                }
            else:
                # Old schema
                return {
                    'mac_address': row[1],
                    'first_seen': row[2],
                    'last_seen': row[3],
                    'current_ip': row[4],
                    'ip_history': json.loads(row[5]) if row[5] else [],
                    'scan_results': row[6],
                    'scan_timestamp': row[7],
                    'device_name': row[8] if len(row) > 8 else None
                }
        return None
    
    def get_mac_from_ip_cached(self, ip_address: str) -> Optional[str]:
        """Get MAC address from IP using cached database"""
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('SELECT mac_address FROM ip_mac_mapping WHERE ip_address = ?', (ip_address,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return result[0]
        
        # Not in cache, get from router
        return self.get_mac_from_ip(ip_address)
    
    def close(self):
        """Close SSH connection properly"""
        self._reset_ssh_connection()
        print("✅ SSH connection closed")
