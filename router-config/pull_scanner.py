#!/usr/bin/env python3
"""
Router Network Scanner with SQLite Database Storage

This script continuously monitors a router's ARP table to detect new devices
on the network. When a new device (identified by MAC address) is found, it
performs an Nmap scan and stores the results in a SQLite database.

HOW THE SCRIPT WORKS:
1. Connects to the router via SSH using configured credentials
2. Reads the ARP table (/proc/net/arp) to get all connected devices (IP + MAC)
3. Compares found devices against a memory file (scanned_macs.json) to identify new devices
4. For each new device, runs an Nmap scan remotely on the router
5. Stores scan results in a SQLite database (scan_database.db)
6. Updates the memory file to track scanned MAC addresses
7. Repeats every 5 seconds to catch new devices as they connect

DATABASE CREATION:
- The database is automatically created on first run in the Thesis_Scans folder
- Database file: scan_database.db
- Table structure: scans (id, timestamp, mac_address, ip_address, raw_output)
- The init_db() function creates the table if it doesn't exist
- Each scan result is inserted as a new row with timestamp, MAC, IP, and full Nmap output

NOTE: This script currently uses SQLite for local storage. It needs to be linked
with the main SQL dataset (mqttlive) for integration with the broader system.
The connection to mqttlive database is NOT yet implemented.

Author: Lujain
Date: 2024
"""

import paramiko
import time
import os
import datetime
import json
import sqlite3
import re

# ========================= CONFIGURATION =========================
# Configuration MUST be set via router_config.json
# Run installer/setup_router.sh to configure router credentials
# No hardcoded credentials - user must configure before use

# Use PROJECT_DIR or fallback to script directory
PROJECT_DIR = os.environ.get('PROJECT_DIR')
if not PROJECT_DIR:
    PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAVE_FOLDER = os.path.join(PROJECT_DIR, "router-config", "Thesis_Scans")

# Load from router_config.json (REQUIRED)
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "router_config.json")
ROUTER_IP = ""
ROUTER_USER = ""
ROUTER_PASS = ""
ROUTER_ENABLED = False

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            ROUTER_ENABLED = config.get("enabled", False)
            ROUTER_IP = config.get("router_ip", "")
            ROUTER_USER = config.get("router_user", "")
            ROUTER_PASS = config.get("router_pass", "")
    except Exception as e:
        print(f"⚠️  Could not load router_config.json: {e}")
        print("   Run installer/setup_router.sh to configure router scanning")

if not ROUTER_ENABLED:
    print("ℹ️  Router scanning is disabled in configuration")
    print("   Run installer/setup_router.sh to enable and configure")
elif not ROUTER_IP or not ROUTER_USER or not ROUTER_PASS:
    print("❌ Router credentials not configured!")
    print("   Run installer/setup_router.sh to configure router scanning")
# =================================================================

# Create output directory if it doesn't exist
os.makedirs(SAVE_FOLDER, exist_ok=True)

# Database and memory file paths
# Use centralized session.db if available, otherwise fallback to local database
SESSION_LOG_DIR = os.environ.get('SESSION_LOG_DIR')
if SESSION_LOG_DIR and os.path.exists(SESSION_LOG_DIR):
    DB_FILE = os.path.join(SESSION_LOG_DIR, "session.db")  # Use centralized session.db
    MEMORY_FILE = os.path.join(SESSION_LOG_DIR, "scanned_memory.json")  # Store memory in session dir
else:
    DB_FILE = os.path.join(SAVE_FOLDER, "scan_database.db")  # Fallback: local SQLite database file
    MEMORY_FILE = os.path.join(SAVE_FOLDER, "scanned_memory.json")  # JSON file to track scanned MAC addresses

# Load previously scanned MAC addresses from memory file
# This prevents re-scanning devices that have already been scanned
if os.path.exists(MEMORY_FILE):
    with open(MEMORY_FILE, 'r') as f:
        try:
            scanned_macs = set(json.load(f))
        except:
            scanned_macs = set()
else:
    scanned_macs = set()  # Empty set if memory file doesn't exist

def init_db():
    """
    Initializes database connection and ensures tables exist.
    
    Uses centralized session.db if SESSION_LOG_DIR is set, otherwise uses local database.
    Writes to scan_history, device_profiles, and ip_mac_mapping tables in session.db.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Create scan_history table (if using session.db, this might already exist)
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  mac_address TEXT NOT NULL,
                  ip_address TEXT NOT NULL,
                  scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  scan_results TEXT)''')
    
    # Create device_profiles table (if using session.db, this might already exist)
    c.execute('''CREATE TABLE IF NOT EXISTS device_profiles
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  mac_address TEXT UNIQUE NOT NULL,
                  current_ip TEXT,
                  ip_history TEXT,
                  scan_results TEXT,
                  scan_timestamp DATETIME,
                  first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                  device_name TEXT)''')
    
    # Create ip_mac_mapping table (if using session.db, this might already exist)
    c.execute('''CREATE TABLE IF NOT EXISTS ip_mac_mapping
                 (ip_address TEXT PRIMARY KEY,
                  mac_address TEXT NOT NULL,
                  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create legacy 'scans' table for backward compatibility (if using local database)
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  mac_address TEXT,
                  ip_address TEXT,
                  raw_output TEXT)''')
    
    conn.commit()
    conn.close()

def save_scan_to_db(ip, mac, raw_data):
    """
    Inserts a new scan result into the centralized session.db database.
    
    Parameters:
        ip: IP address of the scanned device
        mac: MAC address of the scanned device
        raw_data: Full Nmap scan output as text string
    
    Saves to multiple tables:
    - scan_history: Historical scan records
    - device_profiles: Device information (updates existing or creates new)
    - ip_mac_mapping: IP to MAC address mapping
    - scans: Legacy table for backward compatibility
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1. Insert into scan_history table
        c.execute('''INSERT INTO scan_history 
                     (mac_address, ip_address, scan_timestamp, scan_results) 
                     VALUES (?, ?, CURRENT_TIMESTAMP, ?)''',
                  (mac, ip, raw_data))
        
        # 2. Update or insert into device_profiles table
        c.execute('''SELECT id FROM device_profiles WHERE mac_address = ?''', (mac,))
        existing = c.fetchone()
        
        if existing:
            # Update existing device profile
            c.execute('''UPDATE device_profiles 
                         SET current_ip = ?,
                             scan_results = ?,
                             scan_timestamp = CURRENT_TIMESTAMP,
                             last_seen = CURRENT_TIMESTAMP
                         WHERE mac_address = ?''',
                      (ip, raw_data, mac))
        else:
            # Insert new device profile
            # Try to extract device name from nmap output
            device_name = None
            if raw_data:
                # Simple extraction: look for common patterns
                if 'Linux' in raw_data:
                    device_name = 'Linux Device'
                elif 'Windows' in raw_data:
                    device_name = 'Windows Device'
                elif 'Android' in raw_data:
                    device_name = 'Android Device'
                elif 'iPhone' in raw_data or 'iOS' in raw_data:
                    device_name = 'iOS Device'
                else:
                    device_name = f'Device-{mac[:8].replace(":", "")}'
            
            c.execute('''INSERT INTO device_profiles 
                         (mac_address, current_ip, scan_results, scan_timestamp, device_name, first_seen, last_seen)
                         VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
                      (mac, ip, raw_data, device_name))
        
        # 3. Update or insert into ip_mac_mapping table
        c.execute('''INSERT OR REPLACE INTO ip_mac_mapping 
                     (ip_address, mac_address, last_seen) 
                     VALUES (?, ?, CURRENT_TIMESTAMP)''',
                  (ip, mac))
        
        # 4. Insert into legacy scans table for backward compatibility
        c.execute("INSERT INTO scans (timestamp, mac_address, ip_address, raw_output) VALUES (?, ?, ?, ?)",
                  (timestamp, mac, ip, raw_data))
       
        conn.commit()
        conn.close()
        print(f" [V] Saved to session.db - scan_history, device_profiles, ip_mac_mapping updated")
    except Exception as e:
        print(f" [!] Database Error: {e}")
        import traceback
        traceback.print_exc()

def ssh_exec(client, command):
    """
    Executes a command on the remote router via SSH and returns the output.
    
    Parameters:
        client: Paramiko SSH client object
        command: Command string to execute on the router
    
    Returns:
        Command output as string, or error message if execution fails
    """
    try:
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode().strip()
    except Exception as e:
        return f"Error: {e}"

def ensure_nmap_installed(client):
    """
    Checks if Nmap exists on the router. If not, installs it automatically.
    
    SELF-HEALING FUNCTIONALITY:
    - Checks for Nmap installation using 'which nmap'
    - If missing, automatically runs 'opkg update' and 'opkg install nmap'
    - This ensures the scanner can always run even if Nmap is removed or missing
    
    Parameters:
        client: Paramiko SSH client object
    """
    print(" [?] Checking for Nmap on router...", end=" ", flush=True)
    check = ssh_exec(client, "which nmap")
   
    if "nmap" in check:
        print("Found (Ready).")
    else:
        print("MISSING!")
        print(" [!] Initiating Auto-Repair (Installing Nmap)...")
        # Update package list and install Nmap
        # Output redirected to /dev/null to keep screen clean
        ssh_exec(client, "opkg update > /dev/null 2>&1")
        ssh_exec(client, "opkg install nmap > /dev/null 2>&1")
        print(" [V] Repair Complete. Nmap is installed.")

def get_all_connected_devices(client):
    """
    Retrieves all connected devices from the router's ARP table.
    
    HOW IT WORKS:
    - Executes 'cat /proc/net/arp' on the router via SSH
    - Parses the ARP table output to extract IP and MAC addresses
    - Filters out invalid MAC addresses (00:00:00:00:00:00)
    - Returns a dictionary mapping MAC addresses to IP addresses
    
    Parameters:
        client: Paramiko SSH client object
    
    Returns:
        Dictionary with MAC addresses as keys and IP addresses as values
    """
    print(" [.] Reading Router ARP table...", end=" ")
    raw_arp = ssh_exec(client, "cat /proc/net/arp")
    found_devices = {}
   
    # Parse ARP table (skip header line)
    for line in raw_arp.split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[0]      # IP address is first column
            mac = parts[3].lower()  # MAC address is fourth column
            # Filter out invalid/incomplete MAC addresses
            if "00:00:00:00:00:00" not in mac:
                found_devices[mac] = ip

    print(f"Found {len(found_devices)} active.")
    return found_devices

def main():
    """
    Main execution loop for the network scanner.
    
    MAIN LOOP PROCESS:
    1. Initialize SQLite database (create if missing)
    2. Connect to router via SSH
    3. Get list of all connected devices from ARP table
    4. For each device:
       - Skip if already scanned (checked against memory file)
       - Skip localhost IPs (127.x.x.x)
       - Run Nmap scan on new devices
       - Save results to centralized session.db (scan_history, device_profiles, ip_mac_mapping)
       - Update memory file with scanned MAC address
    5. Wait 5 seconds and repeat
    
    INTEGRATED with mqttlive session.db for centralized logging.
    """
    # Check if router scanning is properly configured
    if not ROUTER_ENABLED:
        print("❌ Router scanning is disabled. Exiting.")
        print("   To enable, run: installer/setup_router.sh")
        return
    
    if not ROUTER_IP or not ROUTER_USER or not ROUTER_PASS:
        print("❌ Router credentials not configured. Exiting.")
        print("   To configure, run: installer/setup_router.sh")
        return
    
    print(f"--- ROUTER NETWORK SCANNER STARTED ---")
    if SESSION_LOG_DIR:
        print(f"✅ Using centralized session.db: {DB_FILE}")
        print(f"   Session directory: {SESSION_LOG_DIR}")
    else:
        print(f"⚠️  SESSION_LOG_DIR not set, using local database: {DB_FILE}")
        print(f"   Set SESSION_LOG_DIR environment variable to use centralized logging")
    init_db()  # Ensure database exists before starting
    print("------------------------------------------")

    while True:
        ssh = None
        try:
            # Establish SSH connection to router
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ROUTER_IP, username=ROUTER_USER, password=ROUTER_PASS, timeout=5)

            # 1. SELF-HEAL CHECK: Ensure Nmap is installed
            ensure_nmap_installed(ssh)

            # 2. SCAN LOGIC: Get all currently connected devices from router ARP table
            targets = get_all_connected_devices(ssh)

            # Process each device
            for mac, ip in targets.items():
                # Skip localhost addresses
                if ip.startswith("127."): 
                    continue

                # Only scan devices we haven't seen before
                if mac not in scanned_macs:
                    print(f"\n[!] NEW TARGET: {ip} [{mac}]")
                    print(f" [>] Running Nmap on Router...", end=" ", flush=True)
                   
                    # Execute Nmap scan remotely on the router
                    # -sV: Version detection, -O: OS detection, -F: Fast scan, -Pn: Skip ping
                    start = time.time()
                    nmap_cmd = f"nmap -sV -O -F -Pn --version-light {ip}"
                    scan_result = ssh_exec(ssh, nmap_cmd)
                    duration = round(time.time() - start, 2)
                   
                    print(f"Done ({duration}s).")

                    # Save scan results to SQLite database
                    save_scan_to_db(ip, mac, scan_result)

                    # Update memory file to mark this MAC as scanned
                    scanned_macs.add(mac)
                    with open(MEMORY_FILE, 'w') as f:
                        json.dump(list(scanned_macs), f)

            ssh.close()
            time.sleep(5)  # Wait 5 seconds before next scan cycle

        except KeyboardInterrupt:
            print("\n[!] Scanner stopped by user.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)  # Wait before retrying on error

if __name__ == "__main__":
    main()
