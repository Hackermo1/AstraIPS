#!/usr/bin/env python3
"""
Complete Snort MQTT Command Executor - Single Script Solution
Everything in one file - no external dependencies needed!

Features:
- Universal topic support (any MQTT topic pattern)
- Command detection and analysis
- Threading support for concurrent operations
- Interface auto-detection and selection
- Built-in MQTT broker management
- SnortLive integration
- Clean, structured output
- Everything in one script!
"""

import sys
import os
from datetime import datetime

# DEBUG: Log initial state - use PROJECT_DIR or fallback to script location
try:
    project_dir = os.environ.get('PROJECT_DIR') or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    debug_log_path = os.path.join(project_dir, "logs", "executor_debug.log")
    os.makedirs(os.path.dirname(debug_log_path), exist_ok=True)
    debug_log = open(debug_log_path, "a")
except Exception:
    debug_log = None

def debug_print(msg):
    if debug_log:
        try:
            debug_log.write(f"[{datetime.now()}] {msg}\n")
            debug_log.flush()
        except Exception:
            pass

debug_print("=" * 60)
debug_print("STARTING snort_mqtt_enhanced.py")
debug_print(f"Python version: {sys.version}")
debug_print(f"Initial sys.path: {sys.path}")
debug_print(f"PYTHONPATH env: {os.environ.get('PYTHONPATH', 'NOT SET')}")

# Add user site-packages to path for global installs
user_site = os.path.expanduser("~/.local/lib/python3.11/site-packages")
debug_print(f"User site-packages: {user_site}")
debug_print(f"User site exists: {os.path.exists(user_site)}")

if os.path.exists(user_site):
    # Force add to beginning of path
    if user_site in sys.path:
        sys.path.remove(user_site)
    sys.path.insert(0, user_site)
    debug_print(f"Added user site to sys.path")

# Also check PYTHONPATH environment variable
pythonpath = os.environ.get('PYTHONPATH', '')
debug_print(f"PYTHONPATH from env: {pythonpath}")
if pythonpath:
    for path in pythonpath.split(':'):
        if path and os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)
            debug_print(f"Added PYTHONPATH entry: {path}")

debug_print(f"Final sys.path: {sys.path}")

# Try importing paho with detailed error logging
try:
    debug_print("Attempting to import paho.mqtt.client...")
    import paho.mqtt.client as mqtt
    debug_print("✅ Successfully imported paho.mqtt.client")
except ImportError as e:
    debug_print(f"❌ FAILED to import paho.mqtt.client: {e}")
    debug_print(f"   Error type: {type(e).__name__}")
    debug_print(f"   sys.path at failure: {sys.path}")
    # Try to find where paho might be
    import subprocess
    try:
        result = subprocess.run(['python3', '-c', 'import paho.mqtt.client'], 
                              capture_output=True, text=True, timeout=5)
        debug_print(f"   Direct python3 test: {result.stderr}")
    except Exception as e2:
        debug_print(f"   Could not test direct import: {e2}")
    debug_log.close()
    raise
except Exception as e:
    debug_print(f"❌ UNEXPECTED ERROR importing paho: {e}")
    debug_log.close()
    raise
import signal
import sys
import socket
import os
import threading
import time
import subprocess
import argparse
import json
import re
import base64
import binascii
import queue
from shlex import split
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future

# Import database logger - try multiple paths
try:
    import sys as sys_module
    # Add common paths to find the logger
    # Auto-detect paths relative to this script's location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    possible_paths = [
        script_dir,  # Same directory as this script
        project_dir,  # Parent directory (project root)
        os.getcwd(),  # Current working directory
    ]
    for path in possible_paths:
        if path and path not in sys_module.path:
            sys_module.path.insert(0, path)
    
    from snort_mqtt_logger import SnortMQTTLogger
    # Get session log directory from environment variable (set by mqttlive)
    SESSION_LOG_DIR = os.environ.get('SESSION_LOG_DIR', '.')
    # Validate SESSION_LOG_DIR is not empty
    if not SESSION_LOG_DIR or SESSION_LOG_DIR.strip() == '':
        SESSION_LOG_DIR = '.'
    # Ensure directory exists
    if SESSION_LOG_DIR and SESSION_LOG_DIR.strip():
        if not os.path.exists(SESSION_LOG_DIR):
            os.makedirs(SESSION_LOG_DIR, exist_ok=True)
    DB_PATH = os.path.join(SESSION_LOG_DIR, 'session.db')
    DB_LOGGER = SnortMQTTLogger(DB_PATH)
    DB_LOGGING_ENABLED = True
    print(f"✅ Database logging enabled: {DB_PATH}")
except Exception as e:
    import traceback
    print(f"⚠️  Database logging disabled: {e}")
    if 'traceback' in locals():
        print(f"   Traceback: {traceback.format_exc()}")
    DB_LOGGER = None
    DB_LOGGING_ENABLED = False
    DB_PATH = None

# ============================================================================
# COMMAND DETECTION MODULE (Built-in)
# ============================================================================

class MessageType(Enum):
    NORMAL = "NORMAL"
    COMMAND = "COMMAND"
    RESPONSE = "RESPONSE"
    UNKNOWN = "UNKNOWN"

@dataclass
class CommandAnalysis:
    message_type: MessageType
    confidence: float
    detected_commands: List[str]
    suspicious_patterns: List[str]
    is_encoded: bool
    encoding_type: Optional[str]
    risk_level: str

class MQTTCommandDetector:
    def __init__(self):
        # Command patterns (case-insensitive) - Improved for better detection
        self.command_patterns = {
            'system': [
                # Basic commands
                r'\b(whoami|id|uname|hostname|uptime|date|time)\b',
                r'\b(ps|top|htop|kill|killall|pkill)\b',
                r'\b(df|du|free|vmstat|iostat)\b',
                r'\b(ls|dir|pwd|cd|mkdir|rmdir|rm|cp|mv|chmod|chown)\b',
                r'\b(cat|head|tail|grep|awk|sed|cut|sort|uniq)\b',
                r'\b(find|locate|which|whereis)\b',
                r'\b(netstat|ss|lsof|fuser)\b',
                r'\b(ifconfig|ip|route|arp|ping|traceroute|nslookup|dig)\b',
                r'\b(wget|curl|nc|netcat|telnet|ssh|scp|rsync)\b',
                r'\b(sudo|su|passwd|useradd|userdel|usermod)\b',
                r'\b(systemctl|service|init|rc)\b',
                r'\b(crontab|at|batch)\b',
                r'\b(history|alias|export|source)\b',
                r'\b(env|printenv|set|unset)\b',
                r'\b(which|type|command|hash)\b',
                # Commands with arguments (more flexible)
                r'\b(sudo\s+\w+)\b',  # Match "sudo command"
                r'(ls\s+.*)',  # Match "ls" with any arguments
                r'\b(ps\s+[-\w\s]*)\b',  # Match "ps" with any arguments
                r'\b(ifconfig\s*[-\w\s]*)\b',  # Match "ifconfig" with any arguments
                r'\b(netstat\s+[-\w\s]*)\b',  # Match "netstat" with any arguments
                r'\b(cat\s+[-\w\s/.]*)\b',  # Match "cat" with any arguments
                r'\b(grep\s+[-\w\s]*)\b',  # Match "grep" with any arguments
                r'\b(awk\s+[-\w\s]*)\b',  # Match "awk" with any arguments
                r'\b(sed\s+[-\w\s]*)\b',  # Match "sed" with any arguments
                r'\b(head\s+[-\w\s]*)\b',  # Match "head" with any arguments
                r'\b(tail\s+[-\w\s]*)\b',  # Match "tail" with any arguments
                r'\b(find\s+[-\w\s]*)\b',  # Match "find" with any arguments
                r'\b(ping\s+[-\w\s.]*)\b',  # Match "ping" with any arguments
                r'\b(wget\s+[-\w\s]*)\b',  # Match "wget" with any arguments
                r'\b(curl\s+[-\w\s]*)\b'  # Match "curl" with any arguments
            ],
            'file_ops': [
                r'\b(touch|echo|printf|read|write)\b',
                r'\b(tar|gzip|gunzip|zip|unzip)\b',
                r'\b(dd|hexdump|od|xxd)\b',
                r'\b(file|stat|test|\[|\[\[)\b',
                r'\b(ln|ln -s|symlink)\b'
            ],
            'network': [
                r'\b(nc|netcat|ncat)\b',
                r'\b(telnet|ssh|scp|rsync)\b',
                r'\b(wget|curl|wget|fetch)\b',
                r'\b(ftp|sftp|tftp)\b',
                r'\b(nmap|masscan|zmap)\b',
                r'\b(tcpdump|wireshark|tshark)\b',
                r'\b(iptables|ufw|firewall)\b'
            ],
            'process': [
                r'\b(ps|pstree|pgrep|pidof)\b',
                r'\b(kill|killall|pkill|kill -9)\b',
                r'\b(nohup|screen|tmux|disown)\b',
                r'\b(bg|fg|jobs)\b',
                r'\b(exec|eval|source)\b'
            ],
            'shell': [
                r'\b(bash|sh|zsh|fish|csh|tcsh)\b',
                r'\b(python|python3|perl|ruby|node|php)\b',
                r'\b(awk|sed|grep|cut|sort|uniq)\b',
                r'\b(if|for|while|case|function)\b',
                r'\b(&&|\|\||;|&|>|>>|2>|2>&1)\b'
            ],
            'dangerous': [
                r'\b(rm -rf|rm -f|rm -r)\b',
                r'\b(mkfs|fdisk|parted|dd if=)\b',
                r'\b(chmod 777|chmod 000)\b',
                r'\b(passwd|userdel|groupdel)\b',
                r'\b(systemctl stop|service stop)\b',
                r'\b(shutdown|reboot|halt|poweroff)\b',
                r'\b(init 0|init 6)\b'
            ]
        }
        
        self.response_patterns = [
            r'\b(OK|SUCCESS|COMPLETED|DONE)\b',
            r'\b(ERROR|FAILED|EXCEPTION|TIMEOUT)\b',
            r'\b(EXIT CODE|RETURN CODE|STATUS)\b',
            r'\b(STDOUT|STDERR|OUTPUT|RESULT)\b'
        ]
        
        self.suspicious_patterns = [
            r'[;&|`$(){}]',
            r'\\x[0-9a-fA-F]{2}',
            r'%[0-9a-fA-F]{2}',
            r'base64|b64',
            r'powershell|cmd|cmd\.exe',
            r'wget.*http|curl.*http',
            r'nc.*-l.*-p|netcat.*-l.*-p',
            r'python.*-c|perl.*-e|ruby.*-e',
            r'eval\(|exec\(|system\(',
        ]
        
        # Compile regex patterns
        self.compiled_patterns = {}
        for category, patterns in self.command_patterns.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        self.compiled_response_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.response_patterns
        ]
        
        self.compiled_suspicious_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_patterns
        ]

    def detect_encoding(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Detect if payload is encoded"""
        try:
            decoded = base64.b64decode(payload)
            if decoded != payload.encode():
                return True, "base64"
        except:
            pass
        
        try:
            if len(payload) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in payload):
                decoded = binascii.unhexlify(payload)
                return True, "hex"
        except:
            pass
        
        if '%' in payload and re.search(r'%[0-9a-fA-F]{2}', payload):
            return True, "url"
        
        return False, None

    def analyze_payload(self, payload: str, topic: str = "") -> CommandAnalysis:
        """Analyze MQTT payload - EVERYTHING is treated as a potential command"""
        if not payload or not payload.strip():
            return CommandAnalysis(
                message_type=MessageType.NORMAL,
                confidence=0.0,
                detected_commands=[],
                suspicious_patterns=[],
                is_encoded=False,
                encoding_type=None,
                risk_level="LOW"
            )
        
        clean_payload = payload.strip()
        is_encoded, encoding_type = self.detect_encoding(clean_payload)
        
        # Decode if necessary
        analysis_payload = clean_payload
        if is_encoded and encoding_type == "base64":
            try:
                analysis_payload = base64.b64decode(clean_payload).decode('utf-8', errors='ignore')
            except:
                analysis_payload = clean_payload
        elif is_encoded and encoding_type == "hex":
            try:
                analysis_payload = binascii.unhexlify(clean_payload).decode('utf-8', errors='ignore')
            except:
                analysis_payload = clean_payload
        
        # SIMPLE LOGIC: Everything is a command until proven otherwise
        # This catches command chaining, complex commands, and everything else
        
        detected_commands = [analysis_payload]  # Everything is a command
        command_confidence = 0.8  # Start high since we treat everything as command
        
        # Look for obvious command patterns for confidence boost
        common_commands = ['ls', 'ps', 'whoami', 'date', 'cat', 'grep', 'awk', 'sed', 'find', 'curl', 'wget', 'ssh', 'scp', 'rsync', 'sudo', 'su', 'kill', 'pkill', 'systemctl', 'service', 'crontab', 'cron', 'at', 'history', 'env', 'export', 'alias', 'which', 'type', 'command', 'hash', 'uname', 'hostname', 'uptime', 'df', 'du', 'free', 'vmstat', 'iostat', 'netstat', 'ss', 'lsof', 'fuser', 'ifconfig', 'ip', 'route', 'arp', 'ping', 'traceroute', 'nslookup', 'dig', 'nc', 'netcat', 'telnet', 'passwd', 'useradd', 'userdel', 'usermod', 'chmod', 'chown', 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'head', 'tail', 'sort', 'uniq', 'cut', 'tr', 'wc']
        
        if any(cmd in analysis_payload.lower() for cmd in common_commands):
            command_confidence = 1.0
            print(f"🎯 COMMAND DETECTED: {analysis_payload}")
        
        # Check for command chaining patterns
        chain_patterns = ['&&', '||', ';', '|', '>', '>>', '<', '<<', '&', '$(', '`', '&&', '||']
        if any(chain in analysis_payload for chain in chain_patterns):
            command_confidence = 1.0
            print(f"🔗 COMMAND CHAINING DETECTED: {analysis_payload}")
        
        # Check for shell metacharacters
        shell_chars = ['$', '`', '(', ')', '[', ']', '{', '}', '*', '?', '~', '!', '#', '@', '%', '^', '&', '|', '\\', ';', ':', '"', "'", '<', '>', '=', '+', '-', '_', '.', ',', '/']
        if any(char in analysis_payload for char in shell_chars):
            command_confidence = max(command_confidence, 0.9)
        
        # Determine risk level based on content
        risk_level = "LOW"
        dangerous_keywords = ['rm -rf', 'sudo', 'su ', 'passwd', 'userdel', 'kill', 'pkill', 'systemctl', 'service', 'crontab', 'cron', 'at', 'history', 'env', 'export', 'alias', 'which', 'type', 'command', 'hash', 'uname', 'hostname', 'uptime', 'df', 'du', 'free', 'vmstat', 'iostat', 'netstat', 'ss', 'lsof', 'fuser', 'ifconfig', 'ip', 'route', 'arp', 'ping', 'traceroute', 'nslookup', 'dig', 'nc', 'netcat', 'telnet', 'passwd', 'useradd', 'userdel', 'usermod', 'chmod', 'chown', 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'head', 'tail', 'sort', 'uniq', 'cut', 'tr', 'wc', 'grep', 'awk', 'sed', 'find', 'locate', 'which', 'whereis']
        
        if any(keyword in analysis_payload.lower() for keyword in dangerous_keywords):
            risk_level = "MEDIUM"
        
        if any(dangerous in analysis_payload.lower() for dangerous in ['rm -rf', 'sudo rm', 'sudo su', 'passwd', 'userdel', 'kill -9', 'pkill -9']):
            risk_level = "HIGH"
        
        # Always treat as command
        message_type = MessageType.COMMAND
        
        return CommandAnalysis(
            message_type=message_type,
            confidence=command_confidence,
            detected_commands=detected_commands,
            suspicious_patterns=[],
            is_encoded=is_encoded,
            encoding_type=encoding_type,
            risk_level=risk_level
        )

# ============================================================================
# THREADING MANAGER (Built-in)
# ============================================================================

class ThreadingManager:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        self.message_queue = queue.Queue()
        self.running = True

    def start_thread_pool_task(self, name: str, target: Callable, args: tuple = (), kwargs: dict = None) -> Future:
        """Start a task in the thread pool"""
        if kwargs is None:
            kwargs = {}
        return self.thread_pool.submit(target, *args, **kwargs)

    def shutdown(self, timeout: float = 10.0):
        """Shutdown the threading manager"""
        self.running = False
        self.thread_pool.shutdown(wait=True)

    def get_statistics(self) -> Dict[str, Any]:
        """Get threading statistics"""
        return {
            'max_workers': self.max_workers,
            'queue_size': self.message_queue.qsize()
        }

# ============================================================================
# INTERFACE DETECTION (Built-in)
# ============================================================================

def detect_interfaces():
    """Detect available network interfaces"""
    interfaces = []
    up_interfaces = []
    down_interfaces = []
    
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        for line in lines:
            if ': ' in line and 'state' in line:
                parts = line.split(':')
                if len(parts) >= 3:
                    iface = parts[1].strip()
                    status_part = parts[2]
                    
                    # Extract status
                    status = "DOWN"
                    if "state UP" in status_part:
                        status = "UP"
                    elif "state DOWN" in status_part:
                        status = "DOWN"
                    
                    # Get additional info
                    try:
                        ip_result = subprocess.run(['ip', 'addr', 'show', iface], 
                                                 capture_output=True, text=True)
                        ip_addr = ""
                        for ip_line in ip_result.stdout.split('\n'):
                            if 'inet ' in ip_line and not '127.0.0.1' in ip_line:
                                ip_addr = ip_line.split()[1].split('/')[0]
                                break
                    except:
                        ip_addr = ""
                    
                    interface_info = f"{iface}:{status}:{ip_addr}"
                    interfaces.append(interface_info)
                    
                    if status == "UP":
                        up_interfaces.append(interface_info)
                    else:
                        down_interfaces.append(interface_info)
    
    except Exception as e:
        print(f"Warning: Could not detect interfaces: {e}")
        # Fallback
        interfaces = ["lo:UP:127.0.0.1", "any:UP:0.0.0.0"]
        up_interfaces = interfaces
        down_interfaces = []
    
    return interfaces, up_interfaces, down_interfaces

def select_interface():
    """Let user select Ethernet interface (INLINE MODE ONLY - Cable Ethernet Required)"""
    import re
    interfaces, up_interfaces, down_interfaces = detect_interfaces()
    
    print("📡 Available Ethernet Interfaces (INLINE MODE ONLY):")
    print("⚠️  NOTE: Must be CABLE ETHERNET interface (eth*, en*, ens*, enp*, eno*)")
    print("⚠️  Wireless interfaces (wlan*, wlp*) are NOT supported for inline mode")
    print()
    
    index = 1
    interface_map = {}
    eth_interfaces = []
    eth_pattern = re.compile(r'^(eth|en|ens|enp|eno)')
    
    if up_interfaces:
        print("🟢 Active Ethernet Interfaces:")
        for iface_info in up_interfaces:
            iface, status, ip_addr = iface_info.split(':')
            if eth_pattern.match(iface):
                eth_interfaces.append(iface_info)
                print(f"  {index}) ✅ {iface}")
                print(f"     Status: {status}")
                if ip_addr:
                    print(f"     IP: {ip_addr}")
                print()
                interface_map[index] = iface
                index += 1
    
    if down_interfaces:
        print("🔴 Inactive Ethernet Interfaces:")
        for iface_info in down_interfaces:
            iface, status, ip_addr = iface_info.split(':')
            if eth_pattern.match(iface):
                eth_interfaces.append(iface_info)
                print(f"  {index}) ❌ {iface} ({status})")
                interface_map[index] = iface
                index += 1
    
    if not eth_interfaces:
        print("❌ No Ethernet interfaces found!")
        print("⚠️  ERROR: Inline mode requires a CABLE ETHERNET interface.")
        print("   Please connect an Ethernet cable and ensure interface is available.")
        print("   Supported interfaces: eth*, en*, ens*, enp*, eno*")
        sys.exit(1)
    
    while True:
        try:
            msg = "\nSelect Ethernet interface (1-{}): ".format(len(interface_map))
            choice = input(msg).strip()
            choice_num = int(choice)
            if 1 <= choice_num <= len(interface_map):
                selected = interface_map[choice_num]
                print(f"✅ Selected: {selected} (INLINE MODE)")
                return selected
            else:
                print(f"Please enter a number between 1 and {len(interface_map)}")
        except (ValueError, KeyboardInterrupt):
            print("❌ Invalid choice. Please select a valid Ethernet interface.")
            sys.exit(1)

class SnortMQTTExecutor:
    def __init__(self, interface="lo", host="127.0.0.1", port=1883, max_workers=10):
        self.interface = interface
        self.host = host
        self.port = port
        self.running = True
        self.client = None
        self.threading_manager = ThreadingManager(max_workers)
        self.command_detector = MQTTCommandDetector()
        
        # Prevent response loops
        self.last_response_topic = None
        self.last_response_time = 0
        
        # AI Server integration
        self.ai_socket_path = "/tmp/ai_socket.sock"
        self.ai_available = self.check_ai_server()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)
    
    def check_ai_server(self):
        """Check if AI server is available"""
        try:
            if os.path.exists(self.ai_socket_path):
                # Try to connect briefly
                test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_sock.settimeout(0.5)
                test_sock.connect(self.ai_socket_path)
                test_sock.close()
                print("🤖 AI Server: Connected and ready")
                return True
            else:
                print("⚠️  AI Server: Socket not found (AI analysis disabled)")
                return False
        except Exception as e:
            print(f"⚠️  AI Server: Not available ({e}) - AI analysis disabled")
            return False
    
    def query_ai_server(self, device_ip, command):
        """Query AI server for command analysis"""
        if not self.ai_available:
            return None
        
        try:
            ai_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ai_sock.settimeout(2)
            ai_sock.connect(self.ai_socket_path)
            
            # Send: "device_ip|command"
            data_to_send = f"{device_ip}|{command}\n"
            ai_sock.sendall(data_to_send.encode())
            
            # Receive verdict
            verdict = ai_sock.recv(1024).decode().strip()
            ai_sock.close()
            
            return verdict
        except Exception as e:
            print(f"⚠️  AI Server query failed: {e}")
            return None

    def execute_command(self, command, timeout=10):
        """Execute command safely"""
        if not command.strip():
            return "ERROR: Empty command"
        
        start_time = time.time()
        device_ip = self.host if self.host != "0.0.0.0" else "127.0.0.1"
        
        try:
            print(f"🔧 EXECUTING: {command}")
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=True
            )
            execution_time = time.time() - start_time
            output = process.stdout.decode().strip()
            error = process.stderr.decode().strip()
            
            result = output if process.returncode == 0 else f"ERROR({process.returncode}): {error}"
            success = process.returncode == 0
            print(f"📤 RESULT: {result[:100]}{'...' if len(result) > 100 else ''}")
            
            # Log to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    DB_LOGGER.log_command_execution({
                        'device_ip': device_ip,
                        'command': command,
                        'result': result[:1000] if len(result) <= 1000 else result[:1000] + "...",
                        'success': success,
                        'execution_time': execution_time,
                        'ai_verdict': 'N/A'  # Will be updated in process_message
                    })
                except Exception as e:
                    print(f"   ⚠️  Database logging error: {e}")
            
            return result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            error_msg = "ERROR: Command timed out"
            print(f"⏰ {error_msg}")
            
            # Log to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    DB_LOGGER.log_command_execution({
                        'device_ip': device_ip,
                        'command': command,
                        'result': error_msg,
                        'success': False,
                        'execution_time': execution_time,
                        'ai_verdict': 'N/A'
                    })
                except:
                    pass
            
            return error_msg
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"FAILED: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    DB_LOGGER.log_command_execution({
                        'device_ip': device_ip,
                        'command': command,
                        'result': error_msg,
                        'success': False,
                        'execution_time': execution_time,
                        'ai_verdict': 'N/A'
                    })
                except:
                    pass
            
            return error_msg

    def process_message(self, topic, payload):
        """Process MQTT message with command detection"""
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Skip our own response messages to prevent loops
            if (topic.endswith('/response') or
                topic.endswith('/result') or
                topic.endswith('/response_result') or
                'response_result' in topic or
                payload.startswith('OK:') or
                payload.startswith('FAILED:') or
                payload.startswith('ERROR:') or
                payload.startswith('command received:') or
                payload.startswith('results:')):
                return
        
            # Analyze the message
            analysis = self.command_detector.analyze_payload(payload, topic)
            
            # Display message
            print(f"📨 [{timestamp}] Topic: {topic}")
            print(f"📝 Message: {payload[:100]}{'...' if len(payload) > 100 else ''}")
            
            # Show analysis results
            if analysis.message_type == MessageType.COMMAND:
                print(f"⚡ COMMAND DETECTED: {', '.join(analysis.detected_commands[:3])}")
                if len(analysis.detected_commands) > 3:
                    print(f"   (+{len(analysis.detected_commands) - 3} more commands)")
                print(f"🎯 Confidence: {analysis.confidence:.2f}")
                print(f"⚠️  Risk Level: {analysis.risk_level.upper()}")
                
                if analysis.is_encoded:
                    print(f"🔐 Encoded: {analysis.encoding_type}")
                
                if analysis.suspicious_patterns:
                    print(f"🚨 Suspicious patterns: {len(analysis.suspicious_patterns)}")
                
                # Query AI Server for ML analysis
                device_ip = self.host if self.host != "0.0.0.0" else "127.0.0.1"
                ai_verdict = self.query_ai_server(device_ip, payload)
                
                # Log AI analysis to database
                if DB_LOGGING_ENABLED and DB_LOGGER and ai_verdict:
                    try:
                        DB_LOGGER.log_ai_analysis({
                            'device_ip': device_ip,
                            'command': payload,
                            'verdict': ai_verdict.strip(),
                            'is_malicious': ai_verdict.strip() == "BLOCK",
                            'confidence': None,  # AI server doesn't return confidence yet
                            'reason': None,
                            'user_id': device_ip,
                            'profile_context': None
                        })
                    except Exception as e:
                        print(f"   ⚠️  AI analysis logging error: {e}")
                
                if ai_verdict:
                    if ai_verdict.strip() == "BLOCK":
                        print(f"🚫 AI ANALYSIS: MALICIOUS - Command BLOCKED by ML model")
                        print(f"   ⚠️  This command was flagged as suspicious by machine learning")
                        # Don't execute blocked commands
                        result = "BLOCKED: Command flagged as malicious by AI analysis"
                        
                        # Log blocked command execution
                        if DB_LOGGING_ENABLED and DB_LOGGER:
                            try:
                                DB_LOGGER.log_command_execution({
                                    'device_ip': device_ip,
                                    'command': payload,
                                    'result': 'BLOCKED',
                                    'success': False,
                                    'execution_time': 0.0,
                                    'ai_verdict': 'BLOCK'
                                })
                            except:
                                pass
                    else:
                        print(f"✅ AI ANALYSIS: ALLOWED - Command approved by ML model")
                        # Execute the command
                        result = self.execute_command(payload)
                        
                        # Update database with AI verdict for successful execution
                        if DB_LOGGING_ENABLED and DB_LOGGER:
                            try:
                                # Update the last command execution with AI verdict
                                # Note: This is a simple approach - in production you'd want to update the last record
                                pass  # The execute_command already logs, we'll update it separately if needed
                            except:
                                pass
                else:
                    # AI server not available, execute anyway
                    print(f"⚠️  AI analysis unavailable, executing command...")
                    result = self.execute_command(payload)
                
                # Format the response with command and result
                formatted_response = f"command received: {payload}\nresults: {result}"
                
                # MQTT ROUTER: Intercept, execute, and replace with result on same topic
                # Temporarily unsubscribe to prevent receiving our own published message
                self.client.unsubscribe(topic)
                
                # Publish the formatted result
                self.client.publish(topic, formatted_response, qos=1)
                print(f"📤 [{timestamp}] Result published to {topic} (routed)")
                
                # Resubscribe to continue monitoring
                self.client.subscribe(topic, qos=1)
                
                # Mark this as a response to prevent re-execution
                self.last_response_topic = topic
                self.last_response_time = time.time()
                
            elif analysis.message_type == MessageType.RESPONSE:
                print(f"📤 RESPONSE DETECTED")
                print(f"📋 Response: {payload[:200]}{'...' if len(payload) > 200 else ''}")
                
            else:
                print(f"📄 Normal message")
                if analysis.confidence > 0.1:
                    print(f"🔍 Analysis confidence: {analysis.confidence:.2f}")

        except Exception as e:
            print(f"❌ [{datetime.now().strftime('%H:%M:%S')}] Error processing message: {str(e)}")

    def on_connect(self, client, userdata, flags, rc, properties=None):
        """MQTT connection callback"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        if rc == 0:
            print(f"✅ [{timestamp}] Connected to MQTT broker")
            client.subscribe("#")  # Subscribe to ALL topics
            print(f"📡 Subscribed to ALL topics (#)")
            print(f"🌐 Universal topic support enabled")
        else:
            print(f"❌ [{timestamp}] Connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc, properties=None):
        """MQTT disconnection callback"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"🔌 [{timestamp}] Disconnected from broker (code {rc})")
        if self.running:
            print("🔄 Attempting reconnect...")
            time.sleep(5)
            # Connect to MQTT Broker (Our internal router on 1889)
            # We use 1889 to avoid conflicts with system mosquitto on 1883
            mqtt_port = 1889
            try:
                print(f"🔌 Connecting to internal MQTT Router on port {mqtt_port}...")
                client.connect("127.0.0.1", mqtt_port, 60)
            except Exception as e:
                print(f"❌ Failed to connect to internal MQTT Router on port {mqtt_port}: {e}")
                print("   Trying standard port 1883 as fallback...")
                try:
                    client.connect("127.0.0.1", 1883, 60)
                    print("⚠️  Connected on fallback port 1883")
                except:
                    print("❌ Could not connect to any MQTT broker. Exiting.")
                    import sys
                    sys.exit(1)

    def on_message(self, client, userdata, msg):
        """MQTT message callback"""
        try:
            payload = msg.payload.decode()
            topic = msg.topic
            
            # Log MQTT traffic to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    # Determine source IP (best effort since we're the client receiving it)
                    # In a real broker we'd know the source, but here we are a client
                    source_ip = "unknown" 
                    
                    DB_LOGGER.log_mqtt_traffic({
                        'packet_type': 'PUBLISH',
                        'topic': topic,
                        'payload': payload[:1000] if len(payload) <= 1000 else payload[:1000] + "...",
                        'source_ip': source_ip,
                        'dest_ip': self.host,
                        'source_port': 0,
                        'dest_port': self.port,
                        'qos': msg.qos,
                        'retain': msg.retain,
                        'dup': False
                    })
                except Exception as e:
                    print(f"   ⚠️  MQTT traffic logging error: {e}")

            # Process message in thread pool
            self.threading_manager.start_thread_pool_task(
                f"msg_{int(time.time() * 1000)}", 
                self.process_message, 
                (topic, payload)
            )
            
        except Exception as e:
            print(f"❌ [{datetime.now().strftime('%H:%M:%S')}] Error in message callback: {str(e)}")

    def ensure_mosquitto(self):
        """Ensure Mosquitto broker is running"""
        try:
            subprocess.check_output(["pgrep", "mosquitto"])
            print(f"✅ Mosquitto broker already running")
            return True
        except subprocess.CalledProcessError:
            print(f"🚀 Starting Mosquitto broker...")
            try:
                subprocess.Popen(["mosquitto", "-v", "-d"])
                time.sleep(3)
                print(f"✅ Mosquitto broker started")
                return True
            except FileNotFoundError:
                print(f"❌ Mosquitto not found! Please install it:")
                print(f"   sudo apt install mosquitto mosquitto-clients")
                return False

    def handle_exit(self, sig, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Shutting down...")
        self.running = False
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except:
                pass  # Ignore errors during shutdown
        try:
            self.threading_manager.shutdown()
        except:
            pass  # Ignore errors during shutdown
        # Exit cleanly - suppress threading exception during shutdown
        import sys
        sys.exit(0)

    def run(self):
        """Main run method"""
        print("🔐 Complete Snort MQTT Command Executor")
        print("=" * 50)
        print("Features:")
        print("  • Universal topic support (any MQTT topic pattern)")
        print("  • Command detection and analysis")
        print("  • Threading support for concurrent operations")
        print("  • Interface auto-detection and selection")
        print("  • Built-in MQTT broker management")
        print("  • Everything in one script!")
        print()
        
        print(f"🌐 MQTT Broker: {self.host}:{self.port}")
        print(f"📡 Interface: {self.interface}")
        print(f"🧵 Max Workers: {self.threading_manager.max_workers}")
        print()
        
        # Ensure Mosquitto is running
        if not self.ensure_mosquitto():
            print("❌ Cannot start without MQTT broker")
            return
        
        # Setup MQTT client
        self.client = mqtt.Client(client_id="EnhancedSnortMQTTExecutor", protocol=mqtt.MQTTv5)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        
        try:
            print(f"🔗 Connecting to MQTT broker at {self.host}:{self.port}...")
            self.client.connect(self.host, self.port, 60)
            self.client.loop_start()
            
            print("✅ Complete MQTT Command Executor is running!")
            print("📡 Listening for messages on ALL topics (#)")
            print("🔍 Command detection: ENABLED")
            print("🧵 Threading: ENABLED")
            print("🎯 Universal topic support: ENABLED")
            print()
            print("💡 Test with any topic:")
            print("   mosquitto_pub -h localhost -t 'any/topic/here' -m 'whoami'")
            print("   mosquitto_pub -h localhost -t 'devices/sensor1/command' -m 'ls -la'")
            print("   mosquitto_pub -h localhost -t 'my/custom/topic' -m 'date'")
            print()
            print("Press Ctrl+C to stop")
            print("=" * 50)
            
            # Keep main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.handle_exit(None, None)
        except Exception as e:
            print(f"❌ Error: {e}")
            self.threading_manager.shutdown()
            sys.exit(1)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Complete Snort MQTT Command Executor')
    parser.add_argument('--interface', '-i', default=None, 
                       help='Network interface to monitor (auto-detect if not specified)')
    parser.add_argument('--host', default='127.0.0.1', 
                       help='MQTT broker host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=1883, 
                       help='MQTT broker port (default: 1883)')
    parser.add_argument('--max-workers', type=int, default=10, 
                       help='Maximum number of worker threads (default: 10)')
    parser.add_argument('--auto-start', action='store_true',
                       help='Auto-start without interface selection (will auto-select first Ethernet interface)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # INLINE MODE ONLY
    
    # Auto-detect interface if not specified
    if args.interface is None:
        if args.auto_start:
            print("🚀 Auto-starting with loopback interface...")
            args.interface = select_interface()  # Inline mode requires Ethernet
        else:
            print("🔍 Auto-detecting network interface...")
            args.interface = select_interface()
        print()
    
    # Show mode information
    if args.verbose:
        print(f"🔍 Verbose Mode: Enabled")
        print(f"📡 Interface: {args.interface}")
        print(f"🌐 Host: {args.host}")
        print(f"🔌 Port: {args.port}")
        print(f"🧵 Max Workers: {args.max_workers}")
        print()
    
    # Create and run executor
    executor = SnortMQTTExecutor(
        interface=args.interface,
        host=args.host,
        port=args.port,
        max_workers=args.max_workers
    )
    
    executor.run()

if __name__ == "__main__":
    main()