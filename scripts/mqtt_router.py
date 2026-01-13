#!/usr/bin/env python3
"""
MQTT Router - Intercepts commands, executes them, and routes only the results
This acts as a man-in-the-middle that prevents original commands from reaching subscribers
"""

import socket
import threading
import time
import subprocess
import gzip
import base64
import signal
import sys
import os
import queue
from datetime import datetime
import re

# Import detection state tracker for 4-stage enforcement
try:
    from detection_state_tracker import DetectionStateTracker
    DETECTION_TRACKER_AVAILABLE = True
except ImportError:
    DETECTION_TRACKER_AVAILABLE = False
    print("⚠️  DetectionStateTracker not available - stage tracking disabled")

# Import MAC-based scanner - with comprehensive path resolution
try:
    # Clear any cached imports first
    if 'mac_based_scanner' in sys.modules:
        del sys.modules['mac_based_scanner']
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Build list of possible paths
    # Auto-detect project directory
    project_dir = os.environ.get('PROJECT_DIR') or os.environ.get('MQTTLIVE_DIR') or os.path.dirname(script_dir)
    possible_paths = [
        script_dir,  # Script's directory (scripts/)
        os.getcwd(),  # Current working directory
        project_dir,  # Project root directory
        os.path.dirname(script_dir),  # Parent directory
    ]
    
    # Add all paths to sys.path
    for path in possible_paths:
        if path and os.path.exists(path) and path not in sys.path:
            sys.path.insert(0, path)
    
    # Try importing
    from mac_based_scanner import MACBasedScanner
    MAC_SCANNER_AVAILABLE = True
except ImportError as e:
    # Try explicit file-based import
    try:
        import importlib.util
        
        # Try multiple possible locations
        mac_scanner_locations = [
            os.path.join(script_dir, 'mac_based_scanner.py'),
            os.path.join(os.getcwd(), 'mac_based_scanner.py'),
            os.path.join(os.getcwd(), 'scripts', 'mac_based_scanner.py'),
        ]
        
        mac_scanner_path = None
        for location in mac_scanner_locations:
            if os.path.exists(location):
                mac_scanner_path = location
                break
        
        if mac_scanner_path:
            spec = importlib.util.spec_from_file_location("mac_based_scanner", mac_scanner_path)
            mac_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mac_module)
            MACBasedScanner = mac_module.MACBasedScanner
            MAC_SCANNER_AVAILABLE = True
        else:
            raise ImportError(f"mac_based_scanner.py not found in any expected location")
    except Exception as e2:
        # Silent failure - MAC scanner is optional
        MAC_SCANNER_AVAILABLE = False
        MACBasedScanner = None
except Exception as e:
    # Silent failure - MAC scanner is optional
    MAC_SCANNER_AVAILABLE = False
    MACBasedScanner = None

# Import database logger - try multiple paths
try:
    import sys
    # Add common paths to find the logger
    # Auto-detect paths relative to this script
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _project_dir = os.path.dirname(_script_dir)
    possible_paths = [
        _script_dir,  # scripts/ directory
        _project_dir,  # project root
        os.getcwd(),
    ]
    for path in possible_paths:
        if path and path not in sys.path:
            sys.path.insert(0, path)
    
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
    # Always use centralized session.db (create if doesn't exist)
    DB_PATH = os.path.join(SESSION_LOG_DIR, 'session.db')
    DB_LOGGER = SnortMQTTLogger(DB_PATH)
    DB_LOGGING_ENABLED = True
    print(f"✅ Database logging enabled: {DB_PATH}")
except Exception as e:
    import traceback
    print(f"⚠️  Database logging disabled: {e}")
    print(f"   Traceback: {traceback.format_exc()}")
    DB_LOGGER = None
    DB_LOGGING_ENABLED = False

# Import system monitor for metrics tracking (uses SAME session.db)
try:
    from system_monitor import SystemMonitor
    SESSION_LOG_DIR = os.environ.get('SESSION_LOG_DIR', '.')
    # Validate SESSION_LOG_DIR is not empty
    if not SESSION_LOG_DIR or SESSION_LOG_DIR.strip() == '':
        SESSION_LOG_DIR = '.'
    # Use session.db - ALL metrics in ONE database
    SYSTEM_MONITOR = SystemMonitor(db_path=os.path.join(SESSION_LOG_DIR, 'session.db'), interval=5)
    SYSTEM_MONITOR.start_monitoring()
    SYSTEM_MONITOR_ENABLED = True
except Exception as e:
    print(f"⚠️  System monitor not available: {e}")
    SYSTEM_MONITOR = None
    SYSTEM_MONITOR_ENABLED = False

class MQTTRouter:
    def __init__(self, host='0.0.0.0', port=1883):
        self.host = host
        self.port = port
        self.running = True
        self.subscribers = {}  # topic -> set of client sockets
        self.server_socket = None
        self.ai_socket_path = "/tmp/ai_socket.sock"
        self.ai_available = False  # Will be checked lazily on first use
        self.ai_checked = False  # Track if we've checked yet
        
        # QUEUEING THEORY IMPLEMENTATION
        # Decouple packet reception (Producer) from processing (Consumer)
        # This ensures high-throughput packet acceptance even if processing is slow
        self.command_queue = queue.Queue()
        self.worker_thread = threading.Thread(target=self.process_queue, daemon=True)
        self.worker_thread.start()
        
        # MAC-based scanner (initialize AFTER socket setup to avoid conflicts)
        self.mac_scanner = None
        # Don't initialize here - do it lazily in handle_client to avoid socket conflicts
        
        # Initialize detection state tracker for 4-stage enforcement
        if DETECTION_TRACKER_AVAILABLE:
            try:
                # Use same database path as logger
                if DB_LOGGING_ENABLED and DB_LOGGER:
                    db_path = DB_LOGGER.db_path
                    self.detection_tracker = DetectionStateTracker(db_path=db_path)
                    # Force table creation
                    self.detection_tracker._init_database()
                    print(f"✅ DetectionStateTracker initialized - Stage tracking enabled (DB: {db_path})")
                else:
                    self.detection_tracker = DetectionStateTracker()
                    self.detection_tracker._init_database()
                    print(f"✅ DetectionStateTracker initialized - Stage tracking enabled")
            except Exception as e:
                print(f"⚠️  Failed to initialize DetectionStateTracker: {e}")
                import traceback
                traceback.print_exc()
                self.detection_tracker = None
        else:
            self.detection_tracker = None
            print(f"⚠️  DetectionStateTracker not available - Stage tracking disabled")
    
    def process_queue(self):
        """Worker thread to process commands from the queue (Consumer)"""
        print("👷 Worker thread started: Ready to process commands", flush=True)
        try:
            while self.running:
                try:
                    # Get task from queue (blocking with timeout to allow checking self.running)
                    task = self.command_queue.get(timeout=1)
                    
                    # Unpack task
                    command, client_ip, topic, address = task
                    
                    print(f"⚙️  Processing queued command from {address}: {command[:30]}...", flush=True)
                    
                    # Check if device MAC is blocked BEFORE processing
                    device_mac = None
                    if self.mac_scanner:
                        device_mac = self.mac_scanner.get_mac_from_ip_cached(client_ip)
                    
                    # Check if MAC is blocked
                    if device_mac and SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                        try:
                            if SYSTEM_MONITOR.is_blocked(device_mac):
                                print(f"🚫 Device {device_mac} ({client_ip}) is BLOCKED - dropping command", flush=True)
                                # Log blocked message
                                if DB_LOGGING_ENABLED and DB_LOGGER:
                                    try:
                                        DB_LOGGER.log_mqtt_traffic({
                                            'packet_type': 'PUBLISH',
                                            'topic': topic or '',
                                            'payload': command[:1000] if len(command) <= 1000 else command[:1000] + "...",
                                            'source_ip': client_ip,
                                            'source_mac': device_mac,
                                            'dest_ip': '0.0.0.0',
                                            'dest_mac': None,
                                            'source_port': 0,
                                            'dest_port': 0,
                                            'qos': 0,
                                            'retain': False,
                                            'dup': False,
                                            'status': 'blocked',
                                            'processed': False,
                                            'blocked': True,
                                            'dropped': False,
                                            'broadcasted': False
                                        })
                                    except Exception as e:
                                        print(f"   ⚠️  Blocked message logging error: {e}")
                                # Don't process, don't broadcast - just drop silently
                                self.command_queue.task_done()
                                continue
                        except:
                            pass  # If check fails, continue processing
                    
                    # Execute command (this is the slow part)
                    success, result = self.execute_command(command, client_ip=client_ip, topic=topic)
                    
                    # Update status in database - mark as processed
                    if DB_LOGGING_ENABLED and DB_LOGGER:
                        try:
                            # Try to update the most recent PUBLISH for this command
                            # We'll log a new entry with updated status
                            status = 'processed_blocked' if not success else 'processed'
                            DB_LOGGER.log_mqtt_traffic({
                                'packet_type': 'PUBLISH',
                                'topic': topic or '',
                                'payload': command[:1000] if len(command) <= 1000 else command[:1000] + "...",
                                'source_ip': client_ip,
                                'source_mac': device_mac,
                                'dest_ip': '0.0.0.0',
                                'dest_mac': None,
                                'source_port': 0,
                                'dest_port': 0,
                                'qos': 0,
                                'retain': False,
                                'dup': False,
                                'status': status,
                                'processed': True,
                                'blocked': not success,
                                'dropped': False,
                                'broadcasted': False
                            })
                        except Exception as e:
                            print(f"   ⚠️  Status update logging error: {e}")
                    
                    # Only broadcast if command was successful AND not blocked
                    # If blocked, Snort drops the packet, so no broadcast needed
                    if success and topic and result:
                        # Check again if blocked (might have been blocked during execution)
                        if device_mac and SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                            try:
                                if SYSTEM_MONITOR.is_blocked(device_mac):
                                    print(f"🚫 Device {device_mac} blocked during execution - not broadcasting", flush=True)
                                    self.command_queue.task_done()
                                    continue
                            except:
                                pass
                        
                        result_message = f"RESULT: {result[:500]}"
                        self.broadcast_to_topic(topic, result_message)
                        print(f"📤 Broadcasted result to topic '{topic}': {result_message[:50]}...", flush=True)
                    
                    # Mark task as done
                    self.command_queue.task_done()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"❌ Error in worker thread loop: {e}", flush=True)
                    import traceback
                    traceback.print_exc()
        except Exception as e:
            print(f"❌ FATAL ERROR in worker thread: {e}", flush=True)
            import traceback
            traceback.print_exc()
    
    def check_ai_server(self):
        """Check if AI server is available"""
        try:
            if os.path.exists(self.ai_socket_path):
                # Try to connect briefly to verify server is actually running
                test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_sock.settimeout(0.5)
                try:
                    test_sock.connect(self.ai_socket_path)
                    test_sock.close()
                    print("🤖 AI Server: Connected and ready")
                    return True
                except (ConnectionRefusedError, OSError):
                    # Socket exists but server not listening - stale socket
                    print(f"⚠️  AI Server: Stale socket detected (server not running)")
                    print(f"   Socket exists but connection refused - AI analysis disabled")
                    return False
            else:
                # Socket not found yet - server may still be starting
                # Don't print warning on first check (lazy init), only if we've checked before
                if self.ai_checked:
                    print("⚠️  AI Server: Socket not found (AI analysis disabled)")
                return False
        except Exception as e:
            # Don't print error on first lazy check
            if self.ai_checked:
                print(f"⚠️  AI Server: Not available ({e}) - AI analysis disabled")
            self.ai_available = False # Update instance variable
            return False
    
    def query_ai_server(self, device_ip, command):
        """Query AI server for analysis of a command"""
        print(f"🔍 DEBUG: query_ai_server called for {device_ip}: {command[:30]}...", flush=True)
        
        # Lazy initialization - check AI server on first use (it may not be ready at startup)
        # Check if AI server is available (Retry logic)
        if not self.ai_available:
            # Try to reconnect if it's been a while or first run
            current_time = time.time()
            if not hasattr(self, 'last_ai_check') or (current_time - self.last_ai_check > 5):
                print(f"🔍 DEBUG: Retrying AI server connection...", flush=True)
                self.ai_available = self.check_ai_server() # Update ai_available based on check
                self.last_ai_check = current_time
        
        if not self.ai_available:
            print(f"⚠️ DEBUG: AI server still unavailable after retry.", flush=True)
            return None
            
        try:
            # Create a fresh socket for each request (simple IPC)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2.0) # 2 second timeout
                try:
                    s.connect(self.ai_socket_path)
                except Exception as e:
                    print(f"❌ DEBUG: Failed to connect to AI socket {self.ai_socket_path}: {e}", flush=True)
                    self.ai_available = False
                    return None
                
                # Send request: "IP|COMMAND"
                request = f"{device_ip}|{command}"
                s.sendall(request.encode())
                
                # Get response
                response = s.recv(1024).decode().strip()
                print(f"🧠 DEBUG: AI Response: '{response}'", flush=True)
                return response
                
        except Exception as e:
            print(f"❌ DEBUG: Error querying AI server: {e}", flush=True)
            self.ai_available = False
            return None
        
        return None

    def start(self):
        """Start the MQTT router server"""
        print(f"🚀 Starting MQTT Router on {self.host}:{self.port}")
        print("📡 Universal Command Executor: ALL topics execute commands")
        print("💡 Unrecognized commands will be echoed back to subscribers")
        
        # Verify initial scan completed before accepting connections
        scan_flag_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".initial_scan_complete")
        if os.path.exists(scan_flag_file):
            print("✅ Initial scan verified - ready to accept messages")
        else:
            print("⚠️  Initial scan flag not found - accepting messages anyway (scan may still be running)")

        try:
            # Check if port is already in use (IPv4 ONLY)
            import socket as sock_check
            test_sock = sock_check.socket(sock_check.AF_INET, sock_check.SOCK_STREAM)  # IPv4 ONLY
            bind_host = self.host if self.host != '0.0.0.0' else '0.0.0.0'
            try:
                test_sock.bind((bind_host, self.port))
                test_sock.close()
            except OSError:
                test_sock.close()
                print(f"❌ Port {self.port} is already in use!")
                print(f"   💡 Try: sudo lsof -ti:{self.port} | xargs -r sudo kill -9")
                print(f"   💡 Or stop mosquitto: sudo systemctl stop mosquitto")
                raise
            
            # FORCE IPv4 ONLY - no IPv6 whatsoever
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Explicitly bind to IPv4 address only
            bind_host = self.host if self.host != '0.0.0.0' else '0.0.0.0'
            try:
                self.server_socket.bind((bind_host, self.port))
            except OSError as e:
                if e.errno == 98:  # Address already in use
                    print(f"❌ Port {self.port} is already in use!")
                    print(f"   💡 Try: sudo lsof -ti:{self.port} | xargs -r sudo kill -9")
                    print(f"   💡 Or check if mosquitto is running: sudo systemctl status mosquitto")
                    print(f"   💡 Checking what's using port {self.port}...")
                    import subprocess
                    try:
                        result = subprocess.run(['sudo', 'lsof', '-i', f':{self.port}'], capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            print(f"   {result.stdout}")
                    except:
                        pass
                    # Don't raise - let it retry or handle gracefully
                    raise
                else:
                    raise
            self.server_socket.listen(5)

            print(f"✅ MQTT Router listening on {self.host}:{self.port}")
            print("📨 NOW ACCEPTING MQTT MESSAGES")
            print(f"🐛 DEBUG: Server socket: {self.server_socket}, running={self.running}")

            while self.running:
                try:
                    print(f"🐛 DEBUG: Waiting for connection on {self.host}:{self.port}...")
                    client_socket, address = self.server_socket.accept()
                    print(f"🔌 New client connected: {address}")
                    print(f"🐛 DEBUG: Client socket created: {client_socket}, address={address}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, address),
                        name=f"ClientHandler-{address}"
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    print(f"🐛 DEBUG: Started client handler thread for {address}")

                except socket.timeout:
                    # Timeout is normal, continue
                    continue
                except OSError as e:
                    if self.running:
                        if e.errno == 9:  # Bad file descriptor (socket closed)
                            print(f"🐛 DEBUG: Socket closed, stopping accept loop")
                            break
                        else:
                            print(f"❌ Error accepting connection (errno {e.errno}): {e}")
                            import traceback
                            traceback.print_exc()
                    else:
                        print(f"🐛 DEBUG: Not running, exiting accept loop")
                        break
                except Exception as e:
                    if self.running:
                        print(f"❌ Error accepting connection: {e}")
                        import traceback
                        traceback.print_exc()
                    else:
                        print(f"🐛 DEBUG: Not running, exiting accept loop")
                        break

        except OSError as e:
            if e.errno == 92:  # Protocol not available
                print(f"❌ CRITICAL: [Errno 92] Protocol not available")
                print(f"🐛 DEBUG: This error occurs when trying to set IPv6 options on IPv4 socket")
                print(f"🐛 DEBUG: Error at: bind() or listen() call")
                import traceback
                print(f"🐛 DEBUG: Full traceback:")
                traceback.print_exc()
                print(f"🐛 DEBUG: Host={self.host}, Port={self.port}")
                print(f"🐛 DEBUG: Socket type: {type(self.server_socket) if hasattr(self, 'server_socket') else 'NOT CREATED'}")
            else:
                print(f"❌ Server error (OSError {e.errno}): {e}")
                import traceback
                traceback.print_exc()
        except Exception as e:
            print(f"❌ Server error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            print(f"🐛 DEBUG: Entering finally block, running={self.running}")
            self.stop()
    
    def stop(self):
        """Stop the MQTT router"""
        print("🛑 Stopping MQTT Router...")
        print(f"🐛 DEBUG: stop() called, running={self.running}")
        self.running = False
        if self.server_socket:
            try:
                print(f"🐛 DEBUG: Closing server socket...")
                self.server_socket.close()
                print(f"🐛 DEBUG: Server socket closed")
            except Exception as e:
                print(f"⚠️  Error closing server socket: {e}")
                import traceback
                traceback.print_exc()
        # Close MAC scanner SSH connection
        if self.mac_scanner:
            try:
                print(f"🐛 DEBUG: Closing MAC scanner...")
                self.mac_scanner.close()
                print(f"🐛 DEBUG: MAC scanner closed")
            except Exception as e:
                print(f"⚠️  Error closing MAC scanner: {e}")
                import traceback
                traceback.print_exc()
        print("✅ MQTT Router stopped")
        print(f"🐛 DEBUG: stop() completed")
    
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        client_ip, client_port = address
        connection_id = f"{client_ip}:{client_port}:{time.time()}"
        mac_address = None
        
        print(f"🐛 DEBUG: handle_client started for {address}, connection_id={connection_id}")
        
        # Initialize MAC scanner lazily (after socket is set up)
        if MAC_SCANNER_AVAILABLE and self.mac_scanner is None:
            try:
                self.mac_scanner = MACBasedScanner()
                print(f"🐛 DEBUG: MAC scanner initialized lazily")
            except Exception as e:
                print(f"⚠️  MAC scanner initialization failed: {e}")
                self.mac_scanner = None
        
        # Get MAC address for this connection
        if self.mac_scanner:
            try:
                mac_address = self.mac_scanner.get_mac_from_ip_cached(client_ip)
                print(f"🐛 DEBUG: MAC address for {client_ip}: {mac_address}")
            except Exception as e:
                print(f"⚠️  Error getting MAC address: {e}")
        
        # Record connection start
        if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
            try:
                SYSTEM_MONITOR.record_connection_start(connection_id, mac_address, client_ip, client_port)
                print(f"🐛 DEBUG: Recorded connection start in database")
            except Exception as e:
                print(f"⚠️  Error recording connection start: {e}")
        disconnect_reason = "Normal Disconnect"
        try:
            with client_socket:
                client_socket.settimeout(60) # 60 second timeout
                incomplete_data = b''
                while self.running:
                    try:
                        print(f"🐛 DEBUG: Waiting for data from {address}...", flush=True)
                        data = client_socket.recv(4096)
                        if not data:
                            disconnect_reason = "Client Closed Connection"
                            print(f"🐛 DEBUG: No data received (empty), closing connection for {address}")
                            break
                        print(f"🐛 DEBUG: Received {len(data)} bytes from {address}")

                        # Add new data to any incomplete data from previous recv
                        data = incomplete_data + data
                        incomplete_data = b''

                        while len(data) > 1:
                            # Try to read the remaining length of the MQTT message
                            remaining_length, length_bytes_read = self.decode_remaining_length(data[1:])

                            if remaining_length is None:
                                # Not enough data to read the remaining length
                                incomplete_data = data
                                break

                            header_size = 1 + length_bytes_read
                            full_packet_size = header_size + remaining_length
    
                            if len(data) < full_packet_size:
                                # Not enough data for the full packet
                                incomplete_data = data
                                break
    
                            # We have a full packet
                            packet = data[:full_packet_size]
                            data = data[full_packet_size:] # Move to the next packet in the buffer
    
                            # Process the complete packet
                            packet_type = packet[0] & 0xF0
                            
                            # DEBUG: Print ALL packet types to see what we are receiving
                            print(f"🐛 DEBUG: Packet received - Type: 0x{packet_type:02X} (Raw: 0x{packet[0]:02X}), Len: {len(packet)}", flush=True)
                            
                            packet_type_name = {
                                0x10: "CONNECT",
                                0x20: "CONNACK", 
                                0x30: "PUBLISH",
                                0x40: "PUBACK",
                                0x50: "PUBREC",
                                0x60: "PUBREL",
                                0x70: "PUBCOMP",
                                0x80: "SUBSCRIBE",
                                0x90: "SUBACK",
                                0xA0: "UNSUBSCRIBE",
                                0xB0: "UNSUBACK",
                                0xC0: "PINGREQ",
                                0xD0: "PINGRESP",
                                0xE0: "DISCONNECT"
                            }.get(packet_type, f"UNKNOWN(0x{packet_type:02X})")
                            
                            if packet_type not in [0x10, 0x30, 0x80, 0xC0]:  # Only log non-standard packets
                                print(f"📦 [{address}] Received {packet_type_name} packet (size: {len(packet)} bytes)")
    
                            if packet_type == 0x10:  # CONNECT
                                print(f"📨 [{address}] MQTT CONNECT received")
                                client_ip, client_port = address
                                
                                # Get MAC address for this connection
                                device_mac = None
                                if self.mac_scanner:
                                    device_mac = self.mac_scanner.get_mac_from_ip_cached(client_ip)
                                
                                # CRITICAL: Check if device is blocked BEFORE processing CONNECT
                                is_blocked_device = False
                                if device_mac and SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                                    try:
                                        is_blocked_device = SYSTEM_MONITOR.is_blocked(device_mac)
                                        if is_blocked_device:
                                            print(f"🚫 BLOCKED DEVICE attempting to reconnect: MAC {device_mac} (IP {client_ip})")
                                            # Log blocked reconnection attempt
                                            if DB_LOGGING_ENABLED and DB_LOGGER:
                                                try:
                                                    DB_LOGGER.log_mqtt_traffic({
                                                        'packet_type': 'CONNECT',
                                                        'topic': 'BLOCKED_RECONNECTION_ATTEMPT',
                                                        'payload': f'Blocked device {device_mac} attempted to reconnect',
                                                        'source_ip': client_ip,
                                                        'source_mac': device_mac,
                                                        'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                                                        'source_port': client_port,
                                                        'dest_port': self.port,
                                                        'qos': 0,
                                                        'retain': False,
                                                        'dup': False,
                                                        'status': 'blocked_reconnect',
                                                        'processed': False,
                                                        'blocked': True,
                                                        'dropped': True,
                                                        'broadcasted': False
                                                    })
                                                    # Log security event for blocked reconnection
                                                    SYSTEM_MONITOR.record_security_event(
                                                        event_type='blocked_reconnection_attempt',
                                                        mac_address=device_mac,
                                                        device_ip=client_ip,
                                                        command='MQTT CONNECT',
                                                        threat_level='critical',
                                                        detection_method='mac_block',
                                                        reason=f'Blocked device {device_mac} attempted to reconnect to network',
                                                        blocked=True
                                                    )
                                                    DB_LOGGER.flush()  # Ensure logged before closing connection
                                                except Exception as e:
                                                    print(f"   ⚠️  Blocked reconnection logging error: {e}")
                                            # Close connection immediately - don't send CONNACK
                                            print(f"   🚫 Closing connection - device is blocked")
                                            client_socket.close()
                                            return  # Exit handle_client - don't process further
                                    except Exception as e:
                                        print(f"   ⚠️  Block check error: {e}")
                                
                                # Parse CONNECT packet to extract protocol details
                                mqtt_version, clean_session, keep_alive, will_flag, client_id = self.parse_connect(packet)
                                
                                # Handle parse errors
                                if mqtt_version is None:
                                    print(f"   ⚠️  Failed to parse CONNECT packet, defaulting to MQTT 3.1.1")
                                    mqtt_version = '3.1.1'
                                    clean_session = True
                                    keep_alive = 60
                                    will_flag = False
                                    client_id = 'unknown'
    
                                # Log MQTT CONNECT to database (for non-blocked devices)
                                if DB_LOGGING_ENABLED and DB_LOGGER:
                                    try:
                                        DB_LOGGER.log_mqtt_traffic({
                                            'packet_type': 'CONNECT',
                                            'topic': '',
                                            'payload': client_id or '',
                                            'source_ip': client_ip,
                                            'source_mac': device_mac,
                                            'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                                            'dest_mac': None,
                                            'source_port': client_port,
                                            'dest_port': self.port,
                                            'qos': 0,
                                            'retain': False,
                                            'dup': False,
                                            'status': 'connected',
                                            'processed': True,
                                            'blocked': False,
                                            'dropped': False,
                                            'broadcasted': False
                                        })
                                    except Exception as e:
                                        print(f"   ⚠️  MQTT CONNECT logging error: {e}")
                                
                                # Record protocol metrics
                                if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                                    try:
                                        SYSTEM_MONITOR.record_mqtt_protocol_metrics(
                                            mqtt_version=mqtt_version,
                                            qos_level=0,
                                            is_retained=False,
                                            is_will=will_flag,
                                            is_duplicate=False,
                                            packet_size=len(packet),
                                            is_compressed=False
                                        )
                                        # Update connection with protocol details
                                        if connection_id in SYSTEM_MONITOR.active_connections:
                                            conn_data = SYSTEM_MONITOR.active_connections[connection_id]
                                            conn_data['mqtt_version'] = mqtt_version
                                            conn_data['clean_session'] = clean_session
                                            conn_data['keep_alive'] = keep_alive
                                            conn_data['client_id'] = client_id
                                    except Exception as e:
                                        print(f"   ⚠️  Protocol metrics error: {e}")
                                
                                self.send_connack(client_socket, mqtt_version=mqtt_version)
                            
                            elif packet_type == 0x30:  # PUBLISH
                                print(f"📨 [{address}] PUBLISH packet received (size: {len(packet)} bytes)", flush=True)
                                try:
                                    topic, message, qos_level, retain_flag, dup_flag = self.parse_publish(packet)
                                    print(f"   🔍 Parsed: topic='{topic}', message_length={len(message) if message else 0}, QoS={qos_level}, retain={retain_flag}, dup={dup_flag}", flush=True)
                                    print(f"   🐛 DEBUG: topic type={type(topic)}, message type={type(message)}, topic bool={bool(topic)}, message bool={bool(message)}", flush=True)
                                    # Log MQTT PUBLISH to database
                                    if DB_LOGGING_ENABLED and DB_LOGGER:
                                        try:
                                            client_ip, client_port = address
                                            
                                            # Get MAC address for logging
                                            source_mac = None
                                            if self.mac_scanner:
                                                source_mac = self.mac_scanner.get_mac_from_ip_cached(client_ip)
                                            
                                            # Record device activity for system monitor
                                            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR and source_mac:
                                                SYSTEM_MONITOR.record_device_activity(source_mac, client_ip, 'mqtt_message', 1)
                                                # Record topic activity (messages received)
                                                if topic:
                                                    SYSTEM_MONITOR.record_topic_activity(topic, len(message.encode('utf-8')) if message else 0, is_publish=False)
                                                # Update connection stats
                                                if connection_id in SYSTEM_MONITOR.active_connections:
                                                    SYSTEM_MONITOR.active_connections[connection_id]['messages_received'] += 1
                                                    if topic:
                                                        SYSTEM_MONITOR.active_connections[connection_id]['topics'].add(topic)
                                            
                                            # Record protocol metrics (QoS, retain, dup)
                                            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                                                try:
                                                    SYSTEM_MONITOR.record_mqtt_protocol_metrics(
                                                        mqtt_version=None,  # Will update existing entry
                                                        qos_level=qos_level,
                                                        is_retained=retain_flag,
                                                        is_will=False,
                                                        is_duplicate=dup_flag,
                                                        packet_size=len(packet),
                                                        is_compressed=False
                                                    )
                                                except Exception as e:
                                                    print(f"   ⚠️  Protocol metrics error: {e}")
                                            
                                            DB_LOGGER.log_mqtt_traffic({
                                                'packet_type': 'PUBLISH',
                                                'topic': topic or '',
                                                'payload': (message[:1000] if message and len(message) <= 1000 else (message[:1000] + "..." if message else '')),
                                                'source_ip': client_ip,
                                                'source_mac': source_mac,  # MAC address for tracking
                                                'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                                                'dest_mac': None,  # Could be looked up if needed
                                                'source_port': client_port,
                                                'dest_port': self.port,
                                                'qos': qos_level,  # QoS extracted from packet
                                                'retain': retain_flag,
                                                'dup': dup_flag,
                                                'status': 'received',  # Initial status
                                                'processed': False,
                                                'blocked': False,
                                                'dropped': False,
                                                'broadcasted': False
                                            })
                                        except Exception as e:
                                            print(f"   ⚠️  MQTT PUBLISH logging error: {e}")
                                    # Extract IP from address tuple
                                    client_ip, client_port = address
                                    
                                    # Check if we have valid topic and message
                                    print(f"   🐛 DEBUG: Checking topic and message - topic='{topic}' (len={len(topic) if topic else 0}), message='{str(message)[:50] if message else None}' (type={type(message)})", flush=True)
                                    
                                    if topic and message is not None and str(message).strip():
                                        print(f"   ✅ Topic and message are valid, proceeding to queue", flush=True)
                                        
                                        # Trigger MAC-based scan for this IP (in background thread)
                                        if self.mac_scanner:
                                            def scan_device():
                                                try:
                                                    scan_result = self.mac_scanner.scan_ip(client_ip)
                                                    if scan_result:
                                                        mac = scan_result['mac_address']
                                                        if scan_result['is_new_device']:
                                                            print(f"🆕 New device detected: MAC={mac}, IP={client_ip}", flush=True)
                                                        else:
                                                            print(f"📱 Device scan updated: MAC={mac}, IP={client_ip}", flush=True)
                                                except Exception as e:
                                                    print(f"⚠️  Scan error for {client_ip}: {e}", flush=True)
                                            
                                            # Run scan in background thread (non-blocking)
                                            scan_thread = threading.Thread(target=scan_device, daemon=True)
                                            scan_thread.start()
                                        
                                        # UNIVERSAL COMMAND EXECUTION: All topics are treated as command topics
                                        print(f"⚡ [{address}] COMMAND on '{topic}': '{str(message)[:50]}...'", flush=True)
                                        
                                        # QUEUEING THEORY: Push to queue (Producer)
                                        # This returns IMMEDIATELY so we can accept the next packet
                                        try:
                                            self.command_queue.put((str(message), client_ip, topic, address), timeout=5)
                                            print(f"📥 Queued command from {address} (Queue size: {self.command_queue.qsize()})", flush=True)
                                        except Exception as e:
                                            print(f"❌ ERROR: Failed to queue command: {e}", flush=True)
                                            import traceback
                                            traceback.print_exc()
                                        
                                        # Send immediate acknowledgement (simulated)
                                        # In a real broker, PUBACK would be sent here.
                                        # Since we are intercepting, we just log it.
                                        
                                        # NOTE: We can't return the result immediately anymore because it's async.
                                        # If the client expects a response on the same socket, we'd need a callback mechanism.
                                        # For this test, we'll assume fire-and-forget or that the worker handles responses (if possible).
                                        # But wait, execute_command sends responses back to subscribers!
                                        # The worker thread needs access to self.broadcast_to_topic.
                                        # It has it (self is passed).
                                        
                                        # We just can't send the result back to *this* specific client socket easily 
                                        # if it's expecting a synchronous response in a request-response pattern.
                                        # But MQTT is async by default (PUBLISH -> PUBACK).
                                        # The "result" in execute_command is broadcasted to the topic.
                                        
                                        pass # Continue to next packet immediately
                                    else:
                                        print(f"⚠️  [{address}] PUBLISH parsed but topic or message is empty/invalid", flush=True)
                                        print(f"   topic='{topic}' (type={type(topic)}, bool={bool(topic)})", flush=True)
                                        print(f"   message='{str(message)[:100] if message else None}' (type={type(message)}, bool={bool(message) if message is not None else 'None'})", flush=True)
                                except Exception as e:
                                    print(f"❌ Error parsing PUBLISH from {address}: {e}")
                                    print(f"❌ Packet data (first 50 bytes): {packet[:50]}")
                                    import traceback
                                    traceback.print_exc()
                                    
                            elif packet_type == 0x80:  # SUBSCRIBE
                                try:
                                        topic = self.parse_subscribe(packet)
                                        if topic:
                                            print(f"📡 [{address}] SUBSCRIBE to topic: {topic}")
                                            # Log MQTT SUBSCRIBE to database
                                            if DB_LOGGING_ENABLED and DB_LOGGER:
                                                try:
                                                    client_ip, client_port = address
                                                    DB_LOGGER.log_mqtt_traffic({
                                                        'packet_type': 'SUBSCRIBE',
                                                        'topic': topic,
                                                        'payload': '',
                                                        'source_ip': client_ip,
                                                        'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                                                        'source_port': client_port,
                                                        'dest_port': self.port,
                                                        'qos': 0,
                                                        'retain': False,
                                                        'dup': False
                                                    })
                                                except Exception as e:
                                                    print(f"   ⚠️  MQTT SUBSCRIBE logging error: {e}")
                                            self.add_subscriber(topic, client_socket)
                                            
                                            # Update topic subscriber count
                                            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                                                subscriber_count = len(self.subscribers.get(topic, []))
                                                SYSTEM_MONITOR.update_topic_subscribers(topic, subscriber_count)
                                                if connection_id in SYSTEM_MONITOR.active_connections:
                                                    SYSTEM_MONITOR.active_connections[connection_id]['topics'].add(topic)
                                        self.send_suback(client_socket)
                                except Exception as e:
                                    print(f"❌ Error parsing SUBSCRIBE from {address}: {e}")
                                    
                            elif packet_type == 0xC0:  # PINGREQ
                                print(f"💓 [{address}] PINGREQ received")
                                # Log MQTT PINGREQ to database
                                if DB_LOGGING_ENABLED and DB_LOGGER:
                                    try:
                                        client_ip, client_port = address
                                        DB_LOGGER.log_mqtt_traffic({
                                            'packet_type': 'PINGREQ',
                                            'topic': '',
                                            'payload': '',
                                            'source_ip': client_ip,
                                            'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                                            'source_port': client_port,
                                            'dest_port': self.port,
                                            'qos': 0,
                                            'retain': False,
                                            'dup': False
                                        })
                                    except Exception as e:
                                        print(f"   ⚠️  MQTT PINGREQ logging error: {e}")
                                self.send_pingresp(client_socket)

                    except socket.timeout:
                        # Send heartbeat to keep connection alive
                        try:
                            self.send_pingresp(client_socket)
                            continue
                        except:
                            break
        except socket.timeout:
            disconnect_reason = "Socket Timeout"
            print(f"🐛 DEBUG: Socket timeout for {address} (normal), closing connection")
        except socket.error as e:
            if e.errno == 104:  # Connection reset by peer
                disconnect_reason = "Connection Reset by Peer"
                print(f"🔌 Client {address} disconnected (connection reset)")
            elif e.errno == 107:  # Transport endpoint is not connected
                disconnect_reason = "Transport Not Connected"
                print(f"🐛 DEBUG: Transport endpoint not connected for {address}")
            elif e.errno == 9:  # Bad file descriptor
                disconnect_reason = "Bad File Descriptor"
                print(f"🐛 DEBUG: Bad file descriptor for {address}")
            else:
                disconnect_reason = f"Socket Error: {e.errno}"
                print(f"⚠️  Socket error for {address} (errno {e.errno}): {e}")
                import traceback
                traceback.print_exc()
        except Exception as e:
            disconnect_reason = f"Error: {str(e)[:20]}"
            print(f"❌ Error handling client {address}: {e}")
            import traceback
            traceback.print_exc()
            # Record error
            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                try:
                    SYSTEM_MONITOR.record_error('mqtt_router', 'connection', str(e),
                                              mac_address=mac_address, device_ip=client_ip,
                                              operation_name='handle_client')
                except Exception as db_err:
                    print(f"⚠️  Error recording error to database: {db_err}")
        except KeyboardInterrupt:
            disconnect_reason = "Server Shutdown"
            print(f"🐛 DEBUG: KeyboardInterrupt in handle_client for {address}")
            raise
        finally:
            self.remove_subscriber(client_socket)
            try:
                client_socket.close()
            except:
                pass
            # Log MQTT DISCONNECT to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    client_ip, client_port = address
                    DB_LOGGER.log_mqtt_traffic({
                        'packet_type': 'DISCONNECT',
                        'topic': disconnect_reason,
                        'payload': '',
                        'source_ip': client_ip,
                        'dest_ip': self.host if self.host != '0.0.0.0' else '0.0.0.0',
                        'source_port': client_port,
                        'dest_port': self.port,
                        'qos': 0,
                        'retain': False,
                        'dup': False
                    })
                except Exception as e:
                    print(f"   ⚠️  MQTT DISCONNECT logging error: {e}")
            
            # Record connection end
            disconnect_reason = 'normal'
            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                        try:
                            SYSTEM_MONITOR.record_connection_end(connection_id, disconnect_reason)
                        except Exception as db_error:
                            print(f"⚠️  Database error recording connection end: {db_error}")
                            import traceback
                            traceback.print_exc()
                            # Don't crash - just log the error
            
            print(f"🔌 Client {address} disconnected")
    
    def decode_remaining_length(self, data):
        """Decodes the remaining length of an MQTT message."""
        multiplier = 1
        value = 0
        bytes_read = 0
        for i in range(4): # Max 4 bytes for remaining length
            if i >= len(data):
                return None, 0 # Not enough data
            byte = data[i]
            bytes_read += 1
            value += (byte & 127) * multiplier
            if (byte & 128) == 0:
                return value, bytes_read
            multiplier *= 128
        return None, 0 # Malformed remaining length

    def is_command_topic(self, topic):
        """Check if topic is a command topic"""
        command_indicators = ['/command', 'command/', '/cmd', 'cmd/', '/exec', 'exec/']
        return any(indicator in topic for indicator in command_indicators)
    
    def check_heuristic_flags(self, command):
        """
        STAGE 1: Check for heuristic flags (Flag 2: Scripting & Development, Flag 9: Networking)
        Returns: (is_flagged, flag_type)
        """
        if not command:
            return False, None
        
        command_lower = command.lower()
        
        # Flag 2: Scripting & Development patterns
        scripting_patterns = [
            r'\b(python|python3|python2|perl|ruby|node|nodejs|npm|pip|pip3)\b',
            r'\b(bash|sh|zsh|fish|tcsh|csh)\s+-[ic]',
            r'\b(eval|exec|system|subprocess|os\.system|shell_exec)\s*\(',
            r'<\?php|<\?=|javascript:|vbscript:',
            r'\$\{.*\}|\$\(.*\)',  # Command substitution
            r'`.*`',  # Backtick execution
        ]
        
        # Flag 9: Networking patterns
        networking_patterns = [
            r'\b(nc|netcat|ncat|socat|telnet|ssh|scp|rsync|wget|curl|ftp)\b',
            r'\b(port|socket|bind|listen|connect|accept)\s*\(',
            r'\b(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)',  # Private IP ranges
            r':\d{1,5}\b',  # Port numbers
            r'\b(tcp|udp|icmp|http|https|ftp|smtp|dns)\b',
            r'>\s*/dev/tcp|>\s*/dev/udp',  # TCP/UDP redirection
        ]
        
        # Check for scripting patterns (Flag 2)
        for pattern in scripting_patterns:
            if re.search(pattern, command_lower):
                return True, 'SCRIPTING'
        
        # Check for networking patterns (Flag 9)
        for pattern in networking_patterns:
            if re.search(pattern, command_lower):
                return True, 'NETWORKING'
        
        return False, None
    
    def execute_command(self, command, client_ip=None, topic=None):
        """Execute command safely with ML analysis
        
        Args:
            command: Command string to execute
            client_ip: Real client IP address (from socket connection)
            topic: MQTT topic to broadcast results back to
        """
        if not command or not command.strip():
            return False, "ERROR: Empty command"
        
        start_time = time.time()
        
        # Use REAL client IP instead of self.host (which is always 0.0.0.0 or 127.0.0.1)
        if client_ip and client_ip != "127.0.0.1" and client_ip != "0.0.0.0":
            device_ip = client_ip
        else:
            # Fallback to self.host if no client_ip provided (shouldn't happen)
            device_ip = self.host if self.host != "0.0.0.0" else "127.0.0.1"
            print(f"   ⚠️  No client_ip provided, using fallback: {device_ip}")
        
        # Try to get MAC address for this IP
        device_mac = None
        if self.mac_scanner:
            device_mac = self.mac_scanner.get_mac_from_ip_cached(device_ip)
            if device_mac:
                # Use MAC as device identifier for AI analysis (but keep IP for logging)
                ai_device_id = device_mac
            else:
                ai_device_id = device_ip
        else:
            ai_device_id = device_ip
        
        # Record AI query latency
        ai_query_start = time.time()
        ai_verdict = self.query_ai_server(ai_device_id, command)
        ai_query_latency = (time.time() - ai_query_start) * 1000  # Convert to milliseconds
        
        # Record AI query latency
        if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
            SYSTEM_MONITOR.record_latency('ai_decision_server', 'query', ai_query_latency, success=(ai_verdict is not None))
        
        # ========================================================================
        # 4-STAGE ENFORCEMENT SYSTEM IMPLEMENTATION
        # ========================================================================
        
        # STAGE 1: Check for heuristic flags (Flag 2: Scripting, Flag 9: Networking)
        heuristic_flagged, heuristic_flag_type = self.check_heuristic_flags(command)
        heuristic_flag_value = None
        
        if heuristic_flagged:
            heuristic_flag_value = 'MAL'  # Set heuristic flag for Snort to read
            print(f"   🔍 STAGE 1: Heuristic flagging detected ({heuristic_flag_type}) - Mental note recorded")
            # Stage 1: Record mental note, NO Snort action yet
            # Flags stored in DB for Snort Lua inspector to read on NEXT packet
        
        # Determine if AI confirms malicious
        is_malicious = False
        ai_flag_value = None
        
        if ai_verdict and ai_verdict.strip() == "BLOCK":
            is_malicious = True
            ai_flag_value = 'BLOCK'  # Set AI flag for Snort to read
        
        # Store flags in database for Snort Lua inspector to read
        if DB_LOGGING_ENABLED and DB_LOGGER:
            try:
                # Log AI analysis with flags
                DB_LOGGER.log_ai_analysis({
                    'device_ip': device_ip,
                    'device_mac': device_mac,
                    'command': command,
                    'verdict': ai_verdict.strip() if ai_verdict else 'N/A',
                    'is_malicious': is_malicious,
                    'confidence': None,
                    'reason': None,
                    'user_id': device_ip,
                    'profile_context': None
                })
                
                # CRITICAL: Get current stage BEFORE logging alert (so alert shows correct stage)
                # Get current detection stage for this device
                current_stage_before = 0
                if self.detection_tracker and device_mac:
                    try:
                        current_stage_before = self.detection_tracker.get_current_stage(device_mac)
                    except:
                        current_stage_before = 0
                
                # CRITICAL: Store flags in snort_alerts table so Snort Lua inspector can read them
                # Snort reads these flags on NEXT packet and takes action
                # IMPORTANT: Log synchronously BEFORE blocking to ensure alert is saved
                if heuristic_flag_value or ai_flag_value:
                    # Create detailed Snort decision message
                    if ai_flag_value == 'BLOCK':
                        # Stage 4 = MAC BLOCK (device-level blocking)
                        # Stage 3 = PACKET DROP (packet-level blocking)
                        # Stage 1-2 = ALERT (just flagging)
                        if current_stage_before >= 4:
                            snort_action = "MAC_BLOCK"
                        elif current_stage_before >= 3:
                            snort_action = "PACKET_DROP"
                        else:
                            snort_action = "ALERT"
                        decision_msg = f"[SNORT DECISION: {snort_action}] Command flagged - Heuristic: {heuristic_flag_value or 'NONE'}, AI: {ai_flag_value or 'NONE'} - Stage {current_stage_before}"
                    elif heuristic_flag_value:
                        decision_msg = f"[SNORT DECISION: ALERT] Heuristic flag detected - Type: {heuristic_flag_value}"
                    else:
                        decision_msg = f"[SNORT DECISION: PASS] Command analyzed - No flags"
                    
                    alert_data = {
                        'alert_type': 'alert',
                        'message': decision_msg,
                        'source_ip': device_ip,
                        'dest_ip': self.host if self.host != '0.0.0.0' else '127.0.0.1',
                        'source_port': 0,
                        'dest_port': self.port,
                        'protocol': 'MQTT',
                        'sid': 1001001 if heuristic_flag_value else 1001002,  # Different SID for heuristic vs AI
                        'gid': 1,
                        'rev': 1,
                        'classification': 'attempted-user',
                        'priority': 1 if ai_flag_value == 'BLOCK' else (2 if heuristic_flag_value else 4),
                        'raw_data': command[:500],
                        'heuristic_flag': heuristic_flag_value,  # Snort reads this
                        'ai_flag': ai_flag_value  # Snort reads this
                    }
                    # Log alert and wait for queue to process (ensure it's committed before blocking)
                    DB_LOGGER.log_snort_alert(alert_data)
                    # CRITICAL: Wait for alert to be committed to DB before proceeding to blocking
                    # This ensures alerts are visible even after MAC blocking happens
                    DB_LOGGER.flush()  # Wait for queue to empty and commit
            except Exception as e:
                print(f"   ⚠️  Flag logging error: {e}")
        
        # Record detection and get current stage
        current_stage = 0
        if self.detection_tracker and device_mac:
            try:
                if heuristic_flagged:
                    # Stage 1: Record heuristic detection (mental note)
                    current_stage = self.detection_tracker.record_detection(
                        device_mac, device_ip, command, 'medium', 'heuristic'
                    )
                    print(f"   📊 STAGE 1: Detection recorded - Current stage: {current_stage}")
                
                if is_malicious:
                    # Stage 2+: Record AI detection (escalates stage)
                    current_stage = self.detection_tracker.record_detection(
                        device_mac, device_ip, command, 'high', 'ai_alert'
                    )
                    print(f"   📊 STAGE {current_stage}: AI detection recorded - Current stage: {current_stage}")
                    print(f"   🔍 DEBUG: Checking if Stage 4 blocking needed (current_stage={current_stage}, type={type(current_stage)}, device_mac={device_mac})")
                    
                    # Stage 4: MAC blocking (if stage >= 4)
                    # CRITICAL: Ensure all alerts are logged BEFORE blocking
                    # Ensure current_stage is an integer
                    current_stage_int = int(current_stage) if current_stage else 0
                    print(f"   🔍 DEBUG: current_stage_int={current_stage_int}, comparison: {current_stage_int} >= 4 = {current_stage_int >= 4}")
                    if current_stage_int >= 4:
                        print(f"   ✅ DEBUG: Stage 4 condition met! current_stage_int={current_stage_int} >= 4")
                        # Wait for any pending alert logs to be committed BEFORE blocking
                        # This ensures alerts are visible in display even after MAC blocking
                        if DB_LOGGING_ENABLED and DB_LOGGER:
                            try:
                                if hasattr(DB_LOGGER, 'flush'):
                                    DB_LOGGER.flush()  # Ensure all alerts are saved before blocking
                                else:
                                    print(f"   ⚠️  DB_LOGGER.flush() not available, continuing without flush")
                            except Exception as flush_error:
                                print(f"   ⚠️  Flush error (non-critical): {flush_error}, continuing with blocking")
                        
                        print(f"   🚫 STAGE 4: Triggering MAC blocking for {device_mac} (IP: {device_ip})")
                        print(f"   🔍 DEBUG: SYSTEM_MONITOR_ENABLED={SYSTEM_MONITOR_ENABLED}, SYSTEM_MONITOR={SYSTEM_MONITOR is not None}")
                        if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                            try:
                                # Block MAC address via iptables (blocks all future connections)
                                SYSTEM_MONITOR._block_mac_address(device_mac)
                                print(f"   ✅ STAGE 4: MAC {device_mac} blocked via iptables")
                                
                                # CRITICAL: Actively disconnect ALL existing MQTT connections from this device
                                # This ensures the client sees disconnection and will retry
                                try:
                                    connections_closed = 0
                                    # Use SYSTEM_MONITOR to track and close connections
                                    if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR and hasattr(SYSTEM_MONITOR, 'active_connections'):
                                        # Find all connections for this MAC/IP
                                        connections_to_close = []
                                        for conn_id, conn_info in list(SYSTEM_MONITOR.active_connections.items()):
                                            conn_ip = conn_info.get('ip', '')
                                            conn_mac = conn_info.get('mac', '')
                                            
                                            # Match by IP or MAC
                                            if conn_ip == device_ip or conn_mac == device_mac:
                                                connections_to_close.append(conn_id)
                                        
                                        # Close each connection
                                        for conn_id in connections_to_close:
                                            try:
                                                # Kill connection at OS level using ss -K
                                                import subprocess as sp
                                                # Kill connections on MQTT ports
                                                for port in [1883, 1889]:
                                                    try:
                                                        # Kill connections TO this IP (incoming)
                                                        sp.run(['sudo', 'ss', '-K', 'dst', f'{device_ip}:{port}'], 
                                                              stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=2)
                                                        # Kill connections FROM this IP (outgoing)
                                                        sp.run(['sudo', 'ss', '-K', 'src', f'{device_ip}:{port}'], 
                                                              stdout=sp.DEVNULL, stderr=sp.DEVNULL, timeout=2)
                                                    except:
                                                        pass
                                                
                                                # Remove from active connections tracking
                                                if conn_id in SYSTEM_MONITOR.active_connections:
                                                    del SYSTEM_MONITOR.active_connections[conn_id]
                                                
                                                connections_closed += 1
                                                print(f"   🔌 STAGE 4: Killed MQTT connection {conn_id} for blocked device {device_mac}")
                                            except Exception as e:
                                                print(f"   ⚠️  Error closing connection {conn_id}: {e}")
                                    
                                    if connections_closed > 0:
                                        print(f"   ✅ STAGE 4: Disconnected {connections_closed} active MQTT connection(s) - Client will see disconnection")
                                    else:
                                        print(f"   ⚠️  STAGE 4: No active connections found (iptables will block future connections)")
                                except Exception as e:
                                    print(f"   ⚠️  STAGE 4: Error disconnecting connections: {e}")
                                    import traceback
                                    traceback.print_exc()
                                
                                # CRITICAL: Log mac_blocked event to security_events
                                # This is what the export queries look for
                                try:
                                    SYSTEM_MONITOR.record_security_event(
                                        event_type='mac_blocked',
                                        mac_address=device_mac,
                                        device_ip=device_ip,
                                        command=command[:500] if command else 'Stage 4 Trigger',
                                        threat_level='critical',
                                        detection_method='stage4_escalation',
                                        ai_flag='BLOCK',
                                        reason=f'Stage 4: Device reached {current_stage} detections - MAC blocked and disconnected',
                                        blocked=True
                                    )
                                    print(f"   ✅ STAGE 4: mac_blocked event logged to security_events")
                                except Exception as e:
                                    print(f"   ⚠️  STAGE 4: Failed to log mac_blocked event: {e}")
                                
                                # Wait for blocking event to be logged
                                if DB_LOGGING_ENABLED and DB_LOGGER:
                                    DB_LOGGER.flush()  # Wait for blocking event to be logged
                            except Exception as e:
                                print(f"   ⚠️  STAGE 4: MAC blocking failed: {e}")
                                import traceback
                                traceback.print_exc()
            except Exception as e:
                print(f"   ⚠️  Detection tracking error: {e}")
        
        if is_malicious:
            print(f"   🚫 AI ANALYSIS: MALICIOUS - AI verdict: BLOCK")
            print(f"   ⚠️  This command was flagged as malicious by AI model")
            print(f"   📊 Current enforcement stage: {current_stage}")
            print(f"   🛡️  Snort will read flags and DROP packet/connection immediately")
            
            # CRITICAL: Flags are stored in DB above for Snort to read
            # Snort Lua inspector reads flags and makes the decision:
            # - AI BLOCK flag → Snort calls drop() → Packet AND connection dropped
            # - Snort logs the drop to Snort logs
            # - Snort's decision is reflected in database
            
            # Record security event (for tracking, but Snort makes final decision)
            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                SYSTEM_MONITOR.record_security_event(
                    event_type='ai_blocked_command',
                    mac_address=device_mac,
                    device_ip=device_ip,
                    command=command,
                    threat_level='high' if current_stage < 4 else 'critical',
                    detection_method='ai',
                    ai_confidence=None,
                    ai_flag='BLOCK',
                    reason=f'AI model flagged as malicious - Snort will drop (Stage {current_stage})',
                    blocked=False  # Snort will block, not us
                )
            
            # DON'T broadcast - Snort will drop the packet, so no response should be sent
            # Broadcasting would send a message back, which defeats the purpose of blocking
            # The packet is dropped by Snort, so client won't receive anything
            
            # Return False - command blocked (Snort will drop immediately)
            return False, f"BLOCKED: AI flagged malicious - Snort dropping packet/connection (Stage {current_stage})"
        else:
            if ai_verdict:
                print(f"   ✅ AI ANALYSIS: ALLOWED - Command approved by ML model")
        
        try:
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                shell=True
            )
            execution_time = time.time() - start_time
            execution_latency_ms = execution_time * 1000  # Convert to milliseconds
            
            # Record command execution latency and pattern
            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR and device_mac:
                SYSTEM_MONITOR.record_device_activity(device_mac, device_ip, 'command', 1)
                SYSTEM_MONITOR.record_latency('mqtt_router', 'command_execution', execution_latency_ms, success=(process.returncode == 0))
                # Record command pattern for behavior analysis
                SYSTEM_MONITOR.record_command_pattern(
                    device_mac, device_ip, command,
                    success=(process.returncode == 0),
                    execution_time_ms=execution_latency_ms
                )
            
            # Preserve whitespace, do not use .strip()
            output = process.stdout.decode('utf-8', errors='replace')
            error = process.stderr.decode('utf-8', errors='replace')
            
            # Remove any remaining null bytes
            output = output.replace('\x00', '')
            error = error.replace('\x00', '')
            
            # If the command was not found (return code 127 from shell) - just echo back silently
            if process.returncode == 127:
                # Don't show error, just echo the command back to user
                result = command  # Echo back the original command
                
                # Log to database silently (no print statements)
                if DB_LOGGING_ENABLED and DB_LOGGER:
                    try:
                        DB_LOGGER.log_command_execution({
                            'device_ip': device_ip,
                            'command': command,
                            'result': result,  # No size limit
                            'success': False,
                            'execution_time': execution_time,
                            'ai_verdict': ai_verdict or 'N/A'
                        })
                    except Exception as e:
                        pass  # Silent fail
                
                return True, result  # Return True so it gets broadcast as echo
            elif process.returncode != 0:
                print(f"   ⚠️  Command failed (returncode {process.returncode}): {error[:100]}")
                result = f"ERROR({process.returncode}): {error}"
                
                # Log to database
                if DB_LOGGING_ENABLED:
                    try:
                        DB_LOGGER.log_command_execution({
                            'device_ip': device_ip,
                            'command': command,
                            'result': result,  # No size limit
                            'success': False,
                            'execution_time': execution_time,
                            'ai_verdict': ai_verdict or 'N/A'
                        })
                    except:
                        pass
                
                # Broadcast failure result if topic provided
                if topic:
                    self.broadcast_to_topic(topic, f"ERROR: {result[:500]}")
                return True, result
            else:
                print(f"   ✅ Command executed successfully. Output length: {len(output)} bytes", flush=True)
                if len(output) == 0:
                    print(f"   ⚠️  Warning: Command returned empty output!")
                
                # Log to database
                if DB_LOGGING_ENABLED and DB_LOGGER:
                    try:
                        DB_LOGGER.log_command_execution({
                            'device_ip': device_ip,
                            'command': command,
                            'result': output[:1000] if len(output) <= 1000 else output[:1000] + "...",
                            'success': True,
                            'execution_time': execution_time,
                            'ai_verdict': ai_verdict or 'N/A'
                        })
                        print(f"   💾 Logged to database: {DB_PATH}")
                    except Exception as e:
                        print(f"   ⚠️  Database logging error: {e}")
                
                # Broadcast success result if topic provided
                if topic:
                    self.broadcast_to_topic(topic, f"SUCCESS: {output[:500]}")
                
                return True, output
            
        except subprocess.TimeoutExpired:
            result = "ERROR: Command timed out"
            if DB_LOGGING_ENABLED:
                try:
                    DB_LOGGER.log_command_execution({
                        'device_ip': device_ip,
                        'command': command,
                        'result': result,
                        'success': False,
                        'execution_time': time.time() - start_time,
                        'ai_verdict': ai_verdict or 'N/A'
                    })
                except:
                    pass
            # Broadcast timeout result if topic provided
            if topic:
                self.broadcast_to_topic(topic, f"ERROR: {result[:500]}")
            return False, result
        except Exception as e:
            result = f"ERROR: {str(e)}"
            if DB_LOGGING_ENABLED:
                try:
                    DB_LOGGER.log_command_execution({
                        'device_ip': device_ip,
                        'command': command,
                        'result': result,
                        'success': False,
                        'execution_time': time.time() - start_time,
                        'ai_verdict': ai_verdict or 'N/A'
                    })
                except:
                    pass
            return True, result
    
    def send_large_message_chunks(self, topic, message):
        """Sends a large message in chunks."""
        chunk_size = 1024  # Max size per MQTT message
        message_id = str(int(time.time() * 1000)) # Unique ID for this message
        chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
        num_chunks = len(chunks)

        for i, chunk in enumerate(chunks):
            chunk_header = f"CHUNK:{message_id}:{i+1}:{num_chunks}:"
            self.broadcast_to_topic(topic, chunk_header + chunk)
            time.sleep(0.05) # Small delay to prevent overwhelming the client

    def add_subscriber(self, topic, client_socket):
        """Add client as subscriber to topic"""
        if topic not in self.subscribers:
            self.subscribers[topic] = set()
        self.subscribers[topic].add(client_socket)
        total = len(self.subscribers[topic])
        print(f"📡 Added subscriber to {topic} (total: {total})")
        print(f"   🔍 All subscribers for '{topic}': {len(self.subscribers[topic])} client(s)")
    
    def remove_subscriber(self, client_socket):
        """Remove client from all topics"""
        for topic, subscribers in self.subscribers.items():
            subscribers.discard(client_socket)
    
    def broadcast_to_topic(self, topic, message):
        """Broadcast message to all subscribers of topic"""
        if topic in self.subscribers and len(self.subscribers[topic]) > 0:
            dead_clients = set()
            subscriber_count = len(self.subscribers[topic])
            print(f"📤 Broadcasting to {subscriber_count} subscriber(s) on topic '{topic}'")
            
            # Log broadcasted message to database
            if DB_LOGGING_ENABLED and DB_LOGGER:
                try:
                    DB_LOGGER.log_mqtt_traffic({
                        'packet_type': 'PUBLISH',
                        'topic': topic,
                        'payload': message[:1000] if len(message) <= 1000 else message[:1000] + "...",
                        'source_ip': '0.0.0.0',  # From router
                        'source_mac': None,
                        'dest_ip': '0.0.0.0',  # To subscribers
                        'dest_mac': None,
                        'source_port': self.port,
                        'dest_port': 0,
                        'qos': 0,
                        'retain': False,
                        'dup': False,
                        'status': 'broadcasted',
                        'processed': True,
                        'blocked': False,
                        'dropped': False,
                        'broadcasted': True
                    })
                except Exception as e:
                    print(f"   ⚠️  Broadcast logging error: {e}")
            
            # Record topic activity (message sent/published)
            if SYSTEM_MONITOR_ENABLED and SYSTEM_MONITOR:
                message_bytes = len(message.encode('utf-8'))
                SYSTEM_MONITOR.record_topic_activity(topic, message_bytes, is_publish=True)
                # Record protocol metrics for published messages
                try:
                    SYSTEM_MONITOR.record_mqtt_protocol_metrics(
                        mqtt_version=None,
                        qos_level=0,  # Default QoS 0 for our broadcasts
                        is_retained=False,
                        is_will=False,
                        is_duplicate=False,
                        packet_size=message_bytes,
                        is_compressed=False
                    )
                except Exception as e:
                    pass  # Silent fail for metrics
            
            for client_socket in list(self.subscribers[topic]):
                try:
                    self.send_publish(client_socket, topic, message)
                    print(f"   ✅ Sent to subscriber")
                except Exception as e:
                    print(f"   ❌ Error broadcasting to client: {e}")
                    # Mark for removal
                    dead_clients.add(client_socket)
            
            # Remove dead connections
            for dead_client in dead_clients:
                self.subscribers[topic].discard(dead_client)
        else:
            print(f"⚠️  No subscribers for topic '{topic}' - message not delivered")
    
    def parse_publish(self, data):
        """Parse MQTT PUBLISH packet to extract topic, message, QoS, retain, dup flags"""
        if len(data) < 4:
            return "", "", 0, False, False
        
        # Extract flags from fixed header byte
        fixed_header = data[0]
        dup_flag = bool(fixed_header & 0x08)  # Bit 3
        qos_level = (fixed_header & 0x06) >> 1  # Bits 2-1
        retain_flag = bool(fixed_header & 0x01)  # Bit 0
        
        pos = 1
        remaining_length, length_bytes_read = self.decode_remaining_length(data[pos:])
        pos += length_bytes_read
        
        if pos + 1 >= len(data):
            return "", "", qos_level, retain_flag, dup_flag
        topic_len = (data[pos] << 8) | data[pos + 1]
        pos += 2
        
        if pos + topic_len >= len(data):
            return "", "", qos_level, retain_flag, dup_flag
        topic = data[pos:pos + topic_len].decode('utf-8', errors='replace')
        pos += topic_len
        
        # For QoS > 0, skip packet identifier (2 bytes)
        if qos_level > 0 and pos + 2 <= len(data):
            pos += 2
        
        # For MQTT 5.0, skip properties length (1 byte if present)
        # This is a simplification, a full parser would handle properties
        if data[0] & 0x0F and pos < len(data) and data[pos] == 0:
             pos += 1

        if pos < len(data):
            message = data[pos:].decode('utf-8', errors='replace')
            message = message.replace('\x00', '')
        else:
            message = ""
        
        return topic, message, qos_level, retain_flag, dup_flag
    
    def parse_connect(self, data):
        """Parse MQTT CONNECT packet to extract protocol version, clean session, keep alive, client ID"""
        if len(data) < 10:
            return None, None, None, None, None
        
        pos = 1
        remaining_length, length_bytes_read = self.decode_remaining_length(data[pos:])
        pos += length_bytes_read
        
        # Protocol name (length-prefixed string)
        if pos + 2 > len(data):
            return None, None, None, None, None
        proto_name_len = (data[pos] << 8) | data[pos + 1]
        pos += 2
        
        if pos + proto_name_len > len(data):
            return None, None, None, None, None
        protocol_name = data[pos:pos + proto_name_len].decode('utf-8', errors='ignore')
        pos += proto_name_len
        
        # Protocol level (version)
        if pos >= len(data):
            return None, None, None, None, None
        protocol_level = data[pos]
        pos += 1
        
        # Map protocol level to version string
        version_map = {0x03: '3.1', 0x04: '3.1.1', 0x05: '5.0'}
        mqtt_version = version_map.get(protocol_level, f'unknown({protocol_level})')
        
        # Connect flags
        if pos >= len(data):
            return None, None, None, None, None
        connect_flags = data[pos]
        clean_session = bool(connect_flags & 0x02)  # Bit 1
        will_flag = bool(connect_flags & 0x04)  # Bit 2
        pos += 1
        
        # Keep alive (2 bytes, big endian)
        if pos + 2 > len(data):
            return None, None, None, None, None
        keep_alive = (data[pos] << 8) | data[pos + 1]
        pos += 2
        
        # Client ID (length-prefixed string)
        if pos + 2 > len(data):
            return mqtt_version, clean_session, keep_alive, will_flag, None
        client_id_len = (data[pos] << 8) | data[pos + 1]
        pos += 2
        
        if pos + client_id_len > len(data):
            return mqtt_version, clean_session, keep_alive, will_flag, None
        client_id = data[pos:pos + client_id_len].decode('utf-8', errors='ignore')
        
        return mqtt_version, clean_session, keep_alive, will_flag, client_id
    
    def parse_subscribe(self, data):
        """Parse MQTT SUBSCRIBE packet to extract topic"""
        # Debug: Print hex dump of the packet
        print(f"🐛 DEBUG: SUBSCRIBE Raw Bytes: {data.hex()}")
        
        # Relaxed length check (Fixed header 2 + Packet ID 2 + Topic Len 2 + Topic 1 + QoS 1 = 8 bytes minimum)
        # But let's be safer and allow slightly smaller for debugging
        if len(data) < 5:
            print(f"🐛 DEBUG: SUBSCRIBE packet too short ({len(data)} bytes)")
            return ""
        
        try:
            pos = 1
            remaining_length, length_bytes_read = self.decode_remaining_length(data[pos:])
            pos += length_bytes_read
            
            # Packet Identifier (2 bytes)
            if pos + 2 > len(data):
                print(f"🐛 DEBUG: SUBSCRIBE packet too short for Packet ID (pos={pos}, len={len(data)})")
                return ""
            packet_id = (data[pos] << 8) | data[pos + 1]
            pos += 2 
            
            # MQTT 5.0 Properties Length (Variable Byte Integer)
            if pos + 2 > len(data):
                print(f"🐛 DEBUG: SUBSCRIBE packet too short for Topic Len (pos={pos}, len={len(data)})")
                return ""
                
            topic_len = (data[pos] << 8) | data[pos + 1]
            
            # Sanity check: If topic_len looks huge (e.g. > remaining packet size), 
            # we might be misinterpreting MQTT 5.0 properties as topic length.
            if topic_len > len(data) - pos:
                print(f"🐛 DEBUG: Topic length {topic_len} > remaining data ({len(data)-pos}). Possible MQTT 5.0 properties?")
                # Try skipping one byte (Property Length = 0)
                # pos += 1
                # topic_len = (data[pos] << 8) | data[pos + 1]
            
            pos += 2
            
            if pos + topic_len > len(data):
                print(f"🐛 DEBUG: SUBSCRIBE packet too short for Topic (pos={pos}, topic_len={topic_len}, len={len(data)})")
                return ""
            topic = data[pos:pos + topic_len].decode('utf-8', errors='ignore')
            print(f"🐛 DEBUG: Successfully parsed SUBSCRIBE topic: '{topic}'")
            return topic
        except Exception as e:
            print(f"❌ Error parsing SUBSCRIBE packet: {e}")
            return ""
    
    def send_connack(self, client_socket, mqtt_version='3.1.1'):
        """Send CONNACK packet - supports both MQTT 3.1.1 and 5.0"""
        try:
            # Check which MQTT version the client is using
            # mqtt_version is passed as argument now
            
            # Check if it's MQTT 5.0 (could be string '5.0' or integer 5)
            is_mqtt5 = (mqtt_version == 5 or mqtt_version == '5.0' or (isinstance(mqtt_version, str) and mqtt_version.startswith('5')))
            
            if is_mqtt5:
                # MQTT 5.0 CONNACK: Fixed header + Variable header + Properties
                # Fixed header: Message type (2) + Flags (0) + Remaining length (3)
                # Variable header: Session present (0) + Return code (0) + Reason code (0)
                # Properties: Property length (0) - no properties
                connack = b'\x20\x03\x00\x00\x00'  # MQTT 5.0 CONNACK
            else:
                # MQTT 3.1.1 CONNACK: Fixed header + Variable header
                # Fixed header: Message type (2) + Flags (0) + Remaining length (2)
                # Variable header: Session present (0) + Return code (0)
                connack = b'\x20\x02\x00\x00'  # MQTT 3.1.1 CONNACK
            client_socket.send(connack)
        except Exception as e:
            print(f"❌ Error sending CONNACK: {e}")
            import traceback
            traceback.print_exc()
    
    def send_suback(self, client_socket):
        """Send MQTT 5.0 SUBACK packet"""
        # MQTT 5.0 SUBACK: Fixed header + Variable header + Payload + Properties
        # Fixed header: Message type (9) + Flags (0) + Remaining length
        # Variable header: Packet identifier (0x0001) + Reason code (0) + Properties length (0)
        suback = b'\x90\x04\x00\x01\x00\x00'  # MQTT 5.0 SUBACK with return code 0
        try:
            client_socket.send(suback)
        except Exception as e:
            print(f"❌ Error sending SUBACK: {e}")
    
    def send_pingresp(self, client_socket):
        """Send MQTT PINGRESP packet"""
        pingresp = b'\xD0\x00'  # PINGRESP
        try:
            client_socket.send(pingresp)
        except Exception as e:
            print(f"❌ Error sending PINGRESP: {e}")
    
    def send_publish(self, client_socket, topic, message):
        """Send MQTT PUBLISH packet (QoS 0)"""
        try:
            topic_bytes = topic.encode('utf-8')
            message_bytes = message.encode('utf-8')
            
            # MQTT PUBLISH packet format:
            # Fixed header: Message type (3) + Flags (0 for QoS 0) = 0x30
            # Remaining length: variable byte encoding
            # Topic length: 2 bytes (big endian)
            # Topic: UTF-8 encoded
            # Payload: message bytes
            
            fixed_header = 0x30  # PUBLISH with QoS 0, no flags
            topic_len = len(topic_bytes)
            remaining_len = 2 + topic_len + len(message_bytes)
            
            # Encode remaining length
            remaining_len_bytes = self.encode_remaining_length(remaining_len)
            
            # Build packet
            packet = bytearray()
            packet.append(fixed_header)
            packet.extend(remaining_len_bytes)
            packet.extend(topic_len.to_bytes(2, 'big'))
            packet.extend(topic_bytes)
            packet.extend(message_bytes)
            
            # Send packet
            client_socket.sendall(bytes(packet))
            
        except Exception as e:
            print(f"❌ Error sending PUBLISH to topic '{topic}': {e}")
            raise
    
    def encode_remaining_length(self, length):
        """Encode remaining length for MQTT packet"""
        encoded = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 128
            encoded.append(byte)
            if length == 0:
                break
        return encoded

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='MQTT Router')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=1883, help='Port to bind to')
    
    args = parser.parse_args()
    
    print(f"🚀 Starting MQTT Router on {args.host}:{args.port}")
    router = MQTTRouter(host=args.host, port=args.port)
    
    def signal_handler(sig, frame):
        print(f"\n🛑 Received signal {sig} - stopping router gracefully")
        try:
            router.stop()
        except:
            pass
        # Exit with code 0 so mqttlive monitoring can restart if needed
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        router.start()
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received")
        router.stop()
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"\n❌ Port {args.port} is already in use!")
            print(f"   Checking what's using it...")
            import subprocess
            try:
                result = subprocess.run(['sudo', 'lsof', '-i', f':{args.port}'], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    print(f"   {result.stdout}")
            except:
                pass
            print(f"\n   💡 This is a non-fatal error - mqttlive will retry")
            print(f"   💡 Or manually kill: sudo lsof -ti:{args.port} | xargs -r sudo kill -9")
            # Don't exit - let mqttlive monitoring restart it
            sys.exit(0)  # Exit cleanly so mqttlive can restart
        else:
            import traceback
            print(f"\n❌ FATAL ERROR: {e}")
            print(f"Traceback:\n{traceback.format_exc()}")
            router.stop()
            sys.exit(1)
    except Exception as e:
        import traceback
        print(f"\n❌ FATAL ERROR: {e}")
        print(f"Traceback:\n{traceback.format_exc()}")
        # Log to error file if SESSION_LOG_DIR is set
        error_log_path = os.path.join(os.environ.get('SESSION_LOG_DIR', '.'), 'logs', 'mqtt_router_errors.log')
        os.makedirs(os.path.dirname(error_log_path), exist_ok=True)
        try:
            with open(error_log_path, 'a') as f:
                f.write(f"\n[{datetime.now()}] FATAL ERROR:\n")
                f.write(f"{str(e)}\n")
                f.write(f"Traceback:\n{traceback.format_exc()}\n")
        except:
            pass
        router.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
