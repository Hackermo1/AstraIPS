# File: ai_decision_server.py
import socket
import json
import os
import re
import threading
import argparse
from ips_engine_modular import IPSEngine

def profile_listener(host, port, engine):
    """A threaded listener for incoming device profiles from the 'router'."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Allow reuse of address to avoid "Address already in use" errors
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.listen()
            print(f"✔️  Profile Listener started on TCP {host}:{port}")
            while True:
                conn, addr = s.accept()
                with conn:
                    profile_data = conn.recv(4096).decode()
                    engine.update_device_profile(profile_data)
    except Exception as e:
        print(f"❌ Profile Listener error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Decision Server for IPS/IDS.")
    parser.add_argument('--ip', type=str, default='127.0.0.1',
                        help='IP address for the profile listener to bind to.')
    args = parser.parse_args()

    try:
        # Assume config is in the same directory as this script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base_dir, 'config.json'), 'r') as f:
            config = json.load(f)
        SOCKET_PATH = config['ipc_socket_path']
        PROFILE_LISTENER_PORT = config['profile_listener_port']
    except FileNotFoundError:
        print("❌ FATAL: config.json not found.")
        exit()

    engine = IPSEngine(config)
    if not engine.assets_loaded:
        print("[HALTED] Server cannot start due to asset loading failure.")
        exit()

    # Start the profile listener in a separate, non-blocking thread
    profile_thread = threading.Thread(target=profile_listener,
                                      args=(args.ip, PROFILE_LISTENER_PORT, engine),
                                      daemon=True)
    profile_thread.start()
    
    # Give the profile listener a moment to start
    import time
    time.sleep(0.5)

    # File-based IPC paths for Snort Lua (since Snort doesn't have socket.unix)
    REQUEST_FILE = SOCKET_PATH + ".request"
    RESPONSE_FILE = SOCKET_PATH + ".response"
    
    def file_ipc_listener():
        """Monitor file-based IPC requests from Snort Lua inspector"""
        print(f"✅ File-based IPC listener started for Snort (watching: {REQUEST_FILE})")
        while True:
            try:
                if os.path.exists(REQUEST_FILE):
                    # Read request
                    with open(REQUEST_FILE, 'r') as f:
                        data = f.read().strip()
                    
                    if data:
                        parts = data.split('|', 1)
                        device_ip = parts[0]
                        payload = parts[1] if len(parts) > 1 else ""
                        
                        analysis_result = engine.analyze(device_ip, payload)
                        
                        verdict = 'ALLOW\n'
                        if analysis_result.get("is_malicious"):
                            verdict = 'BLOCK\n'
                        
                        # Write response
                        with open(RESPONSE_FILE, 'w') as f:
                            f.write(verdict)
                        
                        # Remove request file
                        os.remove(REQUEST_FILE)
                
                time.sleep(0.1)  # Check every 100ms
            except KeyboardInterrupt:
                break
            except Exception as e:
                time.sleep(0.1)
    
    # Start file IPC listener in background thread
    file_ipc_thread = threading.Thread(target=file_ipc_listener, daemon=True)
    file_ipc_thread.start()
    
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
    
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(SOCKET_PATH)
            os.chmod(SOCKET_PATH, 0o666) # Make it accessible to Snort
            s.listen()
            print(f"--- AI Decision Server is listening on Unix Socket: {SOCKET_PATH} ---")
            print(f"--- Also monitoring file IPC: {REQUEST_FILE} ---")
            
            while True:
                try:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(1024).decode().strip()
                        if not data: continue
                        
                        parts = data.split('|', 1)
                        device_ip = parts[0]
                        payload = parts[1]
                        
                        analysis_result = engine.analyze(device_ip, payload)
                        
                        verdict = b'ALLOW\n'
                        if analysis_result.get("is_malicious"):
                            verdict = b'BLOCK\n' 
                        
                        conn.sendall(verdict)
                except KeyboardInterrupt:
                    print("\n--- [SHUTDOWN] AI Decision Server ---")
                    break
                except Exception as e:
                    print(f"\nAn error occurred during connection: {e}")
    except Exception as e:
        print(f"❌ Fatal error starting Unix socket listener: {e}")
        import traceback
        traceback.print_exc()
        # Keep the profile listener and file IPC running even if Unix socket fails
        print("⚠️  Unix socket failed, but file IPC and profile listener are still running...")
        try:
            profile_thread.join()
        except KeyboardInterrupt:
            print("\n--- [SHUTTING DOWN] AI Decision Server ---")
