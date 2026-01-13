#!/usr/bin/env python3
"""
Router Manager - Wrapper for Router Network Scanner
Integrates router scanning functionality with mqttlive system
"""

import os
import sys
import subprocess
import signal
import time
import json
import argparse

class RouterManager:
    def __init__(self, config_path=None):
        """
        Initialize Router Manager
        
        Args:
            config_path: Path to router configuration JSON file (optional)
        """
        self.config_path = config_path
        self.scanner_process = None
        self.scanner_pid = None
        self.config = self._load_config()
        # Try multiple possible locations for the scanner script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)
        possible_paths = [
            os.path.join(project_dir, "router-config", "pull_scanner.py"),
            os.path.join(script_dir, "pull_scanner.py"),
            os.path.join(script_dir, "router-config", "pull_scanner.py"),
        ]
        self.scanner_script = None
        for path in possible_paths:
            if os.path.exists(path):
                self.scanner_script = path
                break
        if not self.scanner_script:
            self.scanner_script = possible_paths[0]  # Default to first path
    
    def _load_config(self):
        """Load router configuration from config file"""
        default_config = {
            "enabled": False,
            "router_ip": "",
            "router_user": "",
            "router_pass": "",
            "scan_interval": 5,
            "auto_start": False
        }
        
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"⚠️  Error loading router config: {e}")
                print("   Run installer/setup_router.sh to configure router scanning")
        else:
            print("⚠️  Router config not found. Run installer/setup_router.sh to configure")
        
        return default_config
    
    def is_enabled(self):
        """Check if router scanning is enabled"""
        return self.config.get("enabled", False)
    
    def start(self):
        """Start the router scanner"""
        if not self.is_enabled():
            print("ℹ️  Router scanner is disabled in configuration")
            return False
        
        if not os.path.exists(self.scanner_script):
            print(f"⚠️  Router scanner script not found: {self.scanner_script}")
            return False
        
        if self.is_running():
            print("ℹ️  Router scanner is already running")
            return True
        
        try:
            print("🔍 Starting Router Network Scanner...")
            print(f"   Router IP: {self.config['router_ip']}")
            print(f"   Scan Interval: {self.config['scan_interval']} seconds")
            
            # Start scanner as background process with SESSION_LOG_DIR environment variable
            env = os.environ.copy()
            # Pass SESSION_LOG_DIR to scanner so it uses centralized session.db
            session_dir = os.environ.get('SESSION_LOG_DIR')
            if session_dir:
                env['SESSION_LOG_DIR'] = session_dir
            
            self.scanner_process = subprocess.Popen(
                [sys.executable, self.scanner_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(self.scanner_script),
                env=env
            )
            
            self.scanner_pid = self.scanner_process.pid
            
            # Give it a moment to start
            time.sleep(2)
            
            # Check if process is still running
            if self.scanner_process.poll() is None:
                print(f"✅ Router scanner started (PID: {self.scanner_pid})")
                return True
            else:
                # Process died immediately
                stdout, stderr = self.scanner_process.communicate()
                print(f"❌ Router scanner failed to start")
                if stderr:
                    print(f"   Error: {stderr.decode()}")
                return False
                
        except Exception as e:
            print(f"❌ Error starting router scanner: {e}")
            return False
    
    def stop(self):
        """Stop the router scanner"""
        if not self.is_running():
            print("ℹ️  Router scanner is not running")
            return True
        
        try:
            print(f"🛑 Stopping Router Scanner (PID: {self.scanner_pid})...")
            
            if self.scanner_process:
                # Try graceful termination first
                self.scanner_process.terminate()
                try:
                    self.scanner_process.wait(timeout=5)
                    print("✅ Router scanner stopped gracefully")
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't stop
                    self.scanner_process.kill()
                    self.scanner_process.wait()
                    print("✅ Router scanner force-stopped")
            
            # Also kill by PID if process still exists
            if self.scanner_pid:
                try:
                    os.kill(self.scanner_pid, signal.SIGTERM)
                    time.sleep(1)
                    os.kill(self.scanner_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # Process already dead
            
            # Kill any remaining pull_scanner processes
            try:
                subprocess.run(
                    ["pkill", "-f", "pull_scanner.py"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except:
                pass
            
            self.scanner_process = None
            self.scanner_pid = None
            return True
            
        except Exception as e:
            print(f"⚠️  Error stopping router scanner: {e}")
            return False
    
    def is_running(self):
        """Check if router scanner is running"""
        if self.scanner_process:
            if self.scanner_process.poll() is None:
                return True
            else:
                # Process died
                self.scanner_process = None
                self.scanner_pid = None
                return False
        
        # Check by PID
        if self.scanner_pid:
            try:
                os.kill(self.scanner_pid, 0)  # Check if process exists
                return True
            except (ProcessLookupError, OSError):
                self.scanner_pid = None
                return False
        
        # Check by process name
        try:
            result = subprocess.run(
                ["pgrep", "-f", "pull_scanner.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                pids = result.stdout.decode().strip().split('\n')
                if pids and pids[0]:
                    self.scanner_pid = int(pids[0])
                    return True
        except:
            pass
        
        return False
    
    def get_status(self):
        """Get router scanner status"""
        return {
            "enabled": self.is_enabled(),
            "running": self.is_running(),
            "pid": self.scanner_pid,
            "router_ip": self.config.get("router_ip"),
            "scan_interval": self.config.get("scan_interval")
        }

def main():
    """CLI interface for router manager"""
    parser = argparse.ArgumentParser(description="Router Network Scanner Manager")
    parser.add_argument('--start', action='store_true', help='Start router scanner')
    parser.add_argument('--stop', action='store_true', help='Stop router scanner')
    parser.add_argument('--status', action='store_true', help='Check router scanner status')
    parser.add_argument('--config', type=str, help='Path to router configuration file')
    
    args = parser.parse_args()
    
    # Initialize manager - find config in project's router-config directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    config_path = args.config or os.path.join(project_dir, "router-config", "router_config.json")
    manager = RouterManager(config_path)
    
    if args.start:
        if manager.start():
            sys.exit(0)
        else:
            sys.exit(1)
    elif args.stop:
        if manager.stop():
            sys.exit(0)
        else:
            sys.exit(1)
    elif args.status:
        status = manager.get_status()
        print(f"Router Scanner Status:")
        print(f"  Enabled: {status['enabled']}")
        print(f"  Running: {status['running']}")
        print(f"  PID: {status['pid']}")
        print(f"  Router IP: {status['router_ip']}")
        print(f"  Scan Interval: {status['scan_interval']} seconds")
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
