#!/usr/bin/env python3
"""
Database Query Helper for Snort IDS Rules
Fast database queries for heuristic and AI flags
Used by Lua inspector via file IPC
"""

import sqlite3
import os
import sys
import hashlib
import time
from typing import Dict, Optional, Tuple

class FlagsQueryHelper:
    def __init__(self, db_path=None):
        """
        Initialize flags query helper
        
        Args:
            db_path: Path to session.db (defaults to SESSION_LOG_DIR/session.db)
        """
        if db_path is None:
            session_dir = os.environ.get('SESSION_LOG_DIR')
            if session_dir and os.path.exists(session_dir):
                db_path = os.path.join(session_dir, 'session.db')
            else:
                # Fallback: try to find session.db in common locations
                # Auto-detect paths relative to script location
                script_dir = os.path.dirname(os.path.abspath(__file__))
                project_dir = os.path.dirname(script_dir)
                possible_paths = [
                    os.path.join(project_dir, 'logs'),
                    project_dir,
                    os.getcwd(),
                    os.path.join(os.getcwd(), 'logs'),
                ]
                for base in possible_paths:
                    # Find latest session directory
                    if os.path.exists(base):
                        for item in sorted(os.listdir(base), reverse=True):
                            item_path = os.path.join(base, item)
                            if os.path.isdir(item_path):
                                potential_db = os.path.join(item_path, 'session.db')
                                if os.path.exists(potential_db):
                                    db_path = potential_db
                                    break
                    if db_path:
                        break
        
        self.db_path = db_path
        self.conn = None
        self.cache = {}  # Simple cache: command_hash -> flags
        self.cache_ttl = 60  # Cache TTL in seconds
        self.cache_timestamps = {}
        
        if db_path and os.path.exists(db_path):
            self._connect()
        else:
            print(f"⚠️  Database not found: {db_path}", file=sys.stderr)
    
    def _connect(self):
        """Connect to database"""
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=30.0)
            self.conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
        except Exception as e:
            print(f"❌ Database connection error: {e}", file=sys.stderr)
            self.conn = None
    
    def _get_command_hash(self, command: str, device_ip: str) -> str:
        """Generate hash for command deduplication"""
        combined = f"{device_ip}|{command}"
        return hashlib.md5(combined.encode('utf-8')).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid"""
        if cache_key not in self.cache_timestamps:
            return False
        age = time.time() - self.cache_timestamps[cache_key]
        return age < self.cache_ttl
    
    def get_flags(self, command: str, device_ip: str) -> Dict[str, Optional[str]]:
        """
        Get heuristic and AI flags for a command
        
        Args:
            command: Command string to check
            device_ip: Device IP address
            
        Returns:
            Dictionary with 'heuristic_flag', 'ai_flag', and 'heuristic_flag_number'
            - heuristic_flag: "MAL" or "NOR" (general flag)
            - ai_flag: "MAL" or "NOR" (AI flag)
            - heuristic_flag_number: Numeric flag (2, 9, etc.) if available
        """
        if not self.conn:
            return {'heuristic_flag': None, 'ai_flag': None}
        
        # Check cache first
        cache_key = self._get_command_hash(command, device_ip)
        if cache_key in self.cache and self._is_cache_valid(cache_key):
            return self.cache[cache_key]
        
        # Query database
        command_hash = self._get_command_hash(command, device_ip)
        cursor = self.conn.cursor()
        
        # Query user_flags table
        cursor.execute('''
            SELECT heuristic_flag, ai_flag
            FROM user_flags
            WHERE user_id = ? AND command_hash = ?
            ORDER BY timestamp DESC
            LIMIT 1
        ''', (device_ip, command_hash))
        
        result = cursor.fetchone()
        
        flags = {
            'heuristic_flag': None,
            'ai_flag': None
        }
        
        if result:
            flags['heuristic_flag'] = result['heuristic_flag']
            flags['ai_flag'] = result['ai_flag']
        else:
            # Also check by command text (in case hash doesn't match)
            cursor.execute('''
                SELECT heuristic_flag, ai_flag
                FROM user_flags
                WHERE user_id = ? AND command = ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (device_ip, command))
            
            result = cursor.fetchone()
            if result:
                flags['heuristic_flag'] = result['heuristic_flag']
                flags['ai_flag'] = result['ai_flag']
        
        # Cache result
        self.cache[cache_key] = flags
        self.cache_timestamps[cache_key] = time.time()
        
        return flags
    
    def get_ai_verdict(self, command: str, device_ip: str) -> Optional[str]:
        """
        Get latest AI verdict for a command from ai_analysis table
        
        Args:
            command: Command string
            device_ip: Device IP address
            
        Returns:
            'BLOCK' or 'ALLOW' or None
        """
        if not self.conn:
            return None
        
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT verdict, is_malicious
            FROM ai_analysis
            WHERE device_ip = ? AND command = ?
            ORDER BY timestamp DESC
            LIMIT 1
        ''', (device_ip, command))
        
        result = cursor.fetchone()
        if result:
            if result['is_malicious'] or result['verdict'] == 'BLOCK':
                return 'BLOCK'
            else:
                return 'ALLOW'
        
        return None
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None


def main():
    """
    CLI interface for querying flags
    Usage: query_flags_helper.py <command> <device_ip>
    Output: heuristic_flag|ai_flag|ai_verdict
    """
    if len(sys.argv) < 3:
        print("Usage: query_flags_helper.py <command> <device_ip>", file=sys.stderr)
        sys.exit(1)
    
    command = sys.argv[1]
    device_ip = sys.argv[2]
    
    helper = FlagsQueryHelper()
    flags = helper.get_flags(command, device_ip)
    ai_verdict = helper.get_ai_verdict(command, device_ip)
    
    # Output format: heuristic_flag|ai_flag|ai_verdict
    output = f"{flags['heuristic_flag'] or 'NONE'}|{flags['ai_flag'] or 'NONE'}|{ai_verdict or 'NONE'}"
    print(output)
    
    helper.close()


if __name__ == '__main__':
    main()
