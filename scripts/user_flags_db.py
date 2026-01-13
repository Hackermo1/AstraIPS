#!/usr/bin/env python3
"""
User Flags Database
Separate database for tracking user flags (heuristic and AI)
"""

import sqlite3
import os
import hashlib
from datetime import datetime

class UserFlagsDB:
    def __init__(self, db_path=None):
        """
        Initialize user flags database
        
        Args:
            db_path: Path to database file (default: session.db in SESSION_LOG_DIR)
        """
        # Use centralized session database if available
        if db_path is None:
            session_dir = os.environ.get('SESSION_LOG_DIR')
            if session_dir and os.path.exists(session_dir):
                db_path = os.path.join(session_dir, 'session.db')
            else:
                # Fallback to old location
                base_dir = os.path.dirname(os.path.abspath(__file__))
                ml_dir = os.path.join(base_dir, "ML related things files")
                if os.path.exists(ml_dir):
                    db_path = os.path.join(ml_dir, "user_flags.db")
                else:
                    db_path = os.path.join(base_dir, "user_flags.db")
        elif not os.path.isabs(db_path):
            # Relative path - check if session directory exists
            session_dir = os.environ.get('SESSION_LOG_DIR')
            if session_dir and os.path.exists(session_dir):
                db_path = os.path.join(session_dir, db_path)
            else:
                # Fallback to old location
                base_dir = os.path.dirname(os.path.abspath(__file__))
                ml_dir = os.path.join(base_dir, "ML related things files")
                if os.path.exists(ml_dir):
                    db_path = os.path.join(ml_dir, db_path)
                else:
                    db_path = os.path.join(base_dir, db_path)
        
        self.db_path = db_path
        self.conn = None
        self.setup_database()
    
    def setup_database(self):
        """Create user_flags table"""
        # Ensure directory exists
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        # Create database connection
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        cursor = self.conn.cursor()
        
        # Create table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_id TEXT NOT NULL,
                device_ip TEXT,
                mac_address TEXT,
                command TEXT NOT NULL,
                heuristic_flag TEXT,
                heuristic_flag_source TEXT DEFAULT 'heuristic',
                ai_flag TEXT,
                ai_flag_source TEXT DEFAULT 'ai',
                command_hash TEXT,
                UNIQUE(user_id, command_hash)
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_flags_user_id 
            ON user_flags(user_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_flags_device_ip 
            ON user_flags(device_ip)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_flags_heuristic_flag 
            ON user_flags(heuristic_flag)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_flags_ai_flag 
            ON user_flags(ai_flag)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_flags_timestamp 
            ON user_flags(timestamp)
        ''')
        
        self.conn.commit()
        print(f"✅ User flags database initialized: {self.db_path}")
    
    def _get_command_hash(self, command):
        """Generate hash for command deduplication"""
        return hashlib.md5(command.encode('utf-8')).hexdigest()
    
    def add_flag(self, user_id, device_ip, command, heuristic_flag=None, ai_flag=None, mac_address=None):
        """
        Add or update flags for a user
        
        Args:
            user_id: User identifier (device_ip)
            device_ip: IP address
            command: Full command string
            heuristic_flag: "MAL" or "NOR" from heuristic
            ai_flag: "MAL" or "NOR" from AI
            mac_address: MAC address (optional)
        """
        try:
            command_hash = self._get_command_hash(command)
            cursor = self.conn.cursor()
            
            # Check if entry exists
            cursor.execute('''
                SELECT heuristic_flag, ai_flag 
                FROM user_flags 
                WHERE user_id = ? AND command_hash = ?
            ''', (user_id, command_hash))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing entry
                existing_heuristic = existing[0]
                existing_ai = existing[1]
                
                # Update heuristic flag if provided (allow overwrite)
                new_heuristic = heuristic_flag if heuristic_flag is not None else existing_heuristic
                
                # Update AI flag if provided (allow overwrite)
                new_ai = ai_flag if ai_flag is not None else existing_ai
                
                cursor.execute('''
                    UPDATE user_flags 
                    SET heuristic_flag = ?,
                        ai_flag = ?,
                        timestamp = CURRENT_TIMESTAMP
                    WHERE user_id = ? AND command_hash = ?
                ''', (new_heuristic, new_ai, user_id, command_hash))
            else:
                # Insert new entry - always insert even if both flags are None
                cursor.execute('''
                    INSERT INTO user_flags 
                    (user_id, device_ip, mac_address, command, 
                     heuristic_flag, heuristic_flag_source, 
                     ai_flag, ai_flag_source, command_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    device_ip,
                    mac_address,
                    command,
                    heuristic_flag,
                    'heuristic' if heuristic_flag else None,
                    ai_flag,
                    'ai' if ai_flag else None,
                    command_hash
                ))
            
            self.conn.commit()
            # Debug: print when flags are stored
            if heuristic_flag or ai_flag:
                print(f"   💾 Stored flags: heuristic={heuristic_flag}, ai={ai_flag} for command: {command[:50]}...")
        except Exception as e:
            import traceback
            print(f"   ❌ Error storing flags in user_flags: {e}")
            print(f"   Traceback: {traceback.format_exc()}")
            # Don't re-raise - allow execution to continue
    
    def get_user_flags(self, user_id, limit=100):
        """
        Get all flags for a user
        
        Args:
            user_id: User identifier
            limit: Maximum number of records to return
            
        Returns:
            List of tuples: (command, heuristic_flag, ai_flag, timestamp)
        """
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT command, heuristic_flag, ai_flag, timestamp 
            FROM user_flags 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (user_id, limit))
        return cursor.fetchall()
    
    def get_flag_statistics(self):
        """
        Get flag statistics
        
        Returns:
            dict with heuristic and AI flag counts
        """
        cursor = self.conn.cursor()
        
        # Heuristic flag statistics
        cursor.execute('''
            SELECT heuristic_flag, COUNT(*) as count 
            FROM user_flags 
            WHERE heuristic_flag IS NOT NULL
            GROUP BY heuristic_flag
        ''')
        heuristic_stats = cursor.fetchall()
        
        # AI flag statistics
        cursor.execute('''
            SELECT ai_flag, COUNT(*) as count 
            FROM user_flags 
            WHERE ai_flag IS NOT NULL
            GROUP BY ai_flag
        ''')
        ai_stats = cursor.fetchall()
        
        return {
            'heuristic': dict(heuristic_stats),
            'ai': dict(ai_stats)
        }
    
    def get_user_flag_summary(self, user_id):
        """
        Get summary of flags for a user
        
        Returns:
            dict with flag counts per user
        """
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_commands,
                SUM(CASE WHEN heuristic_flag = 'MAL' THEN 1 ELSE 0 END) as heuristic_mal,
                SUM(CASE WHEN heuristic_flag = 'NOR' THEN 1 ELSE 0 END) as heuristic_nor,
                SUM(CASE WHEN ai_flag = 'MAL' THEN 1 ELSE 0 END) as ai_mal,
                SUM(CASE WHEN ai_flag = 'NOR' THEN 1 ELSE 0 END) as ai_nor
            FROM user_flags
            WHERE user_id = ?
        ''', (user_id,))
        
        result = cursor.fetchone()
        if result:
            return {
                'user_id': user_id,
                'total_commands': result[0] or 0,
                'heuristic_mal': result[1] or 0,
                'heuristic_nor': result[2] or 0,
                'ai_mal': result[3] or 0,
                'ai_nor': result[4] or 0
            }
        return None
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
