#!/usr/bin/env python3
"""
Database Connection Helper - Prevents SQLite locking issues
- Enables WAL mode for concurrent reads/writes
- Adds retry logic with exponential backoff
- Proper connection management
"""

import sqlite3
import time
import os
from contextlib import contextmanager

def get_db_path():
    """Get the unified database path"""
    if os.environ.get('UNIFIED_DB_PATH'):
        return os.environ.get('UNIFIED_DB_PATH')
    
    session_dir = os.environ.get('SESSION_LOG_DIR', 'logs')
    BASE_LOGS_DIR = os.environ.get('BASE_LOGS_DIR', session_dir)
    if BASE_LOGS_DIR and BASE_LOGS_DIR != session_dir:
        return os.path.join(BASE_LOGS_DIR, 'session.db')
    else:
        return os.path.join(session_dir, 'session.db')

@contextmanager
def get_db_connection(db_path=None, timeout=30.0, max_retries=5):
    """
    Get a database connection with WAL mode and retry logic
    
    Args:
        db_path: Path to database (default: session.db from environment)
        timeout: Connection timeout in seconds
        max_retries: Maximum retry attempts for locked database
    
    Yields:
        sqlite3.Connection: Database connection
    """
    if db_path is None:
        db_path = get_db_path()
    
    # Ensure directory exists
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    
    conn = None
    last_error = None
    
    for attempt in range(max_retries):
        try:
            # Connect with timeout
            conn = sqlite3.connect(db_path, timeout=timeout)
            
            # Enable WAL mode for concurrent reads/writes
            conn.execute('PRAGMA journal_mode=WAL')
            
            # Optimize for concurrent access
            conn.execute('PRAGMA synchronous=NORMAL')  # Faster than FULL, safer than OFF
            conn.execute('PRAGMA busy_timeout=30000')  # 30 second busy timeout
            
            # Set foreign keys (if needed)
            conn.execute('PRAGMA foreign_keys=ON')
            
            yield conn
            
            # Success - commit and break
            conn.commit()
            break
            
        except sqlite3.OperationalError as e:
            last_error = e
            error_str = str(e).lower()
            
            if "database is locked" in error_str or "locked" in error_str:
                if attempt < max_retries - 1:
                    # Exponential backoff: 0.1s, 0.2s, 0.4s, 0.8s, 1.6s
                    wait_time = 0.1 * (2 ** attempt)
                    time.sleep(wait_time)
                    continue
                else:
                    # Last attempt failed
                    raise sqlite3.OperationalError(
                        f"Database locked after {max_retries} attempts: {e}"
                    )
            else:
                # Other operational error - don't retry
                raise
                
        except Exception as e:
            last_error = e
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
            
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    if conn and last_error:
        # If we got here with an error, raise it
        raise last_error

def execute_with_retry(db_path, operation, *args, max_retries=5, **kwargs):
    """
    Execute a database operation with retry logic
    
    Args:
        db_path: Path to database
        operation: Function that takes a cursor and executes operations
        *args: Arguments to pass to operation
        max_retries: Maximum retry attempts
        **kwargs: Keyword arguments to pass to operation
    
    Returns:
        Result from operation function
    """
    for attempt in range(max_retries):
        try:
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                result = operation(cursor, *args, **kwargs)
                conn.commit()
                return result
                
        except sqlite3.OperationalError as e:
            error_str = str(e).lower()
            if "database is locked" in error_str and attempt < max_retries - 1:
                wait_time = 0.1 * (2 ** attempt)
                time.sleep(wait_time)
                continue
            raise

def init_database_with_wal(db_path=None):
    """
    Initialize database and ensure WAL mode is enabled
    
    Args:
        db_path: Path to database (default: session.db from environment)
    """
    if db_path is None:
        db_path = get_db_path()
    
    # Ensure directory exists
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    
    # Connect and enable WAL mode
    with get_db_connection(db_path) as conn:
        # WAL mode is already enabled in get_db_connection
        # Just verify it's set
        cursor = conn.cursor()
        cursor.execute('PRAGMA journal_mode')
        mode = cursor.fetchone()[0]
        if mode.upper() != 'WAL':
            cursor.execute('PRAGMA journal_mode=WAL')
            conn.commit()
