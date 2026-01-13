#!/usr/bin/env python3
"""
Async Database Handler - Non-blocking database operations
Ensures all data is logged even under high load
"""

import sqlite3
import threading
import queue
import time
import os
from functools import wraps

class AsyncDBHandler:
    """Async database handler with queue-based writes"""
    
    def __init__(self, db_path=None, max_queue_size=1000):
        """
        Initialize async database handler
        
        Args:
            db_path: Path to database (default: session.db from environment)
            max_queue_size: Maximum queue size before blocking
        """
        if db_path is None:
            if os.environ.get('UNIFIED_DB_PATH'):
                db_path = os.environ.get('UNIFIED_DB_PATH')
            else:
                session_dir = os.environ.get('SESSION_LOG_DIR', 'logs')
                BASE_LOGS_DIR = os.environ.get('BASE_LOGS_DIR', session_dir)
                if BASE_LOGS_DIR and BASE_LOGS_DIR != session_dir:
                    db_path = os.path.join(BASE_LOGS_DIR, 'session.db')
                else:
                    db_path = os.path.join(session_dir, 'session.db')
        
        self.db_path = db_path
        self.write_queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self.worker_thread = None
        self._start_worker()
    
    def _start_worker(self):
        """Start background worker thread for database writes"""
        def worker():
            while self.running:
                try:
                    # Get operation from queue (timeout to allow checking self.running)
                    try:
                        operation = self.write_queue.get(timeout=1.0)
                    except queue.Empty:
                        continue
                    
                    # Execute database operation
                    try:
                        operation()
                    except Exception as e:
                        print(f"⚠️  Async DB write error: {e}")
                    
                    self.write_queue.task_done()
                except Exception as e:
                    print(f"⚠️  Async DB worker error: {e}")
                    time.sleep(0.1)
        
        self.worker_thread = threading.Thread(target=worker, daemon=True, name="async_db_worker")
        self.worker_thread.start()
    
    def execute_async(self, operation):
        """
        Execute database operation asynchronously
        
        Args:
            operation: Callable that performs database operation
        """
        try:
            self.write_queue.put_nowait(operation)
        except queue.Full:
            # Queue full - execute synchronously to avoid data loss
            try:
                operation()
            except Exception as e:
                print(f"⚠️  Sync DB write error (queue full): {e}")
    
    def execute_sync(self, operation):
        """
        Execute database operation synchronously (for critical operations)
        
        Args:
            operation: Callable that performs database operation
        """
        try:
            operation()
        except Exception as e:
            print(f"⚠️  Sync DB write error: {e}")
    
    def stop(self):
        """Stop async handler and wait for queue to drain"""
        self.running = False
        if self.worker_thread:
            self.write_queue.join()
            self.worker_thread.join(timeout=5.0)

# Global instance
_async_db_handler = None

def get_async_db_handler(db_path=None):
    """Get or create global async database handler"""
    global _async_db_handler
    if _async_db_handler is None:
        _async_db_handler = AsyncDBHandler(db_path)
    return _async_db_handler

def async_db_operation(func):
    """Decorator to make database operations async"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        handler = get_async_db_handler()
        handler.execute_async(lambda: func(*args, **kwargs))
    return wrapper

if __name__ == "__main__":
    # Test
    handler = get_async_db_handler()
    
    def test_operation():
        conn = sqlite3.connect(handler.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        count = c.fetchone()[0]
        print(f"✅ Database has {count} tables")
        conn.close()
    
    handler.execute_async(test_operation)
    time.sleep(1)
    handler.stop()
