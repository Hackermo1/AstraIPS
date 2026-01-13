#!/usr/bin/env python3
"""Wrapper script to get MAC address from IP for Lua inspector"""

import sys
from query_flags_helper import FlagsQueryHelper

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("")
        sys.exit(0)
    
    device_ip = sys.argv[1]
    
    # Try to get MAC from database
    import os
    import sqlite3
    
    db_path = None
    if os.environ.get('UNIFIED_DB_PATH'):
        db_path = os.environ.get('UNIFIED_DB_PATH')
    else:
        session_dir = os.environ.get('SESSION_LOG_DIR', 'logs')
        BASE_LOGS_DIR = os.environ.get('BASE_LOGS_DIR', session_dir)
        if BASE_LOGS_DIR and BASE_LOGS_DIR != session_dir:
            db_path = os.path.join(BASE_LOGS_DIR, 'session.db')
        else:
            db_path = os.path.join(session_dir, 'session.db')
    
    if db_path and os.path.exists(db_path):
        try:
            from db_connection_helper import get_db_connection
            with get_db_connection(db_path) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT mac_address FROM ip_mac_mapping
                    WHERE ip_address = ?
                    ORDER BY last_seen DESC LIMIT 1
                ''', (device_ip,))
                result = c.fetchone()
            
            if result:
                print(result[0])
                sys.exit(0)
        except:
            pass
    
    # Fallback: return IP if MAC not found
    print(device_ip)
