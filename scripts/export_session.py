#!/usr/bin/env python3
"""
Export Session - Export centralized session database to Excel and SQL
Usage: python3 export_session.py [session_directory]
"""

import sys
import os
import argparse
from database_exporter import DatabaseExporter

def main():
    parser = argparse.ArgumentParser(description="Export session database to Excel and SQL")
    parser.add_argument('session_dir', nargs='?', help='Session directory (default: latest)')
    parser.add_argument('--excel-only', action='store_true', help='Export only Excel')
    parser.add_argument('--sql-only', action='store_true', help='Export only SQL')
    
    args = parser.parse_args()
    
    # Find session directory
    if args.session_dir:
        session_dir = args.session_dir
    else:
        # Find latest session
        logs_dir = "logs"
        if not os.path.exists(logs_dir):
            print("❌ Logs directory not found")
            return 1
        
        import glob
        sessions = [d for d in glob.glob(os.path.join(logs_dir, "*")) if os.path.isdir(d)]
        if not sessions:
            print("❌ No sessions found")
            return 1
        
        session_dir = max(sessions, key=os.path.getmtime)
        print(f"📁 Using latest session: {os.path.basename(session_dir)}")
    
    # Find database
    db_path = os.path.join(session_dir, "session.db")
    if not os.path.exists(db_path):
        # Fallback to old name
        db_path = os.path.join(session_dir, "snort_mqtt.db")
        if not os.path.exists(db_path):
            print(f"❌ Database not found in {session_dir}")
            return 1
    
    print(f"📊 Exporting database: {db_path}\n")
    
    # Export
    exporter = DatabaseExporter(db_path)
    
    if args.excel_only:
        exporter.export_to_excel()
    elif args.sql_only:
        exporter.export_to_sql()
    else:
        exporter.export_all()
    
    print(f"\n✅ Export complete!")
    print(f"📁 Exports saved to: {exporter.exports_dir}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
