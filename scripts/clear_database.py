#!/usr/bin/env python3
"""
Clear Database Tables - Remove all data but keep table structure
Usage: python3 clear_database.py [db_path]
"""

import sys
import os
import sqlite3
import argparse

def clear_database(db_path):
    """
    Clear all data from database tables but keep table structure
    
    Args:
        db_path: Path to database file
    """
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Remove system tables
        tables = [t for t in tables if not t.startswith('sqlite_')]
        
        if not tables:
            print("⚠️  No tables found in database")
            conn.close()
            return False
        
        print(f"🗑️  Clearing {len(tables)} tables...")
        
        # Disable foreign key constraints temporarily
        cursor.execute("PRAGMA foreign_keys = OFF")
        
        # Clear each table
        cleared_count = 0
        for table in tables:
            try:
                # Get row count before deletion
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]
                
                # Delete all rows
                cursor.execute(f"DELETE FROM {table}")
                
                # Reset auto-increment sequences
                cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
                
                cleared_count += row_count
                print(f"   ✅ {table}: Cleared {row_count} rows")
            except Exception as e:
                print(f"   ⚠️  {table}: Error - {e}")
        
        # Re-enable foreign key constraints
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Commit transaction before VACUUM
        conn.commit()
        
        # Vacuum database to reclaim space (must be outside transaction)
        print("🧹 Vacuuming database...")
        try:
            conn.execute("VACUUM")
        except Exception as e:
            print(f"   ⚠️  Vacuum warning: {e} (continuing anyway)")
        
        conn.close()
        
        print(f"\n✅ Database cleared successfully!")
        print(f"   Total rows cleared: {cleared_count}")
        print(f"   Tables preserved: {len(tables)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    parser = argparse.ArgumentParser(description="Clear all data from database tables")
    parser.add_argument('db_path', nargs='?', help='Path to database file (default: session.db in current directory)')
    
    args = parser.parse_args()
    
    # Find database path
    if args.db_path:
        db_path = args.db_path
    else:
        # Try to find session.db in common locations
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.dirname(script_dir)
        env_project_dir = os.environ.get('PROJECT_DIR', project_dir)
        
        possible_paths = [
            'session.db',
            'logs/session.db',
            os.path.join(os.environ.get('SESSION_LOG_DIR', ''), 'session.db'),
            os.path.join(env_project_dir, 'logs', 'session.db'),
            os.path.join(project_dir, 'logs', 'session.db'),
        ]
        
        db_path = None
        for path in possible_paths:
            if path and os.path.exists(path):
                db_path = path
                break
        
        if not db_path:
            print("❌ Database not found. Please specify path:")
            print("   python3 clear_database.py <db_path>")
            return 1
    
    print(f"📊 Database: {db_path}\n")
    
    # Confirm deletion
    response = input("⚠️  This will DELETE ALL DATA from the database. Continue? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("❌ Cancelled")
        return 1
    
    success = clear_database(db_path)
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
