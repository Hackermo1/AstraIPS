#!/usr/bin/env python3
import sqlite3
import sys

def fix_incomplete_transactions(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM mqtt_traffic WHERE status IS NULL")
    null_count = cursor.fetchone()[0]
    
    if null_count == 0:
        print("✅ No incomplete transactions found")
        return
    
    print(f"🔧 Fixing {null_count} incomplete transactions...")
    
    cursor.execute("""
        UPDATE mqtt_traffic 
        SET status = CASE
            WHEN blocked = 1 THEN 'blocked'
            WHEN processed = 1 THEN 'processed'
            WHEN broadcasted = 1 THEN 'broadcasted'
            WHEN dropped = 1 THEN 'dropped'
            ELSE 'received'
        END
        WHERE status IS NULL
    """)
    
    cursor.execute("UPDATE mqtt_traffic SET processed = 0 WHERE processed IS NULL")
    cursor.execute("UPDATE mqtt_traffic SET blocked = 0 WHERE blocked IS NULL")
    cursor.execute("UPDATE mqtt_traffic SET dropped = 0 WHERE dropped IS NULL")
    cursor.execute("UPDATE mqtt_traffic SET broadcasted = 0 WHERE broadcasted IS NULL")
    
    conn.commit()
    
    cursor.execute("SELECT COUNT(*) FROM mqtt_traffic WHERE status IS NULL")
    remaining = cursor.fetchone()[0]
    
    print(f"✅ Fixed {null_count - remaining} transactions")
    conn.close()

if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "logs/session.db"
    fix_incomplete_transactions(db_path)
