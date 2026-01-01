import mysql.connector

def fix_database_columns():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root", 
            database="lost2found_db"
        )
        cursor = conn.cursor()
        print("Connected to database...")

        # 1. Add 'updated_at' to claims (Fixes your current error)
        try:
            print("Adding 'updated_at' to claims table...")
            cursor.execute("ALTER TABLE claims ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;")
            print("✅ Success: 'updated_at' added.")
        except mysql.connector.Error as err:
            if err.errno == 1060: print("✅ 'updated_at' already exists.")
            else: print(f"⚠️ Warning: {err}")

        # 2. Add 'solved_at' to claims (Required for the Graph)
        try:
            print("Adding 'solved_at' to claims table...")
            cursor.execute("ALTER TABLE claims ADD COLUMN solved_at DATETIME NULL;")
            print("✅ Success: 'solved_at' added.")
        except mysql.connector.Error as err:
            if err.errno == 1060: print("✅ 'solved_at' already exists.")
            else: print(f"⚠️ Warning: {err}")

        conn.commit()
        print("\n🎉 Database Fixed! You can now restart the app.")
        
    except mysql.connector.Error as err:
        print(f"❌ Connection Error: {err}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    fix_database_columns()