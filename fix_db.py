import mysql.connector

def fix_and_wipe_database():
    try:
        # --- CONFIGURATION: Check your DB name and password ---
        db_config = {
            "host": "localhost",
            "user": "root",
            "password": "root",  # CHANGE TO YOUR PASSWORD
            "database": "lost2found_db" # CHANGE TO YOUR DB NAME
        }

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        print("🔌 Connected to MySQL...")

        # --- STEP 1: WIPE ALL DATA ---
        print("🧹 Wiping all table data...")
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        
        # List of tables to empty
        tables = [
            "audit_logs", "claims", "found_items", "lost_items", 
            "messages", "neural_tags", "tag_messages", "users", "matches"
        ]
        
        for table in tables:
            try:
                cursor.execute(f"TRUNCATE TABLE {table}")
                print(f"   ✅ {table} emptied.")
            except mysql.connector.Error as err:
                # If table doesn't exist, we will create it later, so just print a note
                print(f"   ⚠️ Could not truncate {table} (might not exist yet): {err}")

        # --- STEP 2: FIX TABLE STRUCTURES (FOUND ITEMS) ---
        print("\n🛠️  Fixing table structures...")

        # 1. Change 'category' to VARCHAR
        try:
            cursor.execute("ALTER TABLE found_items MODIFY COLUMN category VARCHAR(255)")
            print("   ✅ 'category' is now VARCHAR.")
        except: pass

        # 2. Rename 'location_found' to 'location' (Standardizing names)
        try:
            cursor.execute("SHOW COLUMNS FROM found_items LIKE 'location_found'")
            if cursor.fetchone():
                cursor.execute("ALTER TABLE found_items CHANGE location_found location VARCHAR(255)")
                print("   ✅ Renamed 'location_found' to 'location'.")
        except: pass

        # 3. Ensure 'description' column exists
        try:
            cursor.execute("ALTER TABLE found_items ADD COLUMN description TEXT")
            print("   ✅ Added 'description' column.")
        except: pass

        # --- STEP 3: CREATE MISSING 'MATCHES' TABLE ---
        print("\n✨ Creating missing tables...")
        
        # Drop it first to ensure clean state
        cursor.execute("DROP TABLE IF EXISTS matches")
        
        create_matches_query = """
        CREATE TABLE matches (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lost_id INT NOT NULL,
            found_id INT NOT NULL,
            status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
            proof TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (lost_id) REFERENCES lost_items(id) ON DELETE CASCADE,
            FOREIGN KEY (found_id) REFERENCES found_items(id) ON DELETE CASCADE
        );
        """
        cursor.execute(create_matches_query)
        print("   ✅ 'matches' table created successfully.")

        # --- FINAL CLEANUP ---
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
        conn.commit()
        conn.close()
        print("\n🚀 ALL DONE! Database is fresh, empty, and fixed.")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    fix_and_wipe_database()