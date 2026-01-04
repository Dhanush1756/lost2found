from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import mysql.connector
import os
import numpy as np
import math
import secrets
from PIL import Image
from fuzzywuzzy import fuzz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from difflib import SequenceMatcher
from flask_mail import Mail, Message
import qrcode
import uuid
import os

app = Flask(__name__)
app.secret_key = "lost2found_secret_key"

# --- CONFIGURATIONS ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- EMAIL CONFIGURATION (Simulation Mode if not set) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com' 
app.config['MAIL_PASSWORD'] = 'your-app-password'    
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@lost2found.com'

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- DATABASE CONNECTION ---
def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="lost2found_db"
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGIN DECORATOR ---
def is_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- EMAIL HELPER ---
def send_notification(subject, recipient, body):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        print(f"📧 EMAIL SENT to {recipient}: {subject}")
    except Exception as e:
        print(f"⚠️ EMAIL SIMULATION (To: {recipient}): {subject}")

# --- SMART GEO-FENCING ---
def calculate_distance(coords1, coords2):
    if not coords1 or not coords2: return float('inf')
    try:
        lat1, lon1 = map(float, coords1.split(','))
        lat2, lon2 = map(float, coords2.split(','))
        R = 6371000 
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c 
    except: return float('inf')

# --- HELPER FUNCTION ---
def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

# --- NEURAL IMAGE & TEXT MATCHING ---
def compare_images(img_path1, img_path2):
    try:
        i1 = Image.open(img_path1).resize((64, 64)).convert('RGB')
        i2 = Image.open(img_path2).resize((64, 64)).convert('RGB')
        h1 = i1.histogram()
        h2 = i2.histogram()
        h1_arr = np.array(h1)
        h2_arr = np.array(h2)
        diff = np.sqrt(np.sum((h1_arr - h2_arr) ** 2))
        max_diff = 40000 
        return int(max(0, 100 - (diff / max_diff * 100)))
    except Exception as e:
        return 0

def calculate_similarity(lost_entry, found_item):
    # Fix: Safely get location keys to prevent KeyError
    found_loc = found_item.get('location_found') or found_item.get('location') or ''
    lost_loc = lost_entry.get('location_lost') or lost_entry.get('location') or ''
    
    # Calculate Component Scores
    text_score = fuzz.token_set_ratio(lost_entry['item_name'], found_item['item_name'])
    cat_score = 100 if lost_entry['category'] == found_item['category'] else 0
    loc_score = fuzz.partial_ratio(lost_loc, found_loc)
    
    # Image Comparison (only if paths exist)
    img_score = 0
    if lost_entry.get('image_path') and found_item.get('image_path'):
        p1 = os.path.join(app.config['UPLOAD_FOLDER'], lost_entry['image_path'])
        p2 = os.path.join(app.config['UPLOAD_FOLDER'], found_item['image_path'])
        if os.path.exists(p1) and os.path.exists(p2):
            img_score = compare_images(p1, p2)
    
    # Weighted Total
    total_score = (text_score * 0.4) + (cat_score * 0.3) + (loc_score * 0.1) + (img_score * 0.2)
    
    # Re-weight if no image comparison was possible
    if img_score == 0:
        total_score = (text_score * 0.5) + (cat_score * 0.35) + (loc_score * 0.15)
        
    return int(total_score)

def find_matches_smart(lost_entry):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # --- FIX: Added 'pending' and 'potential_match' to this query ---
    cursor.execute("SELECT * FROM found_items WHERE status IN ('available', 'matched', 'pending', 'potential_match')")
    found_pool = cursor.fetchall()
    conn.close()
    
    matches = []
    for found in found_pool:
        score = calculate_similarity(lost_entry, found)
        distance = calculate_distance(lost_entry.get('location_coords'), found.get('location_coords'))
        if distance <= 100: score += 15 
        elif distance <= 500: score += 10
        elif distance <= 1000: score += 5
        
        # Threshold > 45
        if score > 45:
            found['match_score'] = round(min(score, 100), 1)
            found['distance_meters'] = round(distance, 0) if distance != float('inf') else None
            matches.append(found)
            
    matches.sort(key=lambda x: x['match_score'], reverse=True)
    return matches
# --- AI FRAUD DETECTION ---
def check_fraud_probability(user_email, item_name):
    fraud_points = 0
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Frequency
    cursor.execute("SELECT COUNT(*) as c FROM claims WHERE user_email=%s AND created_at > NOW() - INTERVAL 1 DAY", (user_email,))
    if cursor.fetchone()['c'] >= 2: fraud_points += 4

    # 2. History
    cursor.execute("SELECT COUNT(*) as c FROM claims WHERE user_email=%s AND status='rejected'", (user_email,))
    if cursor.fetchone()['c'] > 0: fraud_points += 3
    
    # 3. Keywords
    high_value_keywords = ['key', 'wallet', 'phone', 'iphone', 'macbook', 'laptop', 'cash', 'card']
    if any(word in item_name.lower() for word in high_value_keywords):
        fraud_points += 2

    conn.close()
    return fraud_points

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/browse')
def browse():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM found_items WHERE status = 'available' ORDER BY date_found DESC")
    items = cursor.fetchall()
    conn.close()
    return render_template('registry.html', items=items)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action') 
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        if action == 'signup':
            name = request.form.get('fullname')
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email exists.")
            else:
                pw_hash = generate_password_hash(password)
                cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, pw_hash))
                conn.commit()
                flash("Account created! Log in.")

        elif action == 'login':
            if email == "adminl2f@gmail.com" and password == "l2f":
                session['user'] = "ADMIN"
                session['is_admin'] = True
                conn.close()
                return redirect(url_for('admin'))

            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # --- BLOCKED CHECK ---
            if user and check_password_hash(user['password'], password):
                if user['is_blocked'] == 1:
                    flash("⛔ Account Blocked by Admin. Contact Support.")
                    conn.close()
                    return redirect(url_for('login'))
                
                session['user'] = user['email']
                session['is_admin'] = False
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid Credentials")
        conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('index'))

# ==========================================
# 1. DASHBOARD ROUTE 
# ==========================================
@app.route('/dashboard')
@is_logged_in
def dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Get Current User
    cursor.execute("SELECT id, email, name, reward_points FROM users WHERE email = %s", (session['user'],))
    current_user = cursor.fetchone()

    # Handle Deleted/Missing Users (Safety Check)
    if not current_user:
        session.clear()
        conn.close()
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('login'))

    # 2. LOST ITEMS (Fixed JOIN to get Chat Button working)
    # We LEFT JOIN 'claims' so we know if there is a claim_id and what the status is.
    cursor.execute("""
        SELECT 
            l.*, 
            c.id as claim_id, 
            c.admin_status as claim_admin_status 
        FROM lost_items l
        LEFT JOIN claims c ON l.id = c.lost_item_id 
        WHERE l.user_email = %s 
        ORDER BY l.date_lost DESC
    """, (session['user'],))
    lost_items = cursor.fetchall()
    
    # 3. FOUND ITEMS
    cursor.execute("""
        SELECT f.*, c.id as claim_id, c.admin_status as claim_admin_status
        FROM found_items f
        LEFT JOIN claims c ON f.id = c.found_item_id AND c.admin_status = 'approved'
        WHERE f.finder_email = %s ORDER BY f.date_found DESC
    """, (session['user'],))
    found_items = cursor.fetchall()

    # 4. NeuralTags
    cursor.execute("SELECT * FROM neural_tags WHERE user_id = %s ORDER BY created_at DESC", (current_user['id'],))
    my_tags = cursor.fetchall()

    # 5. Inbox Messages
    try:
        cursor.execute("""
            SELECT m.*, t.item_name 
            FROM tag_messages m
            JOIN neural_tags t ON m.tag_id = t.id
            WHERE m.owner_id = %s
            ORDER BY m.created_at DESC
        """, (current_user['id'],))
        inbox_messages = cursor.fetchall()
        unread_count = sum(1 for m in inbox_messages if m.get('is_read', 0) == 0)
    except:
        inbox_messages = []
        unread_count = 0

    # 6. Leaderboard
    cursor.execute("SELECT name, reward_points FROM users ORDER BY reward_points DESC LIMIT 5")
    leaderboard = cursor.fetchall()

    conn.close()
    
    return render_template('dashboard.html', 
                           items=lost_items, 
                           found_items=found_items, 
                           my_tags=my_tags,
                           inbox_messages=inbox_messages,
                           unread_count=unread_count,
                           leaderboard=leaderboard,
                           user_points=current_user['reward_points'])

@app.route('/report_lost', methods=['GET', 'POST'])
@is_logged_in
def report_lost():
    if request.method == 'POST':
        # 1. Capture data from Form (Handling multiple possible HTML names)
        item_name = request.form.get('name') or request.form.get('item_name')
        category = request.form.get('category')
        location_lost = request.form.get('location') or request.form.get('location_lost')
        location_coords = request.form.get('location_coords')
        date_lost = request.form.get('date') or request.form.get('date_lost')
        description = request.form.get('description', 'Reported via Neural Sync')
        
        filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '':
                filename = f"lost_{secrets.token_hex(4)}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # 2. Insert into lost_items using your EXACT schema
            query = """INSERT INTO lost_items 
                       (item_name, category, location_lost, location_coords, date_lost, user_email, description, status, image_path) 
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'searching', %s)"""
            cursor.execute(query, (item_name, category, location_lost, location_coords, date_lost, session['user'], description, filename))
            lost_id = cursor.lastrowid
            conn.commit()

            # 3. NORMALIZATION FOR AI: Make sure keys match what the AI function expects
            lost_entry_for_ai = {
                'id': lost_id,
                'item_name': item_name, 
                'category': category, 
                'location_lost': location_lost, # Used for DB matching logic
                'location': location_lost,      # Duplicate as 'location' in case AI looks for that
                'location_coords': location_coords, 
                'image_path': filename
            }
            
            # 4. Run AI Search
            matches = find_matches_smart(lost_entry_for_ai)
            
            # 5. Update status if matches exist
            if matches:
                cursor.execute("UPDATE lost_items SET status = 'potential_match' WHERE id = %s", (lost_id,))
                conn.commit()

            conn.close()
            return render_template('matches.html', matches=matches, lost_id=lost_id, is_verified=False)

        except Exception as e:
            print(f"DEBUG ERROR: {e}")
            conn.close()
            return "Internal Server Error during matching", 500
        
    return render_template('report_lost.html')
    
@app.route('/report_found', methods=['GET', 'POST'])
@is_logged_in
def report_found():
    if request.method == 'POST':
        item_name = request.form.get('name') or request.form.get('item_name')
        category = request.form.get('category')
        location = request.form.get('location')
        location_coords = request.form.get('location_coords', '')
        date_found = request.form.get('date') or request.form.get('date_found')
        description = request.form.get('description', 'Found via App')
        
        image = request.files.get('image')
        filename = ""
        if image and image.filename != '':
            filename = f"found_{secrets.token_hex(4)}_{secure_filename(image.filename)}"
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db()
        cursor = conn.cursor(dictionary=True, buffered=True)
        
        try:
            # 1. Save to found_items
            cursor.execute("UPDATE users SET karma = karma + 10 WHERE email = %s", (session['user'],))
            insert_query = """
                INSERT INTO found_items 
                (item_name, category, description, location, location_coords, date_found, finder_email, image_path, status) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'searching')
            """
            cursor.execute(insert_query, (item_name, category, description, location, location_coords, date_found, session['user'], filename))
            new_found_id = cursor.lastrowid
            conn.commit() 

            # 2. AI SCAN: Compare this NEW FOUND item against all LOST items
            cursor.execute("SELECT * FROM lost_items WHERE status IN ('searching', 'potential_match')")
            all_lost_items = cursor.fetchall()
            
            # Normalize the current found item for the AI
            current_found_for_ai = {
                'id': new_found_id,
                'item_name': item_name,
                'category': category,
                'location': location,
                'image_path': filename
            }

            match_found_flag = False
            for lost in all_lost_items:
                # IMPORTANT: We ensure the lost item has 'location' for the AI even if DB says 'location_lost'
                lost['location'] = lost.get('location_lost') 
                
                score = calculate_match_score(lost, current_found_for_ai)
                
                if score >= 50:
                    cursor.execute("UPDATE lost_items SET status = 'potential_match' WHERE id = %s", (lost['id'],))
                    cursor.execute("UPDATE found_items SET status = 'potential_match' WHERE id = %s", (new_found_id,))
                    match_found_flag = True
            
            if match_found_flag:
                conn.commit()

        except Exception as e:
            print(f"DEBUG MATCH ERROR: {e}")
        
        conn.close()
        return redirect(url_for('dashboard'))
        
    return render_template('report_found.html')            
@app.route('/claim/<int:fid>/<int:lid>', methods=['POST'])
@is_logged_in
def claim(fid, lid):
    user_email = session['user']
    proof = request.form['proof']
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT item_name, finder_email FROM found_items WHERE id=%s", (fid,))
    item_data = cursor.fetchone()
    
    risk_score = check_fraud_probability(user_email, item_data['item_name'])
    status = 'flagged' if risk_score >= 5 else 'pending'
    
    if risk_score >= 5: flash("Claim flagged for review.")
    else: flash("Claim submitted.")

    try:
        cursor.execute("""INSERT INTO claims (lost_item_id, found_item_id, user_email, proof_description, status, admin_status) 
                          VALUES (%s, %s, %s, %s, %s, 'pending')""", (lid, fid, user_email, proof, status))
        cursor.execute("UPDATE lost_items SET status = 'pending_approval' WHERE id = %s", (lid,))
        conn.commit()
        
        if status != 'flagged':
            send_notification("Claim Received", item_data['finder_email'], f"Claim for '{item_data['item_name']}' received.")
            
    except Exception as e:
        print(e)
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/chat/<int:claim_id>', methods=['GET', 'POST'])
@is_logged_in
def chat(claim_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch Claim Details (Keep your existing Join logic)
    query = """
        SELECT c.*, f.finder_email, f.item_name, f.id as found_id
        FROM claims c 
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.id = %s
    """
    cursor.execute(query, (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        conn.close()
        return redirect(url_for('dashboard'))
        
    # Security Check
    if session['user'] not in [claim['user_email'], claim['finder_email']] and not session.get('is_admin'):
        conn.close()
        flash("Unauthorized access.")
        return redirect(url_for('dashboard'))

    # --- FIX: FETCH THE FULL ITEM DETAILS ---
    # We need this so the template can check 'item.status'
    cursor.execute("SELECT * FROM found_items WHERE id = %s", (claim['found_item_id'],))
    item = cursor.fetchone() 

    # 2. Handle Sending Messages
    if request.method == 'POST':
        msg = request.form.get('message')
        if msg:
            # Added 'timestamp' to ensure order is correct
            cursor.execute("""
                INSERT INTO messages (claim_id, sender_email, message_text, timestamp) 
                VALUES (%s, %s, %s, NOW())
            """, (claim_id, session['user'], msg))
            conn.commit()
            # Redirect to prevent form re-submission on refresh
            return redirect(url_for('chat', claim_id=claim_id))
    
    # 3. Fetch Chat History
    cursor.execute("SELECT * FROM messages WHERE claim_id = %s ORDER BY timestamp ASC", (claim_id,))
    messages = cursor.fetchall()
    
    is_finder = (session['user'] == claim['finder_email'])
    
    conn.close()
    
    # 4. Pass 'item' to the template
    return render_template('chat.html', 
                           messages=messages, 
                           claim=claim, 
                           claim_id=claim_id, 
                           is_finder=is_finder, 
                           item=item) # <--- This fixes the error

@app.route('/mark_returned/<int:claim_id>', methods=['GET', 'POST'])
@is_logged_in
def mark_returned(claim_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Get the claim details
    cursor.execute("SELECT * FROM claims WHERE id=%s", (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        conn.close()
        flash("Claim not found", "danger")
        return redirect(url_for('dashboard'))

    # GUARD CHECK (From previous fix)
    if claim['status'] == 'solved' or claim['status'] == 'returned':
        conn.close()
        flash("This item is already marked as returned.", "info")
        return redirect(url_for('dashboard'))

    # --- FIX 1: UPDATE CLAIM STATUS TO 'solved' AND SET TIMESTAMP ---
    # This removes it from "Active Chats", adds it to "History", 
    # and provides the date for the Admin Graph.
    cursor.execute("UPDATE claims SET status='solved', solved_at=NOW() WHERE id=%s", (claim_id,))
    
    # 2. Update FOUND ITEM status (Keeps User Dashboard "RETURNED" badge)
    cursor.execute("UPDATE found_items SET status='returned' WHERE id=%s", (claim['found_item_id'],))

    # 3. Update LOST ITEM status
    cursor.execute("UPDATE lost_items SET status='returned' WHERE id=%s", (claim['lost_item_id'],))

    # 4. Reward the Finder
    cursor.execute("SELECT finder_email FROM found_items WHERE id=%s", (claim['found_item_id'],))
    item = cursor.fetchone()

    if item:
        finder_email = item['finder_email']
        cursor.execute("SELECT id FROM users WHERE email=%s", (finder_email,))
        user_record = cursor.fetchone()
        
        if user_record:
            cursor.execute("UPDATE users SET reward_points = reward_points + 50 WHERE id=%s", (user_record['id'],))
            flash("Item marked returned. Finder rewarded 50 points!", "success")
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/mark_message_read/<int:message_id>')
@is_logged_in
def mark_message_read(message_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Update status to Read (1)
    cursor.execute("UPDATE tag_messages SET is_read = 1 WHERE id = %s", (message_id,))
    
    conn.commit()
    conn.close()
    
    # Redirect back to dashboard with 'tab=alerts' parameter so it stays on the right tab
    return redirect(url_for('dashboard', tab='alerts'))

# --- 1. IMPROVED MATCHING LOGIC (Fixes the "No Match" Issue) ---
def calculate_match_score(lost, found):
    # CRITICAL: Use 'location_lost' for the Lost Item 
    # and 'location' for the Found Item (from the form data)
    lost_loc = lost.get('location_lost', '')
    found_loc = found.get('location', '') # This comes from the found item dictionary
    
    # 1. Text Similarity (Item Name)
    text_score = fuzz.token_set_ratio(lost['item_name'], found['item_name'])
    
    # 2. Location Similarity
    loc_score = fuzz.partial_ratio(lost_loc.lower(), found_loc.lower())
    
    # 3. Category Match
    cat_score = 100 if lost['category'] == found['category'] else 0
    
    # Weighted Average
    total = (text_score * 0.5) + (cat_score * 0.3) + (loc_score * 0.2)
    return int(total)

# --- 2. THE MISSING 'RESCAN' ROUTE ---
@app.route('/rescan/<int:lost_id>')
@is_logged_in
def rescan(lost_id):
    """
    Manually triggers the AI Search for a specific Lost Item.
    This is what runs when you click the 'Rescan' button.
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Get the specific Lost Item
    cursor.execute("SELECT * FROM lost_items WHERE id = %s AND user_email = %s", (lost_id, session['user']))
    lost_item = cursor.fetchone()
    
    if not lost_item:
        flash("Item not found or unauthorized.", "danger")
        return redirect(url_for('dashboard'))

    # 2. Get ALL Found items that are available
    cursor.execute("SELECT * FROM found_items WHERE status IN ('searching', 'available')")
    found_pool = cursor.fetchall()
    conn.close()

    # 3. Run the Matching Logic
    matches = []
    for found in found_pool:
        score = calculate_match_score(lost_item, found)
        
        # LOWERED THRESHOLD TO 50 TO ENSURE YOU SEE RESULTS
        if score >= 50: 
            found['match_score'] = score
            matches.append(found)
    
    # Sort best matches first
    matches = sorted(matches, key=lambda x: x['match_score'], reverse=True)

    # 4. Show the Results Page
    if matches:
        flash(f"Scan complete! Found {len(matches)} potential matches.", "success")
        return render_template('matches.html', matches=matches, lost_id=lost_id)
    else:
        flash("Scan complete. No new matches found yet.", "warning")
        return redirect(url_for('dashboard'))

# --- 3. UPDATED BACKGROUND AUTO-SCAN (For Report Found) ---
def run_background_auto_match(new_found_item):
    """
    Automatically checks matches when a FOUND item is uploaded.
    Sends email if match > 60%.
    """
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        # Get all active Lost items
        cursor.execute("SELECT * FROM lost_items WHERE status = 'searching'")
        lost_pool = cursor.fetchall()
        
        for lost in lost_pool:
            score = calculate_match_score(lost, new_found_item)
            
            if score >= 60:
                print(f"✅ MATCH DETECTED: {score}% for {lost['user_email']}")
                try:
                    msg = Message("🔍 Match Found!", recipients=[lost['user_email']])
                    msg.body = f"Good news! A found item '{new_found_item['item_name']}' matches your lost report.\n\nLogin to Dashboard to view."
                    mail.send(msg)
                except Exception as e:
                    print(f"Email failed: {e}")
        conn.close()
    except Exception as e:
        print(f"Background Scan Error: {e}")

# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
def admin():
    # 1. Security Check
    # Ensure this matches the string you set in session during login
    if 'user' not in session or session.get('user') != "ADMIN": 
        flash('Unauthorized access. Admin privileges required.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # =========================================================
    # 2. Fetch Pending Claims (Crucial for Verification)
    # =========================================================
    # This joins ALL three tables: Claims, Found Items, and Lost Items
    # It ensures you see the 'Proof' text the user typed in matches.html
    cursor.execute("""
        SELECT 
            c.id as claim_id,
            c.user_email as claimant_email,
            c.proof_description,
            c.created_at,
            c.status as risk_status,
            f.item_name as found_item,
            f.image_path as found_image,
            f.id as found_id,
            l.item_name as lost_item,
            l.image_path as lost_image,
            l.id as lost_id
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        JOIN lost_items l ON c.lost_item_id = l.id
        WHERE c.admin_status = 'pending'
        ORDER BY c.created_at ASC
    """)
    pending_claims = cursor.fetchall()

    # =========================================================
    # 3. Fetch Active Chats (Ongoing Investigations)
    # =========================================================
    cursor.execute("""
        SELECT 
            c.id as claim_id, 
            f.item_name, 
            c.status,
            f.finder_email, 
            c.user_email as claimant
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.status NOT IN ('solved', 'rejected')
    """)
    active_chats = cursor.fetchall()

    # =========================================================
    # 4. Fetch Resolution Log (History)
    # =========================================================
    cursor.execute("""
        SELECT 
            c.id, 
            f.item_name, 
            c.solved_at,
            f.finder_email,
            c.user_email as claimant
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.status = 'solved'
        ORDER BY c.solved_at DESC
        LIMIT 50
    """)
    history = cursor.fetchall()

    # =========================================================
    # 5. Fetch User Statistics
    # =========================================================
    cursor.execute("SELECT id, name, email, is_blocked FROM users")
    users = cursor.fetchall()

    # =========================================================
    # 6. Graph Data (Last 7 Days Activity)
    # =========================================================
    cursor.execute("""
        SELECT DATE(solved_at) as date, COUNT(*) as count 
        FROM claims 
        WHERE status = 'solved' AND solved_at >= DATE(NOW()) - INTERVAL 7 DAY
        GROUP BY DATE(solved_at) 
        ORDER BY DATE(solved_at)
    """)
    graph_data = cursor.fetchall()
    
    dates = [row['date'].strftime('%Y-%m-%d') for row in graph_data]
    counts = [row['count'] for row in graph_data]

    # Stats Counters for Top Cards
    stats = {
        'users': len(users),
        'pending': len(pending_claims),
        'active': len(active_chats),
        'solved': len(history)
    }

    # =========================================================
    # 7. NEW: Karma Leaderboard (The missing piece)
    # =========================================================
    cursor.execute("""
        SELECT name, email, reward_points 
        FROM users 
        ORDER BY reward_points DESC 
        LIMIT 10
    """)
    leaderboard = cursor.fetchall()

    # Stats Counters
    stats = {
        'users': len(users),
        'pending': len(pending_claims),
        'active': len(active_chats),
        'solved': len(history)
    }


    cursor.close()
    conn.close()
    return render_template('admin.html', 
                           claims=pending_claims, 
                           active_chats=active_chats,
                           history=history,
                           users=users,
                           stats=stats,
                           graph_dates=dates, 
                           graph_counts=counts,
                           leaderboard=leaderboard)

@app.route('/approve/<int:cid>', methods=['POST'])
def approve(cid):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT lost_item_id, found_item_id, user_email FROM claims WHERE id = %s", (cid,))
    res = cursor.fetchone()
    if res:
        cursor.execute("UPDATE claims SET admin_status = 'approved' WHERE id = %s", (cid,))
        cursor.execute("UPDATE found_items SET status = 'matched' WHERE id = %s", (res['found_item_id'],))
        cursor.execute("UPDATE lost_items SET status = 'potential_match' WHERE id = %s", (res['lost_item_id'],))
        conn.commit()
        send_notification("Claim Approved", res['user_email'], "Claim approved. Chat unlocked.")
        flash("Claim Approved!")
    conn.close()
    return redirect(url_for('admin'))

@app.route('/reject/<int:claim_id>', methods=['POST'])
@is_logged_in
def reject(claim_id):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    reason = request.form.get('reason', 'No reason provided.')
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT lost_item_id, found_item_id, user_email FROM claims WHERE id = %s", (claim_id,))
    res = cursor.fetchone()
    if res:
        cursor.execute("UPDATE lost_items SET status = 'searching', rejection_reason = %s WHERE id = %s", (reason, res['lost_item_id']))
        cursor.execute("UPDATE found_items SET status = 'available' WHERE id = %s", (res['found_item_id'],))
        cursor.execute("UPDATE claims SET admin_status = 'rejected', status = 'rejected' WHERE id = %s", (claim_id,))
        conn.commit()
        send_notification("Claim Rejected", res['user_email'], f"Rejected: {reason}")
        flash("Claim rejected.")
    conn.close()
    return redirect(url_for('admin'))

@app.route('/check_matches/<int:lost_id>')
@is_logged_in
def check_matches(lost_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lost_items WHERE id = %s AND user_email = %s", (lost_id, session['user']))
    lost_item = cursor.fetchone()
    
    if not lost_item: 
        conn.close()
        return redirect(url_for('dashboard'))

    # 1. Run the AI Match (Now includes pending items)
    matches = find_matches_smart(lost_item)

    # 2. Check for existing claims to update UI status
    for match in matches:
        cursor.execute("""
            SELECT admin_status, id as claim_id 
            FROM claims 
            WHERE lost_item_id = %s AND found_item_id = %s
        """, (lost_id, match['id']))
        claim = cursor.fetchone()
        
        # Inject status so matches.html knows what badge to show
        if claim:
            match['match_record_id'] = claim['claim_id'] # For the 'Chat' button link
            if claim['admin_status'] == 'approved':
                match['db_status'] = 'verified'
            else:
                match['db_status'] = claim['admin_status'] # e.g., 'pending'
        else:
            match['db_status'] = None

    conn.close()
    return render_template('matches.html', matches=matches, lost_id=lost_id)
# --- NEW ROUTE: TOGGLE BLOCK ---
@app.route('/toggle_block/<int:user_id>')
def toggle_block(user_id):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Get current status
    cursor.execute("SELECT is_blocked FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    if user:
        new_status = 0 if user['is_blocked'] else 1
        cursor.execute("UPDATE users SET is_blocked = %s WHERE id = %s", (new_status, user_id))
        conn.commit()
        action = "Blocked" if new_status else "Unblocked"
        flash(f"User successfully {action}.")
    
    conn.close()
    return redirect(url_for('admin'))

@app.route('/verify_match/<int:lost_id>/<int:found_id>', methods=['POST'])
@is_logged_in
def verify_match(lost_id, found_id):
    conn = get_db()
    cursor = conn.cursor()

    # 1. Check if this claim already exists to prevent duplicates
    cursor.execute("""
        SELECT id FROM claims 
        WHERE lost_item_id = %s AND found_item_id = %s
    """, (lost_id, found_id))
    existing = cursor.fetchone()

    if existing:
        flash("You have already submitted a request for this item.", "warning")
        conn.close()
        return redirect(url_for('dashboard'))

    # 2. Insert into Claims Table
    # NOTE: 'proof_description' is NOT NULL in your DB, so we provide a default value.
    query = """
        INSERT INTO claims 
        (lost_item_id, found_item_id, user_email, proof_description, admin_status, status, created_at)
        VALUES (%s, %s, %s, 'AI Match Verification Request', 'pending', 'investigating', NOW())
    """
    cursor.execute(query, (lost_id, found_id, session['user']))
    
    # 3. Update status of both items to prevent re-matching
    cursor.execute("UPDATE lost_items SET status = 'pending' WHERE id = %s", (lost_id,))
    cursor.execute("UPDATE found_items SET status = 'pending' WHERE id = %s", (found_id,))

    conn.commit()
    conn.close()

    flash("Verification request sent to Admin! Check your dashboard for updates.", "success")
    return redirect(url_for('dashboard'))

# ==========================================
# NEURAL TAGS (QR CODES)
# ==========================================

@app.route('/create_tag', methods=['POST'])
@is_logged_in
def create_tag():
    user = get_user_by_email(session['user'])
    item_name = request.form['item_name']
    item_desc = request.form['item_desc']
    
    # 1. Generate unique secure code
    unique_code = str(uuid.uuid4())[:8] # Short unique ID
    
    # 2. Create QR Code pointing to your app's scan route
    # In production, replace 'http://127.0.0.1:5000' with your real domain (e.g. ngrok or pythonanywhere)
    scan_url = f"http://127.0.0.1:5000/scan/{unique_code}"
    
    qr = qrcode.make(scan_url)
    qr_filename = f"tag_{unique_code}.png"
    qr_path = os.path.join('static', 'qrcodes', qr_filename)
    
    # Ensure directory exists
    os.makedirs(os.path.join('static', 'qrcodes'), exist_ok=True)
    qr.save(qr_path)
    
    # 3. Save to DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO neural_tags (user_id, item_name, item_desc, unique_code, qr_image_path)
        VALUES (%s, %s, %s, %s, %s)
    """, (user['id'], item_name, item_desc, unique_code, f"qrcodes/{qr_filename}"))
    conn.commit()
    conn.close()
    
    flash('NeuralTag generated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/scan/<unique_code>')
def scan_tag(unique_code):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch tag details and owner email
    cursor.execute("""
        SELECT t.*, u.email as owner_email, u.name as owner_name 
        FROM neural_tags t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.unique_code = %s
    """, (unique_code,))
    tag = cursor.fetchone()
    conn.close()
    
    if not tag:
        return "Invalid or Deleted Tag", 404
        
    return render_template('tag_found.html', tag=tag)

# ==========================================
# 1. DELETE LOST ITEM (Fixed Session Check)
# ==========================================
@app.route('/delete_item/<int:item_id>', methods=['GET', 'POST'])
def delete_item(item_id):
    # FIX 1: Check for 'user' (email), NOT 'user_id'
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # FIX 2: Check ownership using 'user_email'
    cursor.execute("SELECT * FROM lost_items WHERE id = %s", (item_id,))
    item = cursor.fetchone()
    
    if item and item['user_email'] == session['user']:
        cursor.execute("DELETE FROM lost_items WHERE id = %s", (item_id,))
        conn.commit()
        
        # Delete image file
        if item['image_path']:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], item['image_path'])
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass
        flash('Item deleted successfully.', 'success')
    else:
        flash('Permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('dashboard'))

# ==========================================
# 2. DELETE FOUND ITEM (Fixed Session Check)
# ==========================================
@app.route('/delete_found_item/<int:item_id>', methods=['GET', 'POST'])
def delete_found_item(item_id):
    # FIX 1: Check for 'user' (email)
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # FIX 2: Check ownership using 'finder_email'
    cursor.execute("SELECT * FROM found_items WHERE id = %s", (item_id,))
    item = cursor.fetchone()
    
    if item and item['finder_email'] == session['user']:
        cursor.execute("DELETE FROM found_items WHERE id = %s", (item_id,))
        conn.commit()
        
        if item['image_path']:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], item['image_path'])
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass
        flash('Found item deleted successfully.', 'success')
    else:
        flash('Permission denied.', 'danger')
        
    conn.close()
    return redirect(url_for('dashboard'))


# ==========================================
# 3. DELETE NEURAL TAG (FIXED)
# ==========================================
@app.route('/delete_tag/<int:tag_id>', methods=['POST'])
def delete_tag(tag_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Get Current User ID (Required because table uses user_id, not email)
    cursor.execute("SELECT id FROM users WHERE email = %s", (session['user'],))
    current_user = cursor.fetchone()

    if not current_user:
        conn.close()
        return redirect(url_for('login'))

    # 2. Verify Ownership & Get File Path
    # TABLE NAME IS 'neural_tags', NOT 'tags'
    cursor.execute("SELECT * FROM neural_tags WHERE id = %s", (tag_id,))
    tag = cursor.fetchone()

    # Check if tag exists and belongs to the current user
    if tag and tag['user_id'] == current_user['id']:
        cursor.execute("DELETE FROM neural_tags WHERE id = %s", (tag_id,))
        conn.commit()
        
        # 3. Optional: Delete the QR Code Image File
        if tag['qr_image_path']:
            try:
                # Path is stored like "qrcodes/tag_xyz.png", so we join with 'static'
                file_path = os.path.join('static', tag['qr_image_path'])
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Error deleting QR file: {e}")

        flash('Neural Tag deleted successfully.', 'success')
    else:
        flash('Permission denied or tag not found.', 'danger')

    conn.close()
    return redirect(url_for('dashboard'))


# ==========================================
# 4. EDIT NEURAL TAG (FIXED)
# ==========================================
@app.route('/edit_tag/<int:tag_id>', methods=['POST'])
def edit_tag(tag_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get the new name from the form
    new_name = request.form.get('tag_name')
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Get Current User ID
    cursor.execute("SELECT id FROM users WHERE email = %s", (session['user'],))
    current_user = cursor.fetchone()

    # 2. Verify Ownership
    # TABLE NAME IS 'neural_tags'
    cursor.execute("SELECT * FROM neural_tags WHERE id = %s", (tag_id,))
    tag = cursor.fetchone()

    if tag and tag['user_id'] == current_user['id']:
        # COLUMN NAME IS 'item_name', NOT 'name'
        cursor.execute("UPDATE neural_tags SET item_name = %s WHERE id = %s", (new_name, tag_id))
        conn.commit()
        flash('Tag updated successfully.', 'success')
    else:
        flash('Permission denied.', 'danger')

    conn.close()
    return redirect(url_for('dashboard'))

# ==========================================
# 5. EDIT LOST ITEM ROUTE (Correct Column: location_lost)
# ==========================================
@app.route('/edit_lost_item/<int:item_id>', methods=['GET', 'POST'])
def edit_lost_item(item_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM lost_items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    if not item or item['user_email'] != session['user']:
        flash('Permission denied.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    if item['status'] == 'verified' or item['status'] == 'returned':
        flash('Cannot edit verified or returned items.', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('item_name')
        date = request.form.get('date_lost')
        location = request.form.get('location') # Input from HTML
        category = request.form.get('category')
        desc = request.form.get('description')
        
        image = request.files.get('image')
        image_path = item['image_path']

        if image and image.filename != '':
            filename = secure_filename(f"lost_{secrets.token_hex(4)}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = filename

        # FIX: Using 'location_lost' as requested
        try:
            cursor.execute("""
                UPDATE lost_items 
                SET item_name=%s, date_lost=%s, location_lost=%s, category=%s, description=%s, image_path=%s
                WHERE id=%s
            """, (name, date, location, category, desc, image_path, item_id))
            conn.commit()
            flash('Lost item report updated.', 'success')
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", "danger")
        finally:
            conn.close()
        
        return redirect(url_for('dashboard'))

    # Pre-fill fix: Template expects 'location', DB has 'location_lost'
    if item and 'location' not in item and 'location_lost' in item:
        item['location'] = item['location_lost']

    conn.close()
    return render_template('report_lost.html', item=item, is_edit=True)

# ==========================================
# 6. EDIT FOUND ITEM ROUTE (Fixed KeyError)
# ==========================================
@app.route('/edit_found_item/<int:item_id>', methods=['GET', 'POST'])
def edit_found_item(item_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM found_items WHERE id = %s", (item_id,))
    item = cursor.fetchone()

    # 1. Security Check
    if not item or item['finder_email'] != session['user']:
        flash('Permission denied.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    # 2. Status Check (FIXED: Uses .get() to prevent crash)
    # This safely checks the status. If column is missing, it assumes 'None' (not approved)
    admin_status = item.get('claim_admin_status') 
    
    if admin_status == 'approved':
        flash('Cannot edit items that are already approved.', 'warning')
        conn.close()
        return redirect(url_for('dashboard'))

    # 3. Handle Updates (POST)
    if request.method == 'POST':
        name = request.form.get('item_name')
        date = request.form.get('date_found')
        location = request.form.get('location')
        category = request.form.get('category')
        desc = request.form.get('description')
        
        image = request.files.get('image')
        image_path = item['image_path']

        if image and image.filename != '':
            filename = secure_filename(f"found_{secrets.token_hex(4)}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_path = filename

        # Using 'location' as verified in previous step
        try:
            cursor.execute("""
                UPDATE found_items 
                SET item_name=%s, date_found=%s, location=%s, category=%s, description=%s, image_path=%s
                WHERE id=%s
            """, (name, date, location, category, desc, image_path, item_id))
            conn.commit()
            flash('Found item report updated.', 'success')
        except mysql.connector.Error as err:
            flash(f"Database Error: {err}", "danger")
        finally:
            conn.close()
        
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('report_found.html', item=item, is_edit=True)

@app.route('/alert_owner/<unique_code>', methods=['POST'])
def alert_owner(unique_code):
    finder_contact = request.form.get('finder_contact')
    message = request.form.get('message')
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Find the tag and the owner
    cursor.execute("""
        SELECT t.id as tag_id, t.user_id as owner_id, u.name as owner_name 
        FROM neural_tags t 
        JOIN users u ON t.user_id = u.id 
        WHERE unique_code=%s
    """, (unique_code,))
    tag = cursor.fetchone()
    
    if tag:
        # 2. Save message to the Inbox (Database)
        cursor.execute("""
            INSERT INTO tag_messages (tag_id, owner_id, finder_contact, message)
            VALUES (%s, %s, %s, %s)
        """, (tag['tag_id'], tag['owner_id'], finder_contact, message))
        conn.commit()
        
        # 3. Notify the finder
        flash(f"Message sent to {tag['owner_name']}! They will contact you shortly.", 'success')
    else:
        flash("Tag not found.", "danger")
        
    conn.close()
    return redirect(url_for('index'))
      
# ==========================================
#  KARMA LEADERBOARD
# ==========================================

@app.route('/leaderboard')
def leaderboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    # Get top 10 users with karma > 0
    cursor.execute("SELECT name, karma FROM users WHERE karma > 0 ORDER BY karma DESC LIMIT 10")
    leaders = cursor.fetchall()
    conn.close()
    return render_template('leaderboard.html', leaders=leaders)

# ==========================================
# PUBLIC SOS LINK
# ==========================================
@app.route('/view_lost/<int:item_id>')
def view_lost(item_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch safe public details (No private emails/phone numbers exposed directly)
    cursor.execute("""
        SELECT id, item_name, description, location, date_lost, image_path, status 
        FROM lost_items WHERE id = %s
    """, (item_id,))
    item = cursor.fetchone()
    conn.close()

    if not item:
        return "Item not found or removed.", 404

    return render_template('public_item.html', item=item)

if __name__ == '__main__':
    app.run(debug=True)