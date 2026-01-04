-- 1. Create the Database
CREATE DATABASE IF NOT EXISTS lost2found;
USE lost2found;

-- 2. Users Table
-- Stores user profiles, karma, and reward points for the leaderboard 
CREATE TABLE users (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked TINYINT(1) DEFAULT 0,
    karma INT DEFAULT 0,
    reward_points INT DEFAULT 0
);

-- 3. Lost Items Table
-- Tracks items reported as lost by users [cite: 13]
CREATE TABLE lost_items (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    item_name VARCHAR(255) NOT NULL,
    category ENUM('Electronics', 'Bag', 'ID/Wallet', 'Personal Items', 'Other') NOT NULL,
    location_lost VARCHAR(255) NOT NULL,
    date_lost DATE NOT NULL,
    description TEXT,
    user_email VARCHAR(255),
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT,
    image_path VARCHAR(255),
    rejection_reason TEXT,
    location_coords VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- 4. Found Items Table
-- Tracks items reported as found by finders [cite: 12]
CREATE TABLE found_items (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    item_name VARCHAR(255) NOT NULL,
    category VARCHAR(255),
    location VARCHAR(255),
    date_found DATE NOT NULL,
    image_path VARCHAR(255) NOT NULL,
    finder_name VARCHAR(255),
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finder_email VARCHAR(100),
    location_coords VARCHAR(100),
    description TEXT
);

-- 5. Claims Table
-- Manages the administrative approval process for matching lost and found items [cite: 11]
CREATE TABLE claims (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lost_item_id INT NOT NULL,
    found_item_id INT NOT NULL,
    proof_description TEXT NOT NULL,
    proof_image_path VARCHAR(255),
    admin_status VARCHAR(50),
    admin_remarks TEXT,
    claim_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_email VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    solved_at DATETIME,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    rejection_reason TEXT,
    FOREIGN KEY (lost_item_id) REFERENCES lost_items(id) ON DELETE CASCADE,
    FOREIGN KEY (found_item_id) REFERENCES found_items(id) ON DELETE CASCADE
);

-- 6. Matches Table
-- Tracks potential matches identified between lost and found items [cite: 14]
CREATE TABLE matches (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lost_id INT NOT NULL,
    found_id INT NOT NULL,
    status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
    proof TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lost_id) REFERENCES lost_items(id) ON DELETE CASCADE,
    FOREIGN KEY (found_id) REFERENCES found_items(id) ON DELETE CASCADE
);

-- 7. Messages Table
-- Handles the chat system between owners and finders [cite: 15]
CREATE TABLE messages (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    claim_id INT,
    sender_email VARCHAR(255),
    message_text TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (claim_id) REFERENCES claims(id) ON DELETE CASCADE
);

-- 8. NeuralTags Table
-- Stores details for unique QR codes generated for item protection [cite: 16]
CREATE TABLE neural_tags (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    item_name VARCHAR(100) NOT NULL,
    item_desc TEXT,
    unique_code VARCHAR(100) NOT NULL UNIQUE,
    qr_image_path VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 9. Tag Messages Table
-- Logs alerts sent when someone scans a NeuralTag [cite: 17]
CREATE TABLE tag_messages (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tag_id INT NOT NULL,
    owner_id INT NOT NULL,
    finder_contact VARCHAR(255),
    message TEXT,
    is_read TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tag_id) REFERENCES neural_tags(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 10. Audit Logs Table
-- Records system-wide actions for tracking and security [cite: 10]
CREATE TABLE audit_logs (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    item_type ENUM('lost', 'found'),
    item_id INT,
    action_taken VARCHAR(255),
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);