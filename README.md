# 🔍 Lost2Found

**Lost2Found** is a high-end, full-stack web application designed to streamline the process of reporting lost items and recovering found assets within a **closed network** such as a **campus, workplace, or organization**.

The platform ensures secure item recovery using **QR-based identification**, **real-time alerts**, **admin verification**, and **smart matching**, while encouraging honesty through a **gamified reward system**.

---

## 🚀 Features

- **NeuralTags**  
  Generate unique QR codes for your valuable items.

- **Real-time Alerts**  
  Get notified immediately when someone scans your lost item's QR tag.

- **Karma Leaderboard**  
  A gamified system that rewards users for honesty using karma/reward points.

- **Admin Verification**  
  Secure claim process with administrative oversight and status tracking.

- **Smart Matching**  
  Automated matching between lost item reports and found item submissions.

---

## 🛠️ Tech Stack

- **Backend:** Python (Flask)
- **Database:** MySQL
- **Frontend:** Tailwind CSS, Jinja2
- **Icons:** Lucide Icons
- **Visuals & Analytics:** Chart.js

---

## 📋 Database Setup

Ensure **MySQL** is installed on your system before proceeding.

### 1️⃣ Create the Database
```sql
CREATE DATABASE lost2found;
```

### 2️⃣ Import the Schema
```bash
mysql -u your_username -p lost2found < database_setup.sql
```

---

## ⚙️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Dhanush1756/lost2found.git
```

### 2️⃣ Navigate into the Project Directory
```bash
cd lost2found
```

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Run the Application
```bash
python app.py
```

The application will run locally at:
```
http://127.0.0.1:5000/
```

---

## 🏗️ Database Structure

The system relies on the following core tables:

- **users**  
  Manages user profiles, authentication, and karma points.

- **lost_items**  
  Stores reported lost item details and locations.

- **found_items**  
  Stores information about items found by users.

- **claims**  
  Handles claim requests, admin verification, and claim status.

- **neural_tags**  
  Manages unique QR identity codes assigned to items.

- **messages**  
  Facilitates communication related to specific claims.

---

## 📌 Final Steps to Push to GitHub

After saving this content into your `README.md` file, run the following commands:

```bash
git add .
git commit -m "Added README for Lost2Found"
git push origin main
```

---

### 🔐 Lost2Found — Turning honesty into a habit.
