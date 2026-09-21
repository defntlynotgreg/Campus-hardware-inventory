import sqlite3
import logging
import os
import csv
import time
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ValidationError
import re
import bcrypt

# Cloud Database Support for Render & Supabase
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    import psycopg

class PGConnectionWrapper:
    def __init__(self, conn):
        self.conn = conn
        self.cursor = conn.cursor()
    def execute(self, query, params=None):
        pg_query = query.replace('?', '%s')
        if params:
            self.cursor.execute(pg_query, params)
        else:
            self.cursor.execute(pg_query)
        return self.cursor
    def commit(self):
        self.conn.commit()
    def fetchone(self):
        return self.cursor.fetchone()
    def fetchall(self):
        return self.cursor.fetchall()
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.conn.close()

def get_db(db_name="hardware_inventory.db"):
    if DATABASE_URL:
        # Connect normally; Render's env variable now handles the IPv4 routing
        conn = psycopg.connect(DATABASE_URL)
        return PGConnectionWrapper(conn)
    else:
        conn = sqlite3.connect(db_name, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

def setup_logger():
    log_dir = "app_logging"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logging.basicConfig(filename=os.path.join(log_dir, "app.log"), level=logging.INFO,
                        format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    return logging.getLogger("LabTrackerApp")

logger = setup_logger()

class UserSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: str = Field(...)
    password: str = Field(...)
    
    @field_validator('username')
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v): raise ValueError('Username must be alphanumeric.')
        return v
    @field_validator('email')
    def validate_email(cls, v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", v): raise ValueError('Invalid email format.')
        return v
    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 8: raise ValueError('Password minimum 8 chars.')
        if not re.search(r"[A-Z]", v): raise ValueError('Password requires an uppercase letter.')
        if not re.search(r"[0-9]", v): raise ValueError('Password requires a number.')
        if not re.search(r"[@#$%^&*]", v): raise ValueError('Password requires a special char (@#$%^&*).')
        return v

def init_db(db_name="hardware_inventory.db"):
    with get_db(db_name) as conn:
        if not DATABASE_URL:
            conn.execute("PRAGMA journal_mode=WAL;") 
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, role TEXT NOT NULL, failed_attempts INTEGER DEFAULT 0, is_locked INTEGER DEFAULT 0
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id SERIAL PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL,
                desired_password TEXT NOT NULL, status TEXT DEFAULT 'PENDING'
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hardware (
                item_id SERIAL PRIMARY KEY, item_name TEXT NOT NULL, category TEXT NOT NULL,
                total_qty INTEGER NOT NULL, available_qty INTEGER NOT NULL, unit_price REAL NOT NULL, status TEXT NOT NULL
            )""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS borrow_logs (
                log_id SERIAL PRIMARY KEY, username TEXT NOT NULL, item_id INTEGER NOT NULL,
                item_name TEXT NOT NULL, qty_borrowed INTEGER NOT NULL, total_liability REAL NOT NULL,
                borrow_date TEXT NOT NULL, status TEXT DEFAULT 'BORROWED'
            )""")
        conn.commit()

class AuthController:
    def __init__(self, db_name="hardware_inventory.db"):
        self.db_name = db_name

    def register_user(self, username, email, password, role):
        try:
            validated = UserSchema(username=username, email=email, password=password)
        except ValidationError as e:
            return False, f"Validation Error: {e.errors()[0]['msg']}"
            
        hashed_pw = bcrypt.hashpw(validated.password.encode('utf-8'), bcrypt.gensalt())
        try:
            with get_db(self.db_name) as conn:
                conn.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", 
                               (validated.username, validated.email, hashed_pw.decode('utf-8'), role))
                conn.commit()
                logger.info(f"Account registered: '{validated.username}'")
                return True, "Registration successful! You may now log in."
        except Exception as e: 
            if "duplicate key" in str(e) or "IntegrityError" in str(e):
                return False, "Username or Email already taken."
            return False, f"System Error: {e}"

    def login_user(self, username, password):
        if not username or not password: return False, "Please enter both fields.", None, False, None
        try:
            with get_db(self.db_name) as conn:
                row = conn.execute("SELECT password_hash, is_locked, failed_attempts, role, email FROM users WHERE username = ?", (username,)).fetchone()
                if not row: return False, "Invalid credentials.", None, False, None
                db_hash, is_locked, attempts, role, email = row
                if is_locked == 1: return False, "Account is LOCKED.", None, True, email
                    
                if bcrypt.checkpw(password.encode('utf-8'), db_hash.encode('utf-8')):
                    conn.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,))
                    conn.commit()
                    return True, "Login successful!", role, False, email
                else:
                    attempts += 1
                    if attempts >= 3:
                        conn.execute("UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE username = ?", (attempts, username))
                        conn.commit()
                        return False, "Account locked due to 3 failed attempts.", None, True, email
                    else:
                        conn.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (attempts, username))
                        conn.commit()
                        return False, f"Invalid password. Attempts: {attempts}/3", None, False, email
        except Exception as e: return False, f"System Error: {e}", None, False, None

    def submit_password_reset_request(self, username, email, new_password):
        try: UserSchema(username=username, email=email, password=new_password)
        except ValidationError as e: return False, e.errors()[0]['msg']
        try:
            with get_db(self.db_name) as conn:
                if not conn.execute("SELECT 1 FROM users WHERE username = ? AND email = ?", (username, email)).fetchone():
                    return False, "Account details do not match."
                hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                conn.execute("INSERT INTO password_resets (username, email, desired_password) VALUES (?, ?, ?)", 
                               (username, email, hashed_pw.decode('utf-8')))
                conn.commit()
                return True, "Reset request submitted to Administrators."
        except Exception as e: return False, f"System Error: {e}"

    def change_password_direct(self, username, email, current_pw, new_pw):
        try:
            with get_db(self.db_name) as conn:
                row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
                if not row or not bcrypt.checkpw(current_pw.encode('utf-8'), row[0].encode('utf-8')):
                    return False, "Current password is incorrect."
                try: UserSchema(username=username, email=email, password=new_pw)
                except ValidationError as e: return False, e.errors()[0]['msg']
                new_hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
                conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hashed.decode('utf-8'), username))
                conn.commit()
                return True, "Password updated successfully."
        except Exception as e: return False, str(e)

    def get_pending_resets(self):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT id, username, email, status FROM password_resets WHERE status = 'PENDING'").fetchall()
        except Exception: return []

    def process_bulk_resets(self, request_ids, approve=True):
        count = 0
        try:
            with get_db(self.db_name) as conn:
                for rid in request_ids:
                    if approve:
                        res = conn.execute("SELECT desired_password, username FROM password_resets WHERE id = ?", (rid,)).fetchone()
                        if res:
                            conn.execute("UPDATE users SET password_hash = ?, is_locked = 0, failed_attempts = 0 WHERE username = ?", (res[0], res[1]))
                            conn.execute("UPDATE password_resets SET status = 'APPROVED' WHERE id = ?", (rid,))
                            count += 1
                    else:
                        conn.execute("UPDATE password_resets SET status = 'REJECTED' WHERE id = ?", (rid,))
                        count += 1
                conn.commit()
                return True, f"Processed {count} password reset requests."
        except Exception as e: return False, str(e)


class InventoryController:
    def __init__(self, db_name="hardware_inventory.db"):
        self.db_name = db_name

    def compute_status(self, avail_qty):
        if avail_qty > 5: return "Available"
        elif 1 <= avail_qty <= 5: return "Low Stock"
        else: return "Out of Stock"

    def get_categories(self):
        common_cats = ["Actuator", "Connectivity", "Display", "IC/Chip", "Microcontroller", "Passive", "Power", "Sensor", "Tools"]
        try:
            with get_db(self.db_name) as conn:
                data = conn.execute("SELECT DISTINCT category FROM hardware ORDER BY category").fetchall()
                db_cats = [row[0] for row in data]
                return ["ALL"] + sorted(list(set(common_cats + db_cats)))
        except Exception: return ["ALL"] + common_cats

    def get_all_items(self, search_text="", category="ALL"):
        try:
            with get_db(self.db_name) as conn:
                query = "SELECT * FROM hardware WHERE 1=1"
                params = []
                if category and category != "ALL":
                    query += " AND category = ?"
                    params.append(category)
                if search_text:
                    query += " AND (item_name LIKE ? OR category LIKE ?)"
                    params.extend([f"%{search_text}%", f"%{search_text}%"])
                return conn.execute(query, params).fetchall()
        except Exception: return []

    def get_total_valuation(self):
        try:
            with get_db(self.db_name) as conn:
                total = conn.execute("SELECT SUM(total_qty * unit_price) FROM hardware").fetchone()[0]
                return total if total else 0.0
        except Exception: return 0.0

    def add_item(self, name, category, qty_str, price_str):
        try: qty, price = int(qty_str), float(price_str)
        except ValueError: return False, "Quantity must be an integer and Price must be a number."
        if qty < 0 or price < 0: return False, "Quantity and Price cannot be negative."
        status = self.compute_status(qty)
        try:
            with get_db(self.db_name) as conn:
                if conn.execute("SELECT 1 FROM hardware WHERE LOWER(item_name) = LOWER(?)", (name,)).fetchone():
                    return False, "Component name already exists."
                conn.execute("INSERT INTO hardware (item_name, category, total_qty, available_qty, unit_price, status) VALUES (?, ?, ?, ?, ?, ?)", 
                             (name, category, qty, qty, price, status))
                conn.commit()
                return True, "Successfully registered to laboratory."
        except Exception as e: return False, str(e)

    def update_stock(self, item_id, qty_str, action):
        try: qty = int(qty_str)
        except ValueError: return False, "Quantity must be a valid number."
        if qty <= 0: return False, "Please enter a value greater than 0."

        try:
            with get_db(self.db_name) as conn:
                row = conn.execute("SELECT total_qty, available_qty FROM hardware WHERE item_id = ?", (item_id,)).fetchone()
                if not row: return False, "Item not found."
                
                total, avail = row[0], row[1]
                if action == "ADD":
                    new_tot, new_avail = total + qty, avail + qty
                elif action == "DEDUCT":
                    new_tot, new_avail = total - qty, avail - qty
                    if new_tot < 0 or new_avail < 0: 
                        return False, "Cannot deduct. Resulting stock would be less than 0."
                
                status = self.compute_status(new_avail)
                conn.execute("UPDATE hardware SET total_qty = ?, available_qty = ?, status = ? WHERE item_id = ?", 
                             (new_tot, new_avail, status, item_id))
                conn.commit()
                return True, f"Stock successfully {'added' if action == 'ADD' else 'deducted'}."
        except Exception as e: return False, f"System Error: {e}"

    def update_price(self, item_id, new_price_str):
        try: new_price = float(new_price_str)
        except ValueError: return False, "Invalid price format."
        if new_price < 0: return False, "Price cannot be negative."
        
        try:
            with get_db(self.db_name) as conn:
                conn.execute("UPDATE hardware SET unit_price = ? WHERE item_id = ?", (new_price, item_id))
                conn.commit()
                return True, "Price updated."
        except Exception as e: return False, f"System Error: {e}"

    def delete_bulk_items(self, item_ids):
        try:
            with get_db(self.db_name) as conn:
                for item_id in item_ids:
                    conn.execute("DELETE FROM hardware WHERE item_id = ?", (item_id,))
                conn.commit()
                return True, "Items deleted successfully."
        except Exception as e: return False, str(e)

    def borrow_item(self, username, item_id, qty):
        try:
            with get_db(self.db_name) as conn:
                row = conn.execute("SELECT item_name, available_qty, unit_price FROM hardware WHERE item_id = ?", (item_id,)).fetchone()
                if not row: return False, "Component not found."
                item_name, avail, price = row[0], row[1], row[2]
                if qty > avail: return False, f"Only {avail} units available."
                
                liability = qty * price
                date_now = datetime.now().strftime("%Y-%m-%d %H:%M")
                conn.execute("INSERT INTO borrow_logs (username, item_id, item_name, qty_borrowed, total_liability, borrow_date, status) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_BORROW')",
                             (username, item_id, item_name, qty, liability, date_now))
                conn.commit()
                return True, f"Borrow request for {qty}x {item_name} submitted to Admin."
        except Exception as e: return False, str(e)

    def process_bulk_borrows(self, loan_ids, approve=True):
        count = 0
        try:
            with get_db(self.db_name) as conn:
                for lid in loan_ids:
                    log = conn.execute("SELECT item_id, qty_borrowed FROM borrow_logs WHERE log_id = ? AND status = 'PENDING_BORROW'", (lid,)).fetchone()
                    if log:
                        item_id, qty = log[0], log[1]
                        if approve:
                            hw = conn.execute("SELECT available_qty FROM hardware WHERE item_id = ?", (item_id,)).fetchone()
                            if hw and hw[0] >= qty:
                                new_avail = hw[0] - qty
                                conn.execute("UPDATE hardware SET available_qty = ?, status = ? WHERE item_id = ?", (new_avail, self.compute_status(new_avail), item_id))
                                conn.execute("UPDATE borrow_logs SET status = 'BORROWED' WHERE log_id = ?", (lid,))
                                count += 1
                            else:
                                conn.execute("UPDATE borrow_logs SET status = 'REJECTED' WHERE log_id = ?", (lid,))
                        else:
                            conn.execute("UPDATE borrow_logs SET status = 'REJECTED' WHERE log_id = ?", (lid,))
                            count += 1
                conn.commit()
                return True, f"Processed {count} borrow requests."
        except Exception as e: return False, str(e)

    def request_bulk_item_returns(self, loan_ids):
        count = 0
        try:
            with get_db(self.db_name) as conn:
                for lid in loan_ids:
                    conn.execute("UPDATE borrow_logs SET status = 'RETURN_PENDING' WHERE log_id = ? AND status = 'BORROWED'", (lid,))
                    count += 1
                conn.commit()
                return True, f"Requested return for {count} items."
        except Exception as e: return False, str(e)

    def process_bulk_returns(self, loan_ids, approve=True):
        count = 0
        try:
            with get_db(self.db_name) as conn:
                for lid in loan_ids:
                    log = conn.execute("SELECT item_id, qty_borrowed FROM borrow_logs WHERE log_id = ? AND status = 'RETURN_PENDING'", (lid,)).fetchone()
                    if log:
                        item_id, qty = log[0], log[1]
                        if approve:
                            hw = conn.execute("SELECT available_qty FROM hardware WHERE item_id = ?", (item_id,)).fetchone()
                            if hw:
                                new_avail = hw[0] + qty
                                conn.execute("UPDATE hardware SET available_qty = ?, status = ? WHERE item_id = ?", (new_avail, self.compute_status(new_avail), item_id))
                                conn.execute("UPDATE borrow_logs SET status = 'RETURNED' WHERE log_id = ?", (lid,))
                                count += 1
                        else:
                            conn.execute("UPDATE borrow_logs SET status = 'BORROWED' WHERE log_id = ?", (lid,))
                            count += 1
                conn.commit()
                return True, f"Processed {count} return requests."
        except Exception as e: return False, str(e)

    def get_user_active_loans(self, username):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs WHERE username = ? AND status = 'BORROWED' ORDER BY log_id DESC", (username,)).fetchall()
        except Exception: return []

    def get_user_pending_borrows(self, username):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs WHERE username = ? AND status = 'PENDING_BORROW' ORDER BY log_id DESC", (username,)).fetchall()
        except Exception: return []

    def get_user_loan_history(self, username):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs WHERE username = ? ORDER BY log_id DESC", (username,)).fetchall()
        except Exception: return []

    def get_pending_borrows(self):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs WHERE status = 'PENDING_BORROW' ORDER BY log_id DESC").fetchall()
        except Exception: return []

    def get_pending_returns(self):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs WHERE status = 'RETURN_PENDING' ORDER BY log_id DESC").fetchall()
        except Exception: return []

    def get_all_loans_history(self):
        try:
            with get_db(self.db_name) as conn:
                return conn.execute("SELECT * FROM borrow_logs ORDER BY log_id DESC").fetchall()
        except Exception: return []

    def export_to_csv(self, username):
        try:
            with get_db(self.db_name) as conn:
                rows = conn.execute("SELECT * FROM hardware").fetchall()
                with open("inventory_report.csv", "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Item Name", "Category", "Total Qty", "Available Qty", "Unit Price", "Status"])
                    writer.writerows(rows)
                return True, "Successfully exported to inventory_report.csv"
        except Exception as e: return False, str(e)

if __name__ == "__main__":
    init_db()