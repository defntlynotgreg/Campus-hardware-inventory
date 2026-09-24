from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from functools import wraps
import os
from Laboratorysystem import init_db, AuthController, InventoryController

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab1-development-secret-change-me")

auth_ctrl = AuthController()
inv_ctrl = InventoryController()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "ADMIN":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html")
            
        ok, msg, role, is_locked, email = auth_ctrl.login_user(username, password)
        if ok:
            session.clear()
            session["username"] = username
            session["role"] = role
            session["email"] = email
            flash(msg, "success")
            return redirect(url_for("dashboard"))
            
        flash(msg, "danger")
        return render_template("login.html", locked=is_locked, locked_username=username)
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
        
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "USER").strip().upper()
    
    if role not in ("USER", "ADMIN"): role = "USER"
    if not username or not email or not password:
        flash("All registration fields are required.", "danger")
        return redirect(url_for("login"))
        
    ok, msg = auth_ctrl.register_user(username, email, password, role=role)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("login"))

@app.route("/reset-request", methods=["GET", "POST"])
def reset_request():
    if request.method == "GET":
        return render_template("reset.html")
        
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    
    if not username or not email or not new_password or not confirm_password:
        flash("All reset fields are required.", "danger")
        return redirect(url_for("login"))
        
    if new_password != confirm_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("login"))
        
    ok, msg = auth_ctrl.submit_password_reset_request(username, email, new_password)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "ALL")
    if not category: category = "ALL"
    
    items = inv_ctrl.get_all_items(search_text=search, category=category)
    categories = inv_ctrl.get_categories()
    
    all_items_for_total = inv_ctrl.get_all_items(search_text="", category="ALL")
    total_stocks = sum(item[3] for item in all_items_for_total)
    
    active_loans, history, pending_returns = [], [], []
    pending_borrows, pending_borrow_requests, all_loans, pending_resets = [], [], [], []
    audit_logs = []
    
    if session["role"] == "USER":
        active_loans = inv_ctrl.get_user_active_loans(session["username"])
        pending_borrow_requests = inv_ctrl.get_user_pending_borrows(session["username"])
        history = inv_ctrl.get_user_loan_history(session["username"])
    else:
        pending_returns = inv_ctrl.get_pending_returns()
        pending_borrows = inv_ctrl.get_pending_borrows()
        all_loans = inv_ctrl.get_all_loans_history()
        pending_resets = auth_ctrl.get_pending_resets()
        audit_logs = inv_ctrl.get_admin_audit_logs()
        
    return render_template(
        "dashboard.html", items=items, categories=categories, search=search,
        selected_category=category, total_stocks=total_stocks, active_loans=active_loans,
        history=history, pending_returns=pending_returns, pending_borrows=pending_borrows,
        pending_borrow_requests=pending_borrow_requests, all_loans=all_loans, 
        pending_resets=pending_resets, audit_logs=audit_logs
    )

@app.route("/borrow", methods=["POST"])
@login_required
def borrow():
    try:
        item_id = int(request.form["item_id"])
        quantity = int(request.form.get("quantity", "1"))
    except (KeyError, ValueError):
        flash("Invalid item or borrow quantity.", "danger")
        return redirect(url_for("dashboard"))
        
    if quantity < 1:
        flash("Borrow quantity must be at least 1.", "danger")
        return redirect(url_for("dashboard"))
        
    if session["role"] != "USER":
        flash("Only USER accounts can borrow equipment.", "danger")
        return redirect(url_for("dashboard"))
        
    ok, msg = inv_ctrl.borrow_item(session["username"], item_id, quantity)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/return-request", methods=["POST"])
@login_required
def return_request():
    raw_ids = request.form.getlist("loan_ids")
    loan_ids = [int(x) for x in raw_ids if x.isdigit()]
    
    if session["role"] != "USER":
        flash("Only USER accounts can request returns.", "danger")
        return redirect(url_for("dashboard"))
        
    ok, msg = inv_ctrl.request_bulk_item_returns(loan_ids)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("dashboard"))

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    
    if not old_password or not new_password:
        flash("Both current and new passwords are required.", "danger")
        return redirect(url_for("dashboard"))
        
    ok, msg = auth_ctrl.change_password_direct(session["username"], session.get("email", ""), old_password, new_password)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/add", methods=["POST"])
@admin_required
def admin_add():
    try:
        name = request.form.get("item_name", "").strip()
        category = request.form.get("category", "").strip()
        quantity = request.form.get("quantity", "")
        unit_price = request.form.get("unit_price", "")
    except ValueError:
        flash("Quantity must be an integer and unit price must be numeric.", "danger")
        return redirect(url_for("dashboard"))
        
    ok, msg = inv_ctrl.add_item(name, category, quantity, unit_price)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/update", methods=["POST"])
@admin_required
def admin_update():
    item_id = request.form.get("item_id", "").strip()
    action = request.form.get("action")
    
    if not item_id.isdigit():
        flash("Invalid Target Item ID.", "danger")
        return redirect(url_for("dashboard"))
        
    if action in ["ADD", "DEDUCT"]:
        qty = request.form.get("qty", "").strip()
        ok, msg = inv_ctrl.update_stock(int(item_id), qty, action)
    elif action == "PRICE":
        price = request.form.get("price", "").strip()
        ok, msg = inv_ctrl.update_price(int(item_id), price)
    else:
        ok, msg = False, "Invalid management action."
        
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/delete", methods=["POST"])
@admin_required
def admin_delete():
    raw_ids = request.form.getlist("item_ids")
    item_ids = [int(x) for x in raw_ids if x.isdigit()]
    ok, msg = inv_ctrl.delete_bulk_items(item_ids)
    flash(msg, "success" if ok else "warning")
    return redirect(url_for("dashboard"))

@app.route("/admin/borrow-action", methods=["POST"])
@admin_required
def admin_borrow_action():
    raw_ids = request.form.getlist("loan_ids")
    approve = (request.form.get("action") == "approve")
    loan_ids = [int(x) for x in raw_ids if x.isdigit()]
    
    ok, msg = inv_ctrl.process_bulk_borrows(session["username"], loan_ids, approve=approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/return-action", methods=["POST"])
@admin_required
def admin_return_action():
    raw_ids = request.form.getlist("loan_ids")
    approve = (request.form.get("action") == "approve")
    loan_ids = [int(x) for x in raw_ids if x.isdigit()]
    
    ok, msg = inv_ctrl.process_bulk_returns(session["username"], loan_ids, approve=approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin/reset-action", methods=["POST"])
@admin_required
def admin_reset_action():
    raw_ids = request.form.getlist("request_ids")
    approve = (request.form.get("action") == "approve")
    request_ids = [int(x) for x in raw_ids if x.isdigit()]
    
    ok, msg = auth_ctrl.process_bulk_resets(session["username"], request_ids, approve=approve)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("dashboard"))

@app.route("/export")
@login_required
def export():
    ok, msg = inv_ctrl.export_to_csv(session["username"])
    if not ok:
        flash(msg, "danger")
        return redirect(url_for("dashboard"))
        
    path = os.path.abspath("inventory_report.csv")
    if not os.path.exists(path):
        flash("The CSV report could not be found.", "danger")
        return redirect(url_for("dashboard"))
        
    return send_file(path, as_attachment=True, download_name="inventory_report.csv")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    print("\n==========================================================")
    print(" CAMPUS HARDWARE INVENTORY - WEB PORTAL")
    print("==========================================================")
    print(" Open Google Chrome and go to:")
    print(" http://127.0.0.1:5000")
    print("\n Press CTRL+C to stop the server.")
    print("==========================================================\n")
    app.run(debug=True)