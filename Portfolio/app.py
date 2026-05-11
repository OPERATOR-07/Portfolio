from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from flask import Flask, render_template, redirect, url_for, request, flash, abort, jsonify, session
import sqlite3 as db
import os
from datetime import datetime
from pathlib import Path


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "emails.db"
password_hasher = PasswordHasher()


def get_timestamp():
	now = datetime.now()
	return now.strftime("%d/%m/%Y, %H:%M:%S")


def open_db():
	conn = db.connect(DATABASE)
	conn.row_factory = db.Row
	return conn


def json_data():
	if not request.is_json:
		abort(403)
	return request.get_json() or {}


def is_admin_logged_in():
	return session.get("admin_logged_in") is True


def login_required_page(view):
	@wraps(view)
	def wrapped_view(*args, **kwargs):
		if not is_admin_logged_in():
			return redirect(url_for("admin_login"))
		return view(*args, **kwargs)
	return wrapped_view


def login_required_api(view):
	@wraps(view)
	def wrapped_view(*args, **kwargs):
		if not is_admin_logged_in():
			return jsonify({"error": "Authentication required."}), 401
		return view(*args, **kwargs)
	return wrapped_view


def verify_admin_password(password_hash, password):
	try:
		return password_hasher.verify(password_hash, password)
	except (InvalidHash, VerificationError, VerifyMismatchError):
		return False


def email_payload(row):
	return {
		"id": row["id"],
		"name": row["name"],
		"email": row["email"],
		"description": row["description"] or "",
		"timestamp": row["timestamp"],
	}


def admin_payload(row):
	return {
		"id": row["id"],
		"username": row["username"],
		"email": row["email"],
		"password": "",
	}


@app.post("/fetch-admin")
@login_required_api
def fetchadmin():
	req = json_data()
	
	if not req.get("message") or req.get("message") != 'get-admin':
		return abort(403)
	
	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute("select id, username, email, password from Admin order by id")
		admins = cursor.fetchall()

	return jsonify([admin_payload(admin) for admin in admins])


@app.post("/fetch-user")
@login_required_api
def User():
	req = json_data()
	
	if not req.get("message") or req.get("message") != 'get-users':
		return abort(403)
	
	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute("select id, name, email, description, timestamp from Emails order by id")
		users = cursor.fetchall()

	return jsonify([email_payload(user) for user in users])


@app.post("/emails")
@login_required_api
def create_email():
	req = json_data()
	name = (req.get("name") or "").strip()
	email = (req.get("email") or "").strip()
	description = (req.get("description") or "").strip()

	if not name or not email:
		return jsonify({"error": "Name and email are required."}), 400

	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"insert into Emails (name, email, description, timestamp) values (?, ?, ?, ?)",
			(name, email, description, get_timestamp())
		)
		conn.commit()
		cursor.execute(
			"select id, name, email, description, timestamp from Emails where id = ?",
			(cursor.lastrowid,)
		)
		email_record = cursor.fetchone()

	return jsonify(email_payload(email_record)), 201


@app.put("/emails/<int:email_id>")
@login_required_api
def update_email(email_id):
	req = json_data()
	name = (req.get("name") or "").strip()
	email = (req.get("email") or "").strip()
	description = (req.get("description") or "").strip()

	if not name or not email:
		return jsonify({"error": "Name and email are required."}), 400

	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"update Emails set name = ?, email = ?, description = ? where id = ?",
			(name, email, description, email_id)
		)
		if cursor.rowcount == 0:
			return jsonify({"error": "Email record not found."}), 404
		conn.commit()
		cursor.execute(
			"select id, name, email, description, timestamp from Emails where id = ?",
			(email_id,)
		)
		email_record = cursor.fetchone()

	return jsonify(email_payload(email_record))


@app.delete("/emails/<int:email_id>")
@login_required_api
def delete_email(email_id):
	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute("delete from Emails where id = ?", (email_id,))
		if cursor.rowcount == 0:
			return jsonify({"error": "Email record not found."}), 404
		conn.commit()

	return jsonify({"deleted": True, "id": email_id})


@app.post("/admins")
@login_required_api
def create_admin():
	req = json_data()
	username = (req.get("username") or "").strip()
	email = (req.get("email") or "").strip()
	password = (req.get("password") or "").strip()

	if not username or not email or not password:
		return jsonify({"error": "Username, email, and password are required."}), 400

	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"insert into Admin (username, email, password) values (?, ?, ?)",
			(username, email, password_hasher.hash(password))
		)
		conn.commit()
		cursor.execute(
			"select id, username, email, password from Admin where id = ?",
			(cursor.lastrowid,)
		)
		admin = cursor.fetchone()

	return jsonify(admin_payload(admin)), 201


@app.put("/admins/<int:admin_id>")
@login_required_api
def update_admin(admin_id):
	req = json_data()
	username = (req.get("username") or "").strip()
	email = (req.get("email") or "").strip()
	password = (req.get("password") or "").strip()

	if not username or not email:
		return jsonify({"error": "Username and email are required."}), 400

	with open_db() as conn:
		cursor = conn.cursor()
		if password:
			cursor.execute(
				"update Admin set username = ?, email = ?, password = ? where id = ?",
				(username, email, password_hasher.hash(password), admin_id)
			)
		else:
			cursor.execute(
				"update Admin set username = ?, email = ? where id = ?",
				(username, email, admin_id)
			)
		if cursor.rowcount == 0:
			return jsonify({"error": "Admin account not found."}), 404
		conn.commit()
		cursor.execute(
			"select id, username, email, password from Admin where id = ?",
			(admin_id,)
		)
		admin = cursor.fetchone()

	return jsonify(admin_payload(admin))


@app.delete("/admins/<int:admin_id>")
@login_required_api
def delete_admin(admin_id):
	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute("delete from Admin where id = ?", (admin_id,))
		if cursor.rowcount == 0:
			return jsonify({"error": "Admin account not found."}), 404
		conn.commit()

	return jsonify({"deleted": True, "id": admin_id})


@app.route("/")
def home():
	return render_template("portfolio.html")

@app.route("/operator/login", methods=["GET", "POST"])
def admin_login():
	if request.method == "GET":
		if is_admin_logged_in():
			return redirect(url_for("admin"))
		return render_template("login.html")

	username_or_email = (request.form.get("username") or "").strip()
	password = request.form.get("password") or ""

	if not username_or_email or not password:
		flash("Username and password are required.", "error")
		return render_template("login.html"), 400

	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"select id, username, email, password from Admin where username = ? or email = ?",
			(username_or_email, username_or_email)
		)
		admin_record = cursor.fetchone()

	if not admin_record or not verify_admin_password(admin_record["password"], password):
		flash("Invalid username or password.", "error")
		return render_template("login.html"), 401

	session.clear()
	session["admin_logged_in"] = True
	session["admin_id"] = admin_record["id"]
	session["admin_username"] = admin_record["username"]
	return redirect(url_for("admin"))


@app.post("/operator/logout")
def admin_logout():
	session.clear()
	return redirect(url_for("admin_login"))


@app.route("/operator")
@login_required_page
def admin():
	return render_template("admin.html")

@app.route("/portfolio.html")
def redirect_home():
	return redirect(url_for("home"))

@app.route("/services/automation-solutions")
def service1():
	return render_template("/services/automation-solutions.html")

@app.route("/services/internal-management-systems")
def service2():
	return render_template("/services/internal-management-systems.html")

@app.route("/services/business-websites")
def service3():
	return render_template("/services/business-websites.html")

@app.route("/services/custom-web-applications")
def service4():
	return render_template("/services/custom-web-applications.html")

@app.post("/contact")
def contact():
	name = request.form["name"]
	if not name or name == '' or name == None:
		return redirect(url_for("home"))

	email = request.form["email"]
	if not email or email == '' or email == None:
		return redirect(url_for("home"))
	
	description = request.form["description"]
	if not description or description == '' or description == None:
		return redirect(url_for("home"))
	
	with open_db() as conn:
		cursor = conn.cursor()
		cursor.execute(
			"insert into Emails (name, email, description, timestamp) values (?, ?, ?, ?)",
			(name, email, description, get_timestamp())
		)
	
	messages =  flash("Message delivered, Thankyou!!", "success")

	return render_template("portfolio.html", messages = messages)
	


if __name__ == "__main__":
	app.run(host = '0.0.0.0', port = os.environ.get("PORT", 5000))
