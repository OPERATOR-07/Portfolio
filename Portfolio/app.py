from flask import Flask, render_template, redirect, url_for, request, flash
import requests
import sqlite3 as db
import argon2
import os
from datetime import datetime, date


app = Flask(__name__)
app.secret_key = "artemis-core-contact-form"

@app.route("/")
def home():
	return render_template("portfolio.html")

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
	
	def getTime():
		now = datetime.now()
		timestamp = now.strftime("%d/%m/%Y, %H:%M:%S")
		return timestamp
	
	with db.connect("emails.db") as conn:
		cursor = conn.cursor()
		cursor.execute(
			"insert into Emails (name, email, description, timestamp) values (?, ?, ?, ?)",
			(name, email, description, getTime())
		)
	
	messages =  flash("Message delivered, Thankyou!!", "success")

	return render_template("portfolio.html", messages = messages)
	

if __name__ == "__main__":
	app.run(host = '0.0.0.0', port = int(os.environ.get("PORT", 5000)))
