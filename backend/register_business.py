import psycopg2
import os
from dotenv import load_dotenv
from flask import Flask, app, render_template, request, redirect
from app import app

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

@app.route("/register-business", methods=["GET", "POST"])
def register_business():
    if request.method == "POST":
        cur.execute("""
            INSERT INTO business_registrations
            (business_name, business_type, services, owner_name, email, phone, city)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            request.form["business_name"],
            request.form["business_type"],
            ", ".join(request.form.getlist("services")),
            request.form["owner_name"],
            request.form["email"],
            request.form["phone"],
            request.form["city"]
        ))

        conn.commit()
        return redirect("/business-success")

    return render_template("register_business.html")

@app.route("/admin/businesses")
def admin_businesses():
    cur.execute("""
        SELECT id, business_name, business_type, services,
               owner_name, email, phone, city, status
        FROM business_registrations
        ORDER BY created_at DESC
    """)
    businesses = cur.fetchall()
    return render_template("admin_businesses.html", businesses=businesses)

@app.route("/admin/update-status", methods=["POST"])
def update_status():
    business_id = request.form["id"]
    status = request.form["status"]

    cur.execute("""
        UPDATE business_registrations
        SET status = %s
        WHERE id = %s
    """, (status, business_id))

    conn.commit()
    return redirect("/admin/businesses")



