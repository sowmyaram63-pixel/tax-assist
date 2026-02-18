
from flask import Blueprint, session, redirect, render_template, request
from functools import wraps
from db import get_db_connection

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


@admin_bp.route("/callbacks")
@admin_required
def admin_callbacks():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, phone, email, created_at, status
        FROM callback_requests
        ORDER BY created_at DESC
    """)
    callbacks = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("admin_callbacks.html", callbacks=callbacks)


@admin_bp.route("/callbacks/update/<int:id>", methods=["POST"])
@admin_required
def update_callback_status(id):
    status = request.form.get("status")

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE callback_requests
        SET status = %s
        WHERE id = %s
    """, (status, id))

    conn.commit()
    cur.close()
    conn.close()

    return redirect("/admin/callbacks")


@admin_bp.route("/logout")
def admin_logout():
    session.clear()
    return redirect("/")

@admin_bp.route("/registrations")
@admin_required
def admin_registrations():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, email, created_at
        FROM users
        ORDER BY created_at DESC
    """)

    users = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("business_registrations.html", users=users)

@admin_bp.route("/businesses")
@admin_required
def admin_business():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            id,
            business_name,
            business_type,
            services,
            owner_name,
            email,
            phone,
            city,
            status
        FROM business_registrations
        ORDER BY id DESC
    """)

    businesses = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("admin_businesses.html", businesses=businesses)





