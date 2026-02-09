from flask import request, session, redirect, render_template
from app import app, db, cursor
from db import get_db_connection




ADMIN_EMAIL = "admin@taxassist.com"
ADMIN_PASSWORD = "admin123"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # ✅ ADMIN LOGIN 
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['role'] = 'admin'
            session['email'] = email
            return redirect('/admin/dashboard')

        # ✅ USER LOGIN (psycopg2)
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT id, password FROM users WHERE email = %s",
            (email,)
        )
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user and user[1] == password:
            session['role'] = 'user'
            session['user_id'] = user[0]
            return redirect('/index')

        return "Invalid login credentials"

    return render_template('login.html')

#admin dashboard 
@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect('/login')
    return render_template('admin/dashboard.html')

#prevent admin access to user pages
@app.route('/index')
def index():
    if session.get('role') == 'admin':
        return redirect('/admin/dashboard')
    return render_template('index.html')

