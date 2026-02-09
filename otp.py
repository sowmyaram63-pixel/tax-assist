from app import app
from flask import session, redirect, render_template, request
import requests
import random
import os
import time


def send_sms_otp(phone, otp):
    url = "https://www.fast2sms.com/dev/bulkV2"

    payload = {
        "route": "otp",
        "variables_values": otp,
        "numbers": phone
    }

    headers = {
        "authorization": os.getenv("FAST2SMS_API_KEY"),
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

@app.route('/send-otp')
def send_otp():
    if not session.get('admin_temp'):
        return redirect('/admin-login')

    otp = random.randint(100000, 999999)

    session['admin_otp'] = otp
    session['otp_time'] = time.time()  # for expiry

    phone = "9703232849"  # admin phone number

    send_sms_otp(phone, otp)

    # DEV ONLY (remove in production)
    print("ADMIN OTP:", otp)

    return redirect('/verify-otp')
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']

        if 'admin_otp' not in session:
            return redirect('/admin-login')

        # OTP expiry (5 minutes)
        if time.time() - session['otp_time'] > 300:
            session.pop('admin_otp', None)
            return "OTP Expired"

        if int(user_otp) == session['admin_otp']:
            session.pop('admin_otp')
            session.pop('otp_time')
            session.pop('admin_temp')

            session['admin_logged_in'] = True
            return redirect('/admin-dashboard')

        return "Invalid OTP"

    return render_template('verify_otp.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect('/admin-login')

    return render_template('admin_dashboard.html')


