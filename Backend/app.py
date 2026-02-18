
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, redirect, session, url_for,jsonify
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
load_dotenv()
import json
import psycopg2

def get_db():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn, conn.cursor()

app = Flask(__name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static")

from admin import admin_bp

app.register_blueprint(admin_bp)



from Backend.otp import otp_bp
app.register_blueprint(otp_bp)

app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY not set in environment")

DATABASE_URL = os.getenv("DATABASE_URL")

oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWLEDGE_PATH = os.path.join(BASE_DIR, "company_knowledge.json")

with open(KNOWLEDGE_PATH) as f:
    knowledge = json.load(f)

def get_bot_reply(message):
    msg = message.lower()

    # ==============================
    # 💰 ITR COST
    # ==============================
    if "itr" in msg and any(k in msg for k in ["cost", "price", "fees"]):
        return {
            "reply": (
                "💰 ITR Filing Cost: ₹1000\n\n"
                "Final price may vary depending on income type and complexity."
            ),
            "suggestions": ["Documents Required for ITR", "ITR Filing Process", "Talk to Expert"]
        }

    # ==============================
    # 💰 GST COST
    # ==============================
    if "gst" in msg and any(k in msg for k in ["cost", "price", "fees"]):
        return {
            "reply": (
                "💰 GST Service Cost: ₹2000\n\n"
                "Final price may vary based on business type and turnover."
            ),
            "suggestions": ["Documents Required for GST", "GST Registration Process", "Talk to Expert"]
        }

    # ==============================
    # 📄 ITR DOCUMENTS
    # ==============================
    if (
        "itr" in msg
        and any(k in msg for k in ["document", "documents", "doc", "proof", "required"])
    ) or (
        "income tax" in msg
        and any(k in msg for k in ["document", "documents", "doc", "proof"])
    ):
        return {
            "reply": (
                "📄 Documents Required for ITR:\n"
                "• PAN Card\n"
                "• Aadhaar Card\n"
                "• Form 16 (for salaried)\n"
                "• Bank Statements\n"
                "• Investment Proofs (80C, 80D etc.)\n"
                "• Capital Gains details (if applicable)"
            ),
            "suggestions": ["ITR Cost", "ITR Filing Process", "Talk to Expert"]
        }

    # ==============================
    # 📄 GST DOCUMENTS
    # ==============================
    if (
        "gst" in msg
        and any(k in msg for k in ["document", "documents", "doc", "proof", "required"])
    ):
        return {
            "reply": (
                "📄 Documents Required for GST Registration:\n"
                "• PAN Card of Business/Owner\n"
                "• Aadhaar Card\n"
                "• Business Address Proof\n"
                "• Bank Account Details\n"
                "• Business Registration Certificate (if applicable)"
            ),
            "suggestions": ["GST Cost", "GST Registration Process", "Talk to Expert"]
        }
        # ==============================
    # 📄 ITR FILING PROCESS
    # ==============================
    if "itr filing process" in msg or "itr process" in msg:
        return {
            "reply": (
                "📝 ITR Filing Process:\n"
                "1️⃣ Share your documents\n"
                "2️⃣ Expert review & tax calculation\n"
                "3️⃣ Return preparation\n"
                "4️⃣ Filing confirmation\n"
                "5️⃣ Acknowledgement shared via email"
            ),
            "suggestions": ["ITR Cost", "Documents Required for ITR", "Talk to Expert"]
        }

    # ==============================
    # 🧾 GST FILING PROCESS
    # ==============================
    if "gst filing process" in msg or "gst process" in msg:
        return {
            "reply": (
                "📊 GST Filing Process:\n"
                "1️⃣ Share sales & purchase data\n"
                "2️⃣ GST liability calculation\n"
                "3️⃣ Return preparation (GSTR-1 / GSTR-3B)\n"
                "4️⃣ Filing on GST portal\n"
                "5️⃣ Filing confirmation shared"
            ),
            "suggestions": ["GST Cost", "Documents Required for GST", "Talk to Expert"]
        }

    # ==============================
    # 🧾 ITR GENERAL INFO
    # ==============================
    if any(k in msg for k in ["itr", "income tax", "file tax"]):
        return {
            "reply": (
                "We provide end-to-end Income Tax Return filing with expert review and fast processing."
            ),
            "suggestions": ["ITR Cost", "Documents Required for ITR", "Filing Process"]
        }

    # ==============================
    # 🏢 GST GENERAL INFO
    # ==============================
    if "gst" in msg:
        return {
            "reply": (
                "We assist with GST Registration, GST Filing, and compliance support for businesses."
            ),
            "suggestions": ["GST Cost", "Documents Required for GST", "GST Registration Process"]
        }

    # ==============================
    # 🕒 WORKING HOURS
    # ==============================
    if any(k in msg for k in ["working hours", "timing", "open", "support hours"]):
        return {
            "reply": (
                "🕒 Our Working Hours:\n"
                "We are available from 9:00 AM to 9:00 PM (Monday to Saturday).\n\n"
                "For urgent queries, you can request a callback."
            ),
            "suggestions": ["Contact", "Talk to Expert"]
        }
        # ==============================
    # 👨‍💼 TALK TO EXPERT
    # ==============================
    if any(k in msg for k in ["talk to expert", "expert", "human", "agent"]):
        return {
            "reply": (
                "👨‍💼 Our Tax Expert is available to assist you.\n\n"
                "📞 Call us directly: +91 916300998547\n\n"
                "💬 Or click the WhatsApp button on the website to start instant chat.\n\n"
                "We are available from 9 AM to 9 PM."
            ),
            "suggestions": ["Call Now", "WhatsApp Chat", "Working Hours"]
        }

    # ==============================
    # 📞 CONTACT
    # ==============================
    if any(k in msg for k in ["contact", "phone", "email", "support"]):
        return {
            "reply": (
                "📞 Contact Details:\n\n"
                "Phone: +91 916300998547\n"
                "Working Hours: 9 AM - 9 PM\n\n"
                "For instant response, use our WhatsApp chat button."
            ),
            "suggestions": ["Talk to Expert", "Working Hours"]
        }

    # ==============================
    # 💰 GENERAL PRICING
    # ==============================
    if any(k in msg for k in ["pricing", "price", "cost", "fees"]):
        return {
            "reply": (
                "💰 Our Pricing Overview:\n"
                "• ITR Filing – ₹1000\n"
                "• GST Services – ₹2000\n\n"
                "Final cost depends on your specific case."
            ),
            "suggestions": ["ITR", "GST", "Talk to Expert"]
        }
    # ==============================
    # 💬 WHATSAPP CHAT
    # ==============================
    if "whatsapp" in msg:
        return {
            "reply": (
                "💬 Click the WhatsApp button on the bottom right corner "
                "to start instant chat with our tax expert.\n\n"
                "Or use this direct link:\n"
                "https://wa.me/91916300998547"
            ),
            "suggestions": ["Talk to Expert", "Contact"]
        }
    # ==============================
    # 📞 CALL NOW
    # ==============================
    if "call" in msg:
        return {
            "reply": (
                "📞 You can call our Tax Expert directly at:\n\n"
                "+91 916300998547\n\n"
                "Available from 9 AM to 9 PM."
            ),
            "suggestions": ["WhatsApp Chat", "Working Hours"]
        }
    
    # ==============================
    # 🕒 WORKING HOURS
    # ==============================
    if "working hours" in msg or "hours" in msg:
        return {
            "reply": "🕒 Our working hours are 9 AM to 9 PM (All days).",
            "suggestions": ["Talk to Expert", "Contact"]
        }

    # ==============================
    # 🤖 FALLBACK
    # ==============================
    return {
        "reply": (
            "Hi 👋 I can help you with:\n\n"
            "• ITR Filing\n"
            "• GST Services\n"
            "• Pricing Details\n"
            "• Working Hours\n"
            "• Contact Support\n\n"
            "Please choose an option below."
        ),
        "suggestions": ["ITR", "GST", "Pricing", "Contact"]
    }


@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message", "")
    response = get_bot_reply(user_message)
    return jsonify(response)


@app.route("/google-login")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/google/callback")
def google_callback():
    token = google.authorize_access_token(leeway=10)
    user = google.get(
        "https://www.googleapis.com/oauth2/v2/userinfo"
    ).json()
    session.clear()
    session["role"] = "user"
    session["user"] = {
        "email": user["email"],
        "name": user["name"],
        "picture": user["picture"]
    }

    next_page = session.pop("next", None)
    return redirect(next_page or "/dashboard")


@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return "Email and password required", 400

        hashed_password = generate_password_hash(password)

        conn, cursor = get_db()

        try:
            cursor.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_password)
            )
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            cursor.close()
            conn.close()
            return "Email already registered", 409
        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()
            raise e

        cursor.close()
        conn.close()

        session["user"] = {
            "email": email,
            "name": email.split("@")[0]
        }

        next_page = session.pop("next", None)
        return redirect(next_page or "/dashboard")

    return render_template("auth.html", mode="signup")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # 🔐 ADMIN LOGIN (ONLY THIS EMAIL + PASSWORD)
        if email == "admin@taxassist.com" and password == "admin123":
            session.clear()
            session["role"] = "admin"
            session["admin_logged_in"] = True
            session["email"] = email
            return redirect("/admin/dashboard")

        # 👤 CUSTOMER LOGIN
        conn, cursor = get_db()
        cursor.execute(
            "SELECT id, password FROM users WHERE email=%s",
            (email,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session.clear()
            session["role"] = "user"
            session["user"] = {
                "id": user[0],
                "email": email,
                "name": email.split("@")[0]
            }
            return redirect("/dashboard")

        return "Invalid login credentials", 401

    return render_template("auth.html", mode="login")


    return render_template("auth.html", mode="login")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        return redirect("/login")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        new_password = request.form["password"]

        print("Resetting password with token:", token)

        return redirect("/login")

    return render_template("reset_password.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("user") and not session.get("admin_logged_in"):
        return redirect("/login")
    return render_template("home.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/belated-itr")
def belated_itr():
    return render_template("belated_itrfiling.html")

@app.route("/tax-planning")
def tax_planning_services():
    return render_template("tax_planning_services.html")

@app.route("/chatbot")
def chatbot():
    return render_template("chatbot.html")

@app.route("/buy-now")
def buy_now():
    session["next"] = request.referrer or "/payment"

    if "user" in session:
        return redirect(url_for("payment"))

    return redirect(url_for("login"))

@app.route("/payment")
def payment():
    if "user" not in session:
        session["next"] = request.referrer or "/"
        return redirect(url_for("login"))

    return render_template("payment.html")


@app.route("/pay", methods=["POST"])
def pay():
    if "user" not in session:
        session["next"] = "/payment"
        return redirect(url_for("login"))

    # fake order for now
    session["last_order"] = {
        "service": "Belated ITR Filing",
        "amount": "₹999"
    }

    return redirect(url_for("payment_success"))

@app.route("/payment-success")
def payment_success():
    if "last_order" not in session:
        return redirect(url_for("home"))

    return render_template(
        "payment_success.html",
        order=session["last_order"]
    )

@app.route("/request-callback", methods=["POST"])
def request_callback():
    phone = request.form.get("phone")
    email = request.form.get("email")

    if not phone and not email:
        return redirect(request.referrer)

    conn, cursor = get_db()

    cursor.execute("""
        INSERT INTO callback_requests (phone, email)
        VALUES (%s, %s)
    """, (phone, email))

    conn.commit()
    cursor.close()
    conn.close()

    print("📞 NEW CALLBACK REQUEST:", phone, email)
    return redirect(request.referrer)


from psycopg2.errors import UniqueViolation

@app.route("/register-business", methods=["GET", "POST"])
def register_business():
    if request.method == "POST":
        conn, cursor = get_db()

        try:
            cursor.execute("""
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

        except UniqueViolation:
            conn.rollback()
            return "❌ Business already registered", 409

        finally:
            cursor.close()
            conn.close()

        return redirect("/business-success")

    return render_template("register_business.html")

@app.route("/admin/update-status", methods=["POST"])
def update_business_status():
    if not session.get("admin_logged_in"):
        return redirect("/login")

    business_id = request.form["id"]
    status = request.form["status"]

    conn, cur = get_db()

    cur.execute("""
        UPDATE business_registrations
        SET status = %s
        WHERE id = %s
    """, (status, business_id))

    conn.commit()
    cur.close()
    conn.close()

    return redirect("/admin/business")

@app.route("/business-success")
def business_success():
    return render_template("business_success.html")


@app.context_processor
def inject_whatsapp():
    return {
        "WHATSAPP_NUMBER": os.getenv("WHATSAPP_NUMBER"),
        "WHATSAPP_TEXT": os.getenv("WHATSAPP_TEXT")
    }

@app.route("/budget-2026")
def budget_2026():
    return render_template("budget_2026.html")

#admin dashboard

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect("/login")

    conn, cursor = get_db()

    try:
        # Total counts
        cursor.execute("SELECT COUNT(*) FROM callback_requests")
        callback_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM business_registrations")
        business_count = cursor.fetchone()[0]

        # New callbacks (pending)
        cursor.execute("SELECT COUNT(*) FROM callback_requests WHERE status='pending'")
        new_callbacks = cursor.fetchone()[0]

        # New businesses
        cursor.execute("SELECT COUNT(*) FROM business_registrations WHERE status='NEW'")
        new_businesses = cursor.fetchone()[0]

        return render_template(
            "admin_dashboard.html",
            callback_count=callback_count,
            business_count=business_count,
            new_callbacks=new_callbacks,
            new_businesses=new_businesses
        )
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    app.run(debug=True, port=5003)
