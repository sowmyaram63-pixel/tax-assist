
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, request, redirect, session, url_for,jsonify
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import json
import psycopg2

load_dotenv()

def get_db():
    conn = psycopg2.connect(os.getenv("DATABASE_URL"))
    return conn, conn.cursor()

app = Flask(__name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static")

app.secret_key = os.getenv("FLASK_SECRET_KEY")
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

    # ABOUT COMPANY
    if any(k in msg for k in ["company", "about", "who are you"]):
        return {
            "reply": knowledge["company"]["about"],
            "suggestions": ["Services", "ITR", "GST", "Contact"]
        }

    # SERVICES OVERVIEW
    if any(k in msg for k in ["services", "offer", "what do you do", "help"]):
        return {
            "reply": (
                "Here are the services we offer:\n"
                "• Income Tax Return (ITR) Filing\n"
                "• GST Registration & Filing\n"
                "• Tax Planning Assistance"
            ),
            "suggestions": ["ITR", "GST", "Pricing"]
        }

    # ITR
    if any(k in msg for k in ["itr", "income tax", "file tax"]):
        return {
            "reply": knowledge["services"]["itr"],
            "suggestions": ["ITR Cost", "Documents Required", "Filing Process"]
        }

    # GST
    if "gst" in msg:
        return {
            "reply": knowledge["services"]["gst"],
            "suggestions": ["GST Cost", "GST Registration", "GST Returns"]
        }

    # PROCESS
    if any(k in msg for k in ["process", "how it works", "steps"]):
        return {
            "reply": knowledge["process"]["tax_filing"],
            "suggestions": ["ITR", "GST", "Pricing"]
        }

    # PRICING
    if any(k in msg for k in ["cost", "price", "pricing", "fees"]):
        return {
            "reply": (
                "Our pricing:\n"
                "• ITR Filing – from ₹999\n"
                "• GST Filing – from ₹1,499\n"
                "Final cost depends on your case."
            ),
            "suggestions": ["ITR", "GST", "Contact"]
        }

    # PRIVACY
    if any(k in msg for k in ["privacy", "data", "safe"]):
        return {
            "reply": knowledge["policies"]["privacy"],
            "suggestions": ["Security", "Contact"]
        }

    # SECURITY
    if any(k in msg for k in ["secure", "security", "encrypted"]):
        return {
            "reply": knowledge["policies"]["security"],
            "suggestions": ["Privacy Policy", "Contact"]
        }

    # CONTACT
    if any(k in msg for k in ["contact", "email", "phone", "support"]):
        c = knowledge["contact"]
        return {
            "reply": f"You can reach us at {c['email']} or {c['phone']} ({c['hours']}).",
            "suggestions": ["Working Hours", "Talk to Expert"]
        }

    # FALLBACK (SMART, NOT DUMB)
    return {
        "reply": (
            "I can help you with:\n"
            "• ITR filing\n"
            "• GST services\n"
            "• Pricing\n"
            "• Contact details"
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

        conn, cursor = get_db()

        cursor.execute(
            "SELECT id, password FROM users WHERE email=%s",
            (email,)
        )
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["user"] = {
                "id": user[0],
                "email": email,
                "name": email.split("@")[0]
            }

            next_page = session.pop("next", None)
            return redirect(next_page or url_for("home"))

        return "Invalid email or password", 401

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
    if "user" not in session:
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



@app.route("/admin/callbacks")
def admin_callbacks():
    conn, cursor = get_db()

    cursor.execute("""
        SELECT id, phone, email, created_at, status
        FROM callback_requests
        ORDER BY created_at DESC
    """)
    callbacks = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin_callbacks.html", callbacks=callbacks)

@app.route("/admin/callbacks/update/<int:id>", methods=["POST"])
def update_callback_status(id):
    status = request.form.get("status")

    conn, cursor = get_db()

    cursor.execute("""
        UPDATE callback_requests
        SET status = %s
        WHERE id = %s
    """, (status, id))

    conn.commit()
    cursor.close()
    conn.close()

    return redirect("/admin/callbacks")

@app.context_processor
def inject_whatsapp():
    return {
        "WHATSAPP_NUMBER": os.getenv("WHATSAPP_NUMBER"),
        "WHATSAPP_TEXT": os.getenv("WHATSAPP_TEXT")
    }


if __name__ == "__main__":
    app.run(debug=True, port=5003)
