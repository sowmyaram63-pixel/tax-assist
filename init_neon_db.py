import psycopg2

DATABASE_URL = 'postgresql://neondb_owner:npg_GE0Xigd1AkLS@ep-square-union-ahlvp8o1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# users table 
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
""")

# payments table 
cur.execute("""
CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    plan_id INTEGER NOT NULL,
    amount NUMERIC(10,2) NOT NULL,
    payment_status TEXT DEFAULT 'SUCCESS',
    transaction_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
""")

conn.commit()
cur.close()
conn.close()

print("Users & Payments tables ready")
