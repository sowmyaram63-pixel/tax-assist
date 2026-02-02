import psycopg2
import os

# DB
DATABASE_URL = 'postgresql://neondb_owner:npg_GE0Xigd1AkLS@ep-square-union-ahlvp8o1-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'

if not DATABASE_URL:
    raise Exception("DATABASE_URL not set")

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

create_table_query = """
CREATE TABLE IF NOT EXISTS callback_requests (
    id SERIAL PRIMARY KEY,
    phone VARCHAR(20),
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
);
"""

cursor.execute(create_table_query)
conn.commit()

cursor.close()
conn.close()

print("✅ callback_table created successfully")
