
import psycopg2
import os

def get_db_connection():
    db_url = os.getenv("DATABASE_URL") or os.getenv("LOCAL_DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(db_url)


def release_db_connection(conn):
    """Close a DB connection safely."""
    if conn is None:
        return
    try:
        conn.close()
    except Exception:
        pass
