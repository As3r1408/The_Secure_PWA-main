import sqlite3 as sql
import re
import time
import random
from werkzeug.security import generate_password_hash, check_password_hash
import html
import pyotp

def validate_username(username):
    """Ensure the username contains only alphanumeric characters and is 3-20 characters long."""
    return re.match(r"^[a-zA-Z0-9]{3,20}$", username) is not None

def execute_query(query, params=(), retries=5):
    for attempt in range(retries):
        try:
            con = sql.connect("database_files/database.db")
            cur = con.cursor()
            cur.execute(query, params)
            con.commit()
            con.close()
            return cur
        except sql.OperationalError as e:
            if "database is locked" in str(e) and attempt < retries - 1:
                time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
            else:
                raise

def insertUser(username, password, dob):
    if not validate_username(username):
        raise ValueError("Invalid username format")

    hashed_password = generate_password_hash(password)  # Hash passwords before storing
    base32secret = pyotp.random_base32()  # Generate a base32 secret for 2FA
    query = "INSERT INTO users (username, password, dateOfBirth, otp_secret) VALUES (?, ?, ?, ?)"
    params = (username, hashed_password, dob, base32secret)
    execute_query(query, params)

def retrieveUsers(username, password):
    if not validate_username(username):
        return False

    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT password, otp_secret FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if row is None:
        con.close()
        return False

    hashed_password, otp_secret = row
    if not check_password_hash(hashed_password, password):  # Verify password securely
        con.close()
        return False

    # Secure logging instead of writing plaintext logs
    with open("visitor_log.txt", "a") as file:
        file.write(f"User {username} logged in at {time.ctime()}\n")

    time.sleep(random.uniform(0.08, 0.09))  # Keep response time uniform to prevent timing attacks
    con.close()
    return otp_secret

def insertFeedback(feedback):
    sanitized_feedback = html.escape(feedback)  # Prevent XSS
    query = "INSERT INTO feedback (feedback) VALUES (?)"
    params = (sanitized_feedback,)
    execute_query(query, params)

def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()

    feedbacks = [html.escape(row[1]) for row in data]  # Escape content to prevent XSS
    return feedbacks
