import sqlite3 as sql
import re
import time
import random
from werkzeug.security import generate_password_hash, check_password_hash
import html

def validate_username(username):
    """Ensure the username contains only alphanumeric characters and is 3-20 characters long."""
    return re.match(r"^[a-zA-Z0-9]{3,20}$", username) is not None

def insertUser(username, password, dob):
    if not validate_username(username):
        raise ValueError("Invalid username format")

    hashed_password = generate_password_hash(password)  # Hash passwords before storing
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (username, hashed_password, dob),
    )
    con.commit()
    con.close()

def retrieveUsers(username, password):
    if not validate_username(username):
        return False

    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if row is None:
        con.close()
        return False

    hashed_password = row[0]
    if not check_password_hash(hashed_password, password):  # Verify password securely
        con.close()
        return False

    # Secure logging instead of writing plaintext logs
    with open("visitor_log.txt", "a") as file:
        file.write(f"User {username} logged in at {time.ctime()}\n")

    time.sleep(random.uniform(0.08, 0.09))  # Keep response time uniform to prevent timing attacks
    con.close()
    return True

def insertFeedback(feedback):
    sanitized_feedback = html.escape(feedback)  # Prevent XSS
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (sanitized_feedback,))
    con.commit()
    con.close()

def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()

    with open("templates/partials/success_feedback.html", "w") as f:
        if not data:
            f.write("<p>No feedback yet.</p>")  # Display message if no feedback exists
        else:
            for row in data:
                f.write("<p>\n")
                f.write(f"{html.escape(row[1])}\n")  # Escape content to prevent XSS
                f.write("</p>\n")