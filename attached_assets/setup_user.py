#!/usr/bin/env python3
"""
Setup User Script
Creates a single administrative user for the telnet scanner.
This script should be run once during initial setup.
"""
import os
import sys
import getpass
import re
import argparse
from werkzeug.security import generate_password_hash
import sqlite3
from datetime import datetime

# Database setup
DB_PATH = "telnet_scanner.db"

def validate_email(email):
    """Simple email validation"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def create_database():
    """Create the SQLite database and tables if they don't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create user table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT TRUE,
        created_at TEXT,
        last_login TEXT
    )
    ''')
    
    conn.commit()
    return conn

def user_exists():
    """Check if any user exists in the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM user")
    count = cursor.fetchone()[0]
    conn.close()
    
    return count > 0

def create_user(username, email, password):
    """Create a new user in the database"""
    # Check if database exists, create it if not
    conn = create_database()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT COUNT(*) FROM user WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone()[0] > 0:
        conn.close()
        return False, "A user with this username or email already exists"
    
    # Create the user
    password_hash = generate_password_hash(password)
    created_at = datetime.now().isoformat()
    
    try:
        cursor.execute(
            "INSERT INTO user (username, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, password_hash, True, created_at)
        )
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except Exception as e:
        conn.close()
        return False, f"Error creating user: {e}"

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Setup admin user for Telnet Scanner")
    parser.add_argument("-u", "--username", help="Admin username")
    parser.add_argument("-e", "--email", help="Admin email")
    parser.add_argument("-p", "--password", help="Admin password (not recommended, use interactive mode)")
    parser.add_argument("-f", "--force", action="store_true", help="Force user creation even if one already exists")
    args = parser.parse_args()

    # Ensure DB and tables exist first
    create_database()

    # Check if user already exists
    if user_exists() and not args.force:
        print("A user already exists in the database. Use --force to overwrite.")
        return

    # Get username
    username = args.username
    while not username:
        username = input("Enter admin username: ")
        if not username or len(username) < 3:
            print("Username must be at least 3 characters")
            username = None

    # Get email
    email = args.email
    while not email or not validate_email(email):
        email = input("Enter admin email: ")
        if not validate_email(email):
            print("Invalid email format")
            email = None

    # Get password
    password = args.password
    while not password:
        password = getpass.getpass("Enter admin password: ")
        valid, message = validate_password(password)
        if not valid:
            print(message)
            password = None
            continue

        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords don't match")
            password = None

    # Create the user
    success, message = create_user(username, email, password)
    print(message)

    if success:
        print(f"\nAdmin user '{username}' created successfully!")
        print("You can now log in to the Telnet Scanner web interface.")


if __name__ == "__main__":
    main()
