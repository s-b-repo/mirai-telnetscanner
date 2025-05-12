#!/usr/bin/env python3
"""
First-time setup script for Telnet Scanner
Creates admin user and initial configuration
"""
import argparse
import os
import sys
import getpass
import logging
from flask import Flask
from werkzeug.security import generate_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("Setup")

def setup_admin_user(username, email, password, db_uri=None):
    """Set up the admin user in the database"""
    try:
        # Create a minimal Flask app
        app = Flask(__name__)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_uri or "sqlite:///telnet_scanner.db"
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        
        # Import database models
        from models import db, User
        
        # Initialize database
        db.init_app(app)
        
        with app.app_context():
            # Create database tables
            db.create_all()
            
            # Check if users already exist
            user_count = User.query.count()
            if user_count > 0:
                logger.warning(f"Database already contains {user_count} users")
                if input("Continue anyway? (y/n): ").lower() != 'y':
                    logger.info("Setup aborted")
                    return False
            
            # Create admin user
            admin_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=True
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            logger.info(f"Admin user '{username}' created successfully")
            return True
            
    except Exception as e:
        logger.error(f"Error setting up admin user: {e}")
        return False

def create_default_files():
    """Create default credential and proxy files"""
    # Create credentials file
    if not os.path.exists("creds.txt"):
        with open("creds.txt", "w") as f:
            f.write("# Default credentials for telnet scanning\n")
            f.write("# Format: username:password\n\n")
            f.write("admin:admin\n")
            f.write("root:root\n")
            f.write("user:user\n")
        logger.info("Created default credentials file (creds.txt)")
    
    # Create proxy file
    if not os.path.exists("proxies.txt"):
        with open("proxies.txt", "w") as f:
            f.write("# Proxy list for telnet scanning\n")
            f.write("# Format: host:port\n")
            f.write("# Use 127.0.0.1:0 for direct connections\n\n")
            f.write("127.0.0.1:0\n")
        logger.info("Created default proxy file (proxies.txt)")
    
    # Create empty hits file
    if not os.path.exists("hits.txt"):
        with open("hits.txt", "w") as f:
            f.write("# Successful telnet logins\n")
            f.write("# Format: timestamp | ip:port | username:password\n\n")
        logger.info("Created empty hits file (hits.txt)")

def main():
    """Main setup function"""
    parser = argparse.ArgumentParser(description="Set up Telnet Scanner admin user")
    parser.add_argument("--username", "-u", help="Admin username")
    parser.add_argument("--email", "-e", help="Admin email")
    parser.add_argument("--password", "-p", help="Admin password (not recommended, use interactive prompt)")
    parser.add_argument("--db-uri", help="Database URI (default: sqlite:///telnet_scanner.db)")
    
    args = parser.parse_args()
    
    logger.info("Telnet Scanner Setup")
    logger.info("====================")
    
    # Get admin username
    username = args.username
    while not username:
        username = input("Admin username: ")
        if not username or len(username) < 3:
            logger.error("Username must be at least 3 characters")
            username = None
    
    # Get admin email
    email = args.email
    while not email:
        email = input("Admin email: ")
        if not email or '@' not in email:
            logger.error("Please enter a valid email address")
            email = None
    
    # Get admin password
    password = args.password
    while not password:
        password = getpass.getpass("Admin password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if not password or len(password) < 8:
            logger.error("Password must be at least 8 characters")
            password = None
            continue
            
        if password != confirm_password:
            logger.error("Passwords do not match")
            password = None
    
    # Create default files
    create_default_files()
    
    # Set up admin user
    success = setup_admin_user(username, email, password, args.db_uri)
    
    if success:
        logger.info("Setup completed successfully")
        logger.info(f"You can now log in as '{username}' with the password you provided")
        logger.info("Run the application with: python main.py")
        return 0
    else:
        logger.error("Setup failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
