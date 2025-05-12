"""
Configuration settings for the Telnet Scanner application
"""
import os

# Flask application settings
SECRET_KEY = os.environ.get("SESSION_SECRET", "default_secure_key_change_in_production")
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# Database settings
SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///telnet_scanner.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Scanner settings
MAX_CONCURRENT_SCANS = 50
DEFAULT_CREDENTIALS_FILE = "creds.txt"
DEFAULT_HITS_FILE = "hits.txt"
DEFAULT_PROXY_FILE = "proxies.txt"

# Proxy settings
PROXY_REFRESH_INTERVAL = 300  # 5 minutes
PROXY_CONNECTION_TIMEOUT = 5
PROXY_TEST_TIMEOUT = 10

# Telnet settings
TELNET_CONNECT_TIMEOUT = 5
TELNET_LOGIN_TIMEOUT = 6
TELNET_RETRY_ATTEMPTS = 2

# Scan batch settings
IP_BATCH_SIZE = 200
SCAN_BATCH_DELAY = 1.0
SCAN_PORTS = [23, 2323]

# Reserved network prefixes (don't scan these)
RESERVED_PREFIXES = [
    "0.", "10.", "100.64.", "127.", "169.254.",
    "172.16.", "172.31.", "192.0.0.", "192.168.",
    "198.18.", "198.19.", *[f"{i}." for i in range(224, 256)]
]
