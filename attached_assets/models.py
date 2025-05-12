from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import hashlib

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        """Set the password hash from a plaintext password"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return f'<User {self.username}>'

class Proxy(db.Model):
    """Proxy server model"""
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    is_working = db.Column(db.Boolean, default=False)
    response_time = db.Column(db.Float, nullable=True)  # in seconds
    last_tested = db.Column(db.DateTime, nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    added_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    added_by = db.relationship('User', backref=db.backref('added_proxies', lazy=True))
    
    @property
    def address(self):
        """Return the full proxy address as host:port"""
        return f"{self.host}:{self.port}"
        
    def __repr__(self):
        return f'<Proxy {self.host}:{self.port} working={self.is_working}>'
        
    @staticmethod
    def get_hash(host, port):
        """Generate a unique hash for a proxy to prevent duplicates"""
        proxy_str = f"{host}:{port}".lower()
        return hashlib.md5(proxy_str.encode()).hexdigest()

class ProxyLog(db.Model):
    """Log of proxy scanning activity"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    scan_type = db.Column(db.String(32), nullable=False)  # manual, auto, etc.
    proxies_tested = db.Column(db.Integer, default=0)
    proxies_found = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, default=0.0)  # in seconds
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('proxy_scans', lazy=True))
    
    def __repr__(self):
        return f'<ProxyLog {self.timestamp} found={self.proxies_found}>'

class ScannerLog(db.Model):
    """Log of telnet scanner activity"""
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    ips_scanned = db.Column(db.Integer, default=0)
    login_attempts = db.Column(db.Integer, default=0)
    successful_logins = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default="running")  # running, completed, error
    error_message = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('scanner_sessions', lazy=True))
    
    def __repr__(self):
        return f'<ScannerLog {self.start_time} status={self.status}>'

# Index to prevent duplicate proxies
db.Index('idx_proxy_host_port', Proxy.host, Proxy.port, unique=True)