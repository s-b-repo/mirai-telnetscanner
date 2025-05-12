"""
Database models for the Telnet Scanner application
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model for authentication and tracking actions"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    proxies = db.relationship('Proxy', backref='added_by', lazy='dynamic')
    proxy_logs = db.relationship('ProxyLog', backref='user', lazy='dynamic')
    scan_logs = db.relationship('ScannerLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Set the user's password hash"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if the password matches the hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Proxy(db.Model):
    """Proxy model for storing proxy server information"""
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    is_working = db.Column(db.Boolean, default=False)
    success_count = db.Column(db.Integer, default=0)
    failure_count = db.Column(db.Integer, default=0)
    last_tested = db.Column(db.DateTime, nullable=True)
    response_time = db.Column(db.Float, nullable=True)  # in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<Proxy {self.host}:{self.port}>'
    
    @property
    def proxy_string(self):
        """Return the proxy as a string in format host:port"""
        return f"{self.host}:{self.port}"
    
    @property
    def success_rate(self):
        """Calculate success rate percentage"""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0
        return (self.success_count / total) * 100

class ProxyLog(db.Model):
    """Log model for proxy scanning operations"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(20), default='manual')  # manual, auto, test
    proxies_tested = db.Column(db.Integer, default=0)
    proxies_found = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, nullable=True)  # in seconds
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<ProxyLog {self.timestamp} {self.scan_type}>'

class Credential(db.Model):
    """Credential model for storing username/password pairs for scanning"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    is_enabled = db.Column(db.Boolean, default=True)
    success_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<Credential {self.username}:{self.password}>'

class TelnetHit(db.Model):
    """Model for storing successful telnet logins"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    credential_id = db.Column(db.Integer, db.ForeignKey('credential.id'), nullable=True)
    
    def __repr__(self):
        return f'<TelnetHit {self.ip_address}:{self.port} {self.username}>'

class ScannerLog(db.Model):
    """Log model for telnet scanning operations"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(20), default='manual')  # manual, auto, scheduled
    ips_scanned = db.Column(db.Integer, default=0)
    login_attempts = db.Column(db.Integer, default=0)
    successful_logins = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float, nullable=True)  # in seconds
    is_running = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<ScannerLog {self.timestamp} {self.scan_type}>'

class ScannerStat(db.Model):
    """Statistics for scanner performance"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ips_scanned = db.Column(db.Integer, default=0)
    login_attempts = db.Column(db.Integer, default=0)
    successful_logins = db.Column(db.Integer, default=0)
    proxies_used = db.Column(db.Integer, default=0)
    scan_rate = db.Column(db.Float, default=0.0)  # IPs per second
    
    def __repr__(self):
        return f'<ScannerStat {self.timestamp}>'
