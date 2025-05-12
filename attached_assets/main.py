from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort
import os
import subprocess
import threading
import time
import json
import asyncio
import logging
import signal
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from functools import wraps
from sqlalchemy import exc

from models import db, User, Proxy, ProxyLog, ScannerLog
from forms import LoginForm, RegistrationForm, ProxyForm, ScannerForm
from proxy_scanner import ProxyScanner

# Initialize Flask app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///telnet_scanner.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Initialize database
with app.app_context():
    # Create tables
    db.create_all()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for scanner process management
scanner_process = None
scanner_output = []
scanner_stats = {
    "status": "stopped",
    "start_time": None,
    "scanned": 0,
    "attempts": 0,
    "hits": 0,
    "last_update": None
}

# Global variable for proxy scanner process
proxy_scanner_process = None

def update_scanner_stats():
    """Update scanner statistics from hits file"""
    try:
        if os.path.exists("hits.txt"):
            with open("hits.txt", "r") as f:
                scanner_stats["hits"] = len(f.readlines())
        
        scanner_stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        logger.error(f"Error updating scanner stats: {e}")

def read_scanner_output(process):
    """Read output from scanner process and update stats"""
    while process.poll() is None:
        try:
            line = process.stdout.readline().decode('utf-8').strip()
            if line:
                scanner_output.append(line)
                # Limit output buffer size
                if len(scanner_output) > 100:
                    scanner_output.pop(0)
                
                # Parse statistics from output
                if "Statistics - Scanned:" in line:
                    parts = line.split("|")
                    for part in parts:
                        if "Scanned:" in part:
                            scanner_stats["scanned"] = int(part.split(":")[1].strip())
                        elif "Attempts:" in part:
                            scanner_stats["attempts"] = int(part.split(":")[1].strip())
                        elif "Hits:" in part:
                            scanner_stats["hits"] = int(part.split(":")[1].strip())
                
                update_scanner_stats()
        except Exception as e:
            logger.error(f"Error reading scanner output: {e}")
            break
        time.sleep(0.1)
    
    # Scanner process ended
    scanner_stats["status"] = "stopped"
    logger.info("Scanner process ended")

# Fix various LSP issues by implementing correct object instantiation

# Helper function to safely get form field label
def safe_getattr(obj, name, default=""):
    """Safely get attribute with default value if None"""
    value = getattr(obj, name, None)
    return value if value is not None else default

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Redirect to the requested page or default to index
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            # Log failed login attempts for security
            logger.warning(f"Failed login attempt for username: {form.username.data}")
            
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# No registration route for single-user system
# User creation is done via setup_user.py CLI tool

# Proxy management routes
@app.route('/proxies', methods=['GET'])
@login_required
def proxies():
    """Display proxy management page"""
    proxies = Proxy.query.all()
    working_proxies = [p for p in proxies if p.is_working]
    scan_logs = ProxyLog.query.order_by(ProxyLog.timestamp.desc()).limit(10).all()
    
    # Forms
    form = ProxyForm()
    scan_form = FlaskForm()
    test_form = FlaskForm()
    
    # Check if scanning is in progress
    scanning = proxy_scanner_process is not None and proxy_scanner_process.poll() is None
    
    return render_template('proxies.html', 
                          proxies=proxies,
                          working_proxies=working_proxies,
                          scan_logs=scan_logs,
                          form=form,
                          scan_form=scan_form,
                          test_form=test_form,
                          scanning=scanning)

@app.route('/add_proxy', methods=['POST'])
@login_required
def add_proxy():
    """Add a new proxy"""
    form = ProxyForm()
    if form.validate_on_submit():
        host = form.host.data
        port = form.port.data
        
        # Check if proxy already exists
        existing = Proxy.query.filter_by(host=host, port=port).first()
        if existing:
            flash(f'Proxy {host}:{port} already exists', 'warning')
            return redirect(url_for('proxies'))
        
        # Create new proxy
        proxy = Proxy(host=host, port=port, added_by_id=current_user.id)
        db.session.add(proxy)
        
        try:
            db.session.commit()
            flash(f'Proxy {host}:{port} added successfully', 'success')
            
            # Start a background task to test this proxy
            def test_proxy_async():
                with app.app_context():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    scanner = ProxyScanner()
                    result = loop.run_until_complete(scanner.test_proxy(f"{host}:{port}"))
                    
                    proxy = Proxy.query.filter_by(host=host, port=port).first()
                    if proxy:
                        proxy.is_working = result
                        proxy.last_tested = datetime.utcnow()
                        db.session.commit()
            
            threading.Thread(target=test_proxy_async, daemon=True).start()
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding proxy: {e}")
            flash(f'Error adding proxy: {e}', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('proxies'))

@app.route('/test_proxy/<int:proxy_id>', methods=['POST'])
@login_required
def test_proxy(proxy_id):
    """Test a specific proxy"""
    proxy = Proxy.query.get_or_404(proxy_id)
    
    # Start background task to test this proxy
    def test_proxy_async():
        with app.app_context():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scanner = ProxyScanner()
            
            start_time = time.time()
            result = loop.run_until_complete(scanner.test_proxy(f"{proxy.host}:{proxy.port}"))
            duration = time.time() - start_time
            
            proxy = Proxy.query.get(proxy_id)
            if proxy:
                proxy.is_working = result
                proxy.last_tested = datetime.utcnow()
                proxy.response_time = duration if result else None
                db.session.commit()
    
    threading.Thread(target=test_proxy_async, daemon=True).start()
    flash(f'Testing proxy {proxy.host}:{proxy.port}...', 'info')
    return redirect(url_for('proxies'))

@app.route('/delete_proxy/<int:proxy_id>', methods=['POST'])
@login_required
def delete_proxy(proxy_id):
    """Delete a proxy"""
    proxy = Proxy.query.get_or_404(proxy_id)
    
    try:
        db.session.delete(proxy)
        db.session.commit()
        flash(f'Proxy {proxy.host}:{proxy.port} deleted', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting proxy: {e}")
        flash(f'Error deleting proxy: {e}', 'danger')
    
    return redirect(url_for('proxies'))

@app.route('/scan_proxies', methods=['POST'])
@login_required
def scan_proxies():
    """Start a proxy scanning task"""
    global proxy_scanner_process
    
    # Check if already scanning
    if proxy_scanner_process is not None and proxy_scanner_process.poll() is None:
        flash('Proxy scan already in progress', 'warning')
        return redirect(url_for('proxies'))
    
    # Log the scan
    scan_log = ProxyLog(
        scan_type='manual',
        user_id=current_user.id
    )
    db.session.add(scan_log)
    db.session.commit()
    
    # Run the proxy scanner in a separate process
    def run_scanner():
        with app.app_context():
            start_time = time.time()
            
            # Create scanner and run scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scanner = ProxyScanner()
            result = loop.run_until_complete(scanner.run_scan())
            
            # Update database with results
            scan_duration = time.time() - start_time
            
            # Update scan log
            scan_log = ProxyLog.query.get(scan_log.id)
            if scan_log:
                scan_log.proxies_tested = result['total']
                scan_log.proxies_found = len(result['proxies'])
                scan_log.scan_duration = scan_duration
                db.session.commit()
            
            # Sync database with proxies from file
            sync_proxies_from_file()
    
    # Start scanner in background thread
    proxy_scanner_process = threading.Thread(target=run_scanner, daemon=True)
    proxy_scanner_process.start()
    
    flash('Proxy scan started', 'success')
    return redirect(url_for('proxies'))

@app.route('/test_proxies', methods=['POST'])
@login_required
def test_proxies():
    """Test all proxies"""
    proxies = Proxy.query.all()
    
    def test_all_async():
        with app.app_context():
            start_time = time.time()
            
            # Create scanner
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scanner = ProxyScanner()
            
            # Test each proxy
            for proxy in proxies:
                result = loop.run_until_complete(scanner.test_proxy(f"{proxy.host}:{proxy.port}"))
                proxy.is_working = result
                proxy.last_tested = datetime.utcnow()
            
            # Save changes
            db.session.commit()
            
            # Log the test
            scan_log = ProxyLog(
                scan_type='test',
                proxies_tested=len(proxies),
                proxies_found=sum(1 for p in proxies if p.is_working),
                scan_duration=time.time() - start_time,
                user_id=current_user.id
            )
            db.session.add(scan_log)
            db.session.commit()
    
    threading.Thread(target=test_all_async, daemon=True).start()
    flash(f'Testing {len(proxies)} proxies...', 'info')
    return redirect(url_for('proxies'))

def sync_proxies_from_file():
    """Sync proxies in database with proxies.txt file"""
    with app.app_context():
        try:
            # Read proxies from file
            file_proxies = set()
            if os.path.exists("proxies.txt"):
                with open("proxies.txt", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and ":" in line:
                            file_proxies.add(line)
            
            # Add new proxies to database
            for proxy_str in file_proxies:
                if ":" not in proxy_str:
                    continue
                    
                host, port = proxy_str.split(":")
                if not port.isdigit():
                    continue
                    
                port = int(port)
                existing = Proxy.query.filter_by(host=host, port=port).first()
                
                if not existing:
                    new_proxy = Proxy(
                        host=host,
                        port=port,
                        is_working=True,  # Assume working initially
                        last_tested=datetime.utcnow()
                    )
                    db.session.add(new_proxy)
            
            db.session.commit()
            logger.info(f"Synced {len(file_proxies)} proxies from file")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error syncing proxies from file: {e}")

# Main scanner routes
@app.route('/')
@login_required
def index():
    """Render the main dashboard"""
    # Get scanner form
    form = ScannerForm()
    form.batch_size.data = 200
    form.max_conns.data = 50
    
    # Get available credentials
    credentials = []
    if os.path.exists("creds.txt"):
        with open("creds.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    credentials.append(line)
    
    # Get hits
    hits = []
    if os.path.exists("hits.txt"):
        with open("hits.txt", "r") as f:
            hits = [line.strip() for line in f if line.strip()]
    
    # Get working proxies count
    working_proxies_count = Proxy.query.filter_by(is_working=True).count()
    
    return render_template('index.html', 
                          scanner_stats=scanner_stats, 
                          scanner_output=scanner_output,
                          credentials=credentials,
                          hits=hits,
                          working_proxies_count=working_proxies_count,
                          form=form)

@app.route('/start_scanner', methods=['POST'])
@login_required
def start_scanner():
    """Start the telnet scanner"""
    global scanner_process
    
    if scanner_stats["status"] == "running":
        flash("Scanner is already running", "warning")
        return redirect(url_for('index'))
    
    form = ScannerForm()
    if form.validate_on_submit():
        try:
            # Get parameters from form
            batch_size = str(form.batch_size.data)
            max_conns = str(form.max_conns.data)
            verbose = form.verbose.data
            
            # Build command
            cmd = ["python", "improved_telnet_scanner.py", 
                "--batch-size", batch_size, 
                "--max-conns", max_conns]
            
            if verbose:
                cmd.append("--verbose")
            
            # Start the scanner process
            scanner_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=False
            )
            
            # Reset statistics
            scanner_output.clear()
            scanner_stats["status"] = "running"
            scanner_stats["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scanner_stats["scanned"] = 0
            scanner_stats["attempts"] = 0
            
            # Start thread to read output
            threading.Thread(target=read_scanner_output, args=(scanner_process,), daemon=True).start()
            
            # Log scanner session
            scanner_log = ScannerLog(
                start_time=datetime.utcnow(),
                status="running",
                user_id=current_user.id
            )
            db.session.add(scanner_log)
            db.session.commit()
            
            flash("Scanner started successfully", "success")
        except Exception as e:
            flash(f"Failed to start scanner: {e}", "danger")
            logger.error(f"Error starting scanner: {e}")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/stop_scanner', methods=['POST'])
@login_required
def stop_scanner():
    """Stop the running scanner"""
    global scanner_process
    
    if scanner_stats["status"] != "running" or scanner_process is None:
        flash("Scanner is not running", "warning")
        return redirect(url_for('index'))
    
    try:
        # Send SIGTERM to gracefully stop the scanner
        scanner_process.send_signal(signal.SIGTERM)
        
        # Wait a bit for graceful shutdown
        time.sleep(2)
        
        # If still running, force kill
        if scanner_process.poll() is None:
            scanner_process.terminate()
            time.sleep(1)
            if scanner_process.poll() is None:
                scanner_process.kill()
        
        scanner_stats["status"] = "stopped"
        
        # Update scanner log
        scanner_log = ScannerLog.query.filter_by(status="running").order_by(ScannerLog.start_time.desc()).first()
        if scanner_log:
            scanner_log.status = "completed"
            scanner_log.end_time = datetime.utcnow()
            scanner_log.ips_scanned = scanner_stats["scanned"]
            scanner_log.login_attempts = scanner_stats["attempts"]
            scanner_log.successful_logins = scanner_stats["hits"]
            db.session.commit()
        
        flash("Scanner stopped successfully", "success")
    except Exception as e:
        flash(f"Error stopping scanner: {e}", "danger")
        logger.error(f"Error stopping scanner: {e}")
    
    return redirect(url_for('index'))

@app.route('/api/stats')
@login_required
def get_stats():
    """API endpoint to get current scanner statistics"""
    update_scanner_stats()
    return jsonify(scanner_stats)

@app.route('/api/output')
@login_required
def get_output():
    """API endpoint to get scanner output"""
    return jsonify(scanner_output)

@app.route('/api/hits')
@login_required
def get_hits():
    """API endpoint to get successful hits"""
    hits = []
    try:
        if os.path.exists("hits.txt"):
            with open("hits.txt", "r") as f:
                hits = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error reading hits file: {e}")
    
    return jsonify(hits)

@app.route('/edit_credentials', methods=['GET', 'POST'])
@login_required
def edit_credentials():
    """Edit credentials file"""
    if request.method == 'POST':
        try:
            content = request.form.get('content', '')
            with open("creds.txt", "w") as f:
                f.write(content)
            flash("Credentials saved successfully", "success")
        except Exception as e:
            flash(f"Error saving credentials: {e}", "danger")
        
        return redirect(url_for('index'))
    
    # GET request - show edit form
    content = ""
    try:
        if os.path.exists("creds.txt"):
            with open("creds.txt", "r") as f:
                content = f.read()
    except Exception as e:
        flash(f"Error reading credentials file: {e}", "danger")
    
    return render_template('edit_credentials.html', content=content)

@app.route('/clear_hits', methods=['POST'])
@login_required
def clear_hits():
    """Clear the hits file"""
    try:
        with open("hits.txt", "w") as f:
            pass
        flash("Hits cleared successfully", "success")
        scanner_stats["hits"] = 0
    except Exception as e:
        flash(f"Error clearing hits: {e}", "danger")
    
    return redirect(url_for('index'))

# Handle SIGTERM for clean shutdown
def handle_sigterm(signum, frame):
    global scanner_process
    if scanner_process and scanner_process.poll() is None:
        scanner_process.terminate()
    exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

# Create templates directory if it doesn't exist
os.makedirs('templates', exist_ok=True)

if __name__ == '__main__':
    # For local development only, not used in production with gunicorn
    app.run(host='0.0.0.0', port=5000, debug=True)