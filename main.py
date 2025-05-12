# Main entry point for the Telnet Scanner Web Application
import asyncio
import logging
import os
import threading
import time
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps

from models import db, User, Proxy, Credential, TelnetHit, ScannerLog, ProxyLog, ScannerStat
from forms import (LoginForm, RegistrationForm, ProxyForm, ScannerForm, CredentialForm, 
                  BatchCredentialForm, IPRangeForm, SettingsForm, ChangePasswordForm, ImportProxiesForm)
from scanner_manager import ScannerManager
import config

# Initialize Flask application
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = config.SQLALCHEMY_TRACK_MODIFICATIONS
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["WTF_CSRF_ENABLED"] = True

# Import Flask-WTF CSRF protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize scanner manager
scanner_manager = ScannerManager(app)

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
    db.create_all()
    
    # Check if we need to create an admin user
    if User.query.count() == 0:
        logger.info("No users found, creating default admin user")
        admin_user = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin_user.set_password('admin')
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Created default admin user (username: admin, password: admin)")
        # We'll show a flash message when the user logs in, not during initialization

# Start background task for proxy health checks
def start_proxy_health_check():
    """Start background task for regular proxy health checks"""
    def run_health_checks():
        logger.info("Starting background proxy health check task")
        while True:
            try:
                with app.app_context():
                    # Create async loop within thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    # Initialize scanner manager if needed
                    if not scanner_manager.proxy_manager:
                        loop.run_until_complete(scanner_manager.initialize())
                    
                    # Refresh proxies
                    loop.run_until_complete(scanner_manager.proxy_manager.refresh_proxies())
                    
                    # Update proxy status in database
                    proxies = Proxy.query.all()
                    for proxy in proxies:
                        proxy_str = f"{proxy.host}:{proxy.port}"
                        is_working = proxy_str in scanner_manager.proxy_manager.working_proxies
                        proxy.is_working = is_working
                        proxy.last_tested = datetime.utcnow()
                    
                    # Log the health check
                    proxy_log = ProxyLog(
                        scan_type='auto',
                        proxies_tested=len(proxies),
                        proxies_found=sum(1 for p in proxies if p.is_working)
                    )
                    db.session.add(proxy_log)
                    db.session.commit()
                    
                    logger.info(f"Proxy health check completed, {proxy_log.proxies_found}/{proxy_log.proxies_tested} working")
                    
                    # Close the event loop
                    loop.close()
                    
            except Exception as e:
                logger.error(f"Error in proxy health check: {e}")
            
            # Sleep until next check (5 minutes)
            time.sleep(config.PROXY_REFRESH_INTERVAL)
    
    # Start the thread
    proxy_thread = threading.Thread(target=run_health_checks, daemon=True)
    proxy_thread.start()
    logger.info("Started proxy health check background task")

# Start the proxy health check thread
start_proxy_health_check()

# Routes
@app.route('/')
@login_required
def index():
    """Dashboard homepage"""
    # Get scanner status
    scanner_status = scanner_manager.get_status()
    
    # Get recent hits
    recent_hits = TelnetHit.query.order_by(TelnetHit.timestamp.desc()).limit(10).all()
    
    # Get scanner logs
    scanner_logs = ScannerLog.query.order_by(ScannerLog.timestamp.desc()).limit(5).all()
    
    # Get proxy statistics
    total_proxies = Proxy.query.count()
    working_proxies = Proxy.query.filter_by(is_working=True).count()
    
    # Get credential statistics
    total_credentials = Credential.query.count()
    
    # Get scanner statistics for the charts
    stats = ScannerStat.query.order_by(ScannerStat.timestamp.desc()).limit(20).all()
    stats.reverse()  # Reverse for chronological order
    
    # Prepare forms
    scanner_form = ScannerForm()
    ip_range_form = IPRangeForm()
    
    return render_template('index.html',
                          scanner_status=scanner_status,
                          recent_hits=recent_hits,
                          scanner_logs=scanner_logs,
                          total_proxies=total_proxies,
                          working_proxies=working_proxies,
                          total_credentials=total_credentials,
                          stats=stats,
                          scanner_form=scanner_form,
                          ip_range_form=ip_range_form)

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
            
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """Handle user logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    """Handle user registration (admin only)"""
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken', 'danger')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_admin=form.is_admin.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('User registered successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html', form=form)

@app.route('/proxies', methods=['GET'])
@login_required
def proxies():
    """Display proxy management page"""
    # Get all proxies
    proxies = Proxy.query.all()
    working_proxies = [p for p in proxies if p.is_working]
    
    # Get recent proxy logs
    proxy_logs = ProxyLog.query.order_by(ProxyLog.timestamp.desc()).limit(10).all()
    
    # Forms
    proxy_form = ProxyForm()
    import_form = ImportProxiesForm()
    
    # Check if scanner manager is initialized
    is_initialized = scanner_manager.proxy_manager is not None
    if not is_initialized:
        flash("Initializing proxy system, please wait...", "info")
        # Start initialization in background
        def init_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scanner_manager.initialize())
            loop.close()
        
        threading.Thread(target=init_async, daemon=True).start()
    
    return render_template('proxies.html',
                          proxies=proxies,
                          working_proxies=working_proxies,
                          proxy_logs=proxy_logs,
                          proxy_form=proxy_form,
                          import_form=import_form,
                          is_initialized=is_initialized)

@app.route('/add_proxy', methods=['POST'])
@login_required
def add_proxy():
    """Add a new proxy"""
    form = ProxyForm()
    
    if form.validate_on_submit():
        host = form.host.data
        port = form.port.data
        
        # Check if proxy already exists
        if Proxy.query.filter_by(host=host, port=port).first():
            flash(f'Proxy {host}:{port} already exists', 'warning')
            return redirect(url_for('proxies'))
        
        # Create new proxy
        proxy = Proxy(
            host=host,
            port=port,
            added_by_id=current_user.id
        )
        db.session.add(proxy)
        db.session.commit()
        
        flash(f'Proxy {host}:{port} added successfully', 'success')
        
        # Test the proxy in background
        def test_proxy_async():
            with app.app_context():
                # Ensure scanner manager is initialized
                if not scanner_manager.proxy_manager:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(scanner_manager.initialize())
                    loop.close()
                
                # Test the proxy
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(scanner_manager.proxy_manager.test_proxy(f"{host}:{port}"))
                
                # Update proxy status
                proxy = Proxy.query.filter_by(host=host, port=port).first()
                if proxy:
                    proxy.is_working = result
                    proxy.last_tested = datetime.utcnow()
                    db.session.commit()
                
                # Sync proxies to file
                loop.run_until_complete(scanner_manager.sync_proxies_to_file())
                loop.close()
        
        threading.Thread(target=test_proxy_async, daemon=True).start()
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('proxies'))

@app.route('/import_proxies', methods=['POST'])
@login_required
def import_proxies():
    """Import multiple proxies from text"""
    form = ImportProxiesForm()
    
    if form.validate_on_submit():
        proxy_text = form.proxies.data
        lines = proxy_text.strip().split('\n')
        
        imported_count = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check if line is in format host:port
            if ':' not in line:
                continue
            
            try:
                host, port = line.split(':')
                port = int(port)
                
                # Validate IP and port
                if port < 1 or port > 65535:
                    continue
                
                # Check if proxy already exists
                if Proxy.query.filter_by(host=host, port=port).first():
                    continue
                
                # Create new proxy
                proxy = Proxy(
                    host=host,
                    port=port,
                    added_by_id=current_user.id
                )
                db.session.add(proxy)
                imported_count += 1
            except:
                continue
        
        if imported_count > 0:
            db.session.commit()
            flash(f'Imported {imported_count} proxies successfully', 'success')
            
            # Sync proxies to file in background
            def sync_proxies_async():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(scanner_manager.sync_proxies_to_file())
                loop.close()
            
            threading.Thread(target=sync_proxies_async, daemon=True).start()
        else:
            flash('No valid proxies found to import', 'warning')
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
    
    # Test the proxy in background
    def test_proxy_async():
        with app.app_context():
            # Ensure scanner manager is initialized
            if not scanner_manager.proxy_manager:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(scanner_manager.initialize())
                loop.close()
            
            # Test the proxy
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Get start time for response time measurement
            start_time = time.time()
            result = loop.run_until_complete(scanner_manager.proxy_manager.test_proxy(f"{proxy.host}:{proxy.port}"))
            duration = time.time() - start_time
            
            # Update proxy status
            proxy = Proxy.query.get(proxy_id)
            if proxy:
                proxy.is_working = result
                proxy.last_tested = datetime.utcnow()
                proxy.response_time = duration if result else None
                db.session.commit()
            
            loop.close()
    
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
        
        # Sync proxies to file in background
        def sync_proxies_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scanner_manager.sync_proxies_to_file())
            loop.close()
        
        threading.Thread(target=sync_proxies_async, daemon=True).start()
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting proxy: {e}', 'danger')
    
    return redirect(url_for('proxies'))

@app.route('/test_all_proxies', methods=['POST'])
@login_required
def test_all_proxies():
    """Test all proxies"""
    proxies = Proxy.query.all()
    
    if not proxies:
        flash('No proxies to test', 'warning')
        return redirect(url_for('proxies'))
    
    # Create a proxy log entry
    proxy_log = ProxyLog(
        scan_type='test',
        user_id=current_user.id
    )
    db.session.add(proxy_log)
    db.session.commit()
    
    # Test proxies in background
    def test_proxies_async():
        with app.app_context():
            # Ensure scanner manager is initialized
            if not scanner_manager.proxy_manager:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(scanner_manager.initialize())
                loop.close()
            
            start_time = time.time()
            working_count = 0
            
            # Test each proxy
            for proxy in proxies:
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    # Test proxy
                    test_start_time = time.time()
                    result = loop.run_until_complete(scanner_manager.proxy_manager.test_proxy(f"{proxy.host}:{proxy.port}"))
                    test_duration = time.time() - test_start_time
                    
                    # Update proxy status
                    proxy.is_working = result
                    proxy.last_tested = datetime.utcnow()
                    if result:
                        proxy.response_time = test_duration
                        working_count += 1
                    
                    loop.close()
                except:
                    proxy.is_working = False
                    proxy.last_tested = datetime.utcnow()
            
            # Update proxy log
            proxy_log = ProxyLog.query.get(proxy_log.id)
            if proxy_log:
                proxy_log.proxies_tested = len(proxies)
                proxy_log.proxies_found = working_count
                proxy_log.scan_duration = time.time() - start_time
            
            db.session.commit()
            
            # Sync proxies to file
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scanner_manager.sync_proxies_to_file())
            loop.close()
    
    threading.Thread(target=test_proxies_async, daemon=True).start()
    flash(f'Testing {len(proxies)} proxies...', 'info')
    
    return redirect(url_for('proxies'))

@app.route('/scan_proxies', methods=['POST'])
@login_required
def scan_proxies():
    """Scan for new proxies including internet-wide scanning"""
    # Get scan parameters from form
    scan_type = request.form.get('scan_type', 'local')  # 'local' or 'internet'
    batch_size = request.form.get('batch_size', type=int, default=100)
    num_batches = request.form.get('num_batches', type=int, default=5)
    
    # Validate inputs
    batch_size = max(10, min(batch_size, 500))  # Between 10 and 500
    num_batches = max(1, min(num_batches, 20))  # Between 1 and 20
    
    # Create a proxy log entry
    proxy_log = ProxyLog(
        scan_type='scan',
        user_id=current_user.id
    )
    db.session.add(proxy_log)
    db.session.commit()
    
    flash(f'Starting {"internet-wide" if scan_type == "internet" else "local"} proxy scan...', 'info')
    
    # Start proxy scan in background
    def scan_proxies_async():
        with app.app_context():
            start_time = time.time()
            
            # Choose scanner based on scan type
            if scan_type == 'internet':
                # Use the Internet Scanner for wide-range scanning
                from internet_proxy_scanner import InternetProxyScanner
                scanner = InternetProxyScanner(app=app)
                
                # Set up async event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Run internet-wide scan
                result = loop.run_until_complete(scanner.continuous_scan(
                    num_batches=num_batches,
                    batch_size=batch_size,
                    delay_between_batches=1.0
                ))
                
                # Update proxy log with results
                proxy_log = ProxyLog.query.get(proxy_log.id)
                if proxy_log:
                    proxy_log.proxies_tested = result.get('ips_scanned', 0)
                    proxy_log.proxies_found = result.get('newly_found', 0)
                    proxy_log.scan_duration = time.time() - start_time
                    db.session.commit()
                
                # Sync proxies to file and refresh the proxy manager
                loop.run_until_complete(scanner_manager.sync_proxies_to_file())
                loop.run_until_complete(scanner_manager.proxy_manager.refresh_proxies())
            else:
                # Use the original proxy scanner for local/targeted scanning
                from proxy_scanner import ProxyScanner
                scanner = ProxyScanner()
                
                # Set up async event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Run regular scan
                result = loop.run_until_complete(scanner.run_scan())
                
                # Process results
                if result and 'proxies' in result:
                    # Add new proxies to database
                    for proxy_str in result['proxies']:
                        try:
                            host, port = proxy_str.split(':')
                            port = int(port)
                            
                            # Skip direct connection
                            if host == "127.0.0.1" and port == 0:
                                continue
                            
                            # Check if proxy already exists
                            if not Proxy.query.filter_by(host=host, port=port).first():
                                proxy = Proxy(
                                    host=host,
                                    port=port,
                                    is_working=True,
                                    last_tested=datetime.utcnow(),
                                    added_by_id=current_user.id
                                )
                                db.session.add(proxy)
                        except:
                            continue
                    
                    db.session.commit()
                    
                    # Update proxy log
                    proxy_log = ProxyLog.query.get(proxy_log.id)
                    if proxy_log:
                        proxy_log.proxies_tested = result.get('total', 0)
                        proxy_log.proxies_found = len(result.get('proxies', []))
                        proxy_log.scan_duration = time.time() - start_time
                        db.session.commit()
                    
                    # Sync proxies to file
                    loop.run_until_complete(scanner_manager.sync_proxies_to_file())
            
            # Close the event loop
            loop.close()
    
    # Start scanning in a background thread
    threading.Thread(target=scan_proxies_async, daemon=True).start()
    
    return redirect(url_for('proxies'))

@app.route('/credentials', methods=['GET'])
@login_required
def credentials():
    """Display credential management page"""
    # Get all credentials
    credentials = Credential.query.all()
    
    # Get successful hits
    hits = TelnetHit.query.order_by(TelnetHit.timestamp.desc()).limit(20).all()
    
    # Forms
    cred_form = CredentialForm()
    batch_form = BatchCredentialForm()
    
    return render_template('credentials.html',
                          credentials=credentials,
                          hits=hits,
                          cred_form=cred_form,
                          batch_form=batch_form)

@app.route('/add_credential', methods=['POST'])
@login_required
def add_credential():
    """Add a new credential"""
    form = CredentialForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if credential already exists
        if Credential.query.filter_by(username=username, password=password).first():
            flash(f'Credential {username}:{password} already exists', 'warning')
            return redirect(url_for('credentials'))
        
        # Create new credential
        cred = Credential(
            username=username,
            password=password,
            added_by_id=current_user.id
        )
        db.session.add(cred)
        db.session.commit()
        
        flash(f'Credential {username}:{password} added successfully', 'success')
        
        # Sync credentials to file in background
        def sync_creds_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scanner_manager.sync_credentials_to_file())
            loop.close()
        
        threading.Thread(target=sync_creds_async, daemon=True).start()
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('credentials'))

@app.route('/batch_add_credentials', methods=['POST'])
@login_required
def batch_add_credentials():
    """Add multiple credentials"""
    form = BatchCredentialForm()
    
    if form.validate_on_submit():
        creds_text = form.credentials.data
        lines = creds_text.strip().split('\n')
        
        added_count = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check if line is in format username:password
            if ':' not in line:
                continue
            
            username, password = line.split(':', 1)
            
            # Check if credential already exists
            if Credential.query.filter_by(username=username, password=password).first():
                continue
            
            # Create new credential
            cred = Credential(
                username=username,
                password=password,
                added_by_id=current_user.id
            )
            db.session.add(cred)
            added_count += 1
        
        if added_count > 0:
            db.session.commit()
            flash(f'Added {added_count} credentials successfully', 'success')
            
            # Sync credentials to file in background
            def sync_creds_async():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(scanner_manager.sync_credentials_to_file())
                loop.close()
            
            threading.Thread(target=sync_creds_async, daemon=True).start()
        else:
            flash('No valid credentials found to add', 'warning')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('credentials'))

@app.route('/toggle_credential/<int:cred_id>', methods=['POST'])
@login_required
def toggle_credential(cred_id):
    """Toggle a credential's enabled status"""
    cred = Credential.query.get_or_404(cred_id)
    
    cred.is_enabled = not cred.is_enabled
    db.session.commit()
    
    status = "enabled" if cred.is_enabled else "disabled"
    flash(f'Credential {cred.username}:{cred.password} {status}', 'success')
    
    # Sync credentials to file in background
    def sync_creds_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(scanner_manager.sync_credentials_to_file())
        loop.close()
    
    threading.Thread(target=sync_creds_async, daemon=True).start()
    
    return redirect(url_for('credentials'))

@app.route('/delete_credential/<int:cred_id>', methods=['POST'])
@login_required
def delete_credential(cred_id):
    """Delete a credential"""
    cred = Credential.query.get_or_404(cred_id)
    
    try:
        db.session.delete(cred)
        db.session.commit()
        flash(f'Credential {cred.username}:{cred.password} deleted', 'success')
        
        # Sync credentials to file in background
        def sync_creds_async():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(scanner_manager.sync_credentials_to_file())
            loop.close()
        
        threading.Thread(target=sync_creds_async, daemon=True).start()
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting credential: {e}', 'danger')
    
    return redirect(url_for('credentials'))

@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    """Start telnet scanner"""
    form = ScannerForm()
    
    if form.validate_on_submit():
        if scanner_manager.is_running:
            flash('Scanner is already running', 'warning')
            return redirect(url_for('index'))
        
        # Get form data
        batch_size = form.batch_size.data
        max_concurrent = form.max_concurrent.data
        use_proxies = form.use_proxies.data
        
        # Parse ports
        ports = [int(p.strip()) for p in form.include_ports.data.split(',') if p.strip()]
        if ports:
            config.SCAN_PORTS = ports
        
        # Start the scanner
        success = scanner_manager.start_scan(
            scan_type='manual',
            batch_size=batch_size,
            max_concurrent=max_concurrent,
            user_id=current_user.id
        )
        
        if success:
            flash('Scanner started successfully', 'success')
        else:
            flash('Failed to start scanner', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/stop_scan', methods=['POST'])
@login_required
def stop_scan():
    """Stop telnet scanner"""
    if not scanner_manager.is_running:
        flash('Scanner is not running', 'warning')
        return redirect(url_for('index'))
    
    success = scanner_manager.stop_scan()
    
    if success:
        flash('Scanner stopped successfully', 'success')
    else:
        flash('Failed to stop scanner', 'danger')
    
    return redirect(url_for('index'))

@app.route('/scan_specific_range', methods=['POST'])
@login_required
def scan_specific_range():
    """Scan a specific IP range"""
    form = IPRangeForm()
    
    if form.validate_on_submit():
        if scanner_manager.is_running:
            flash('Scanner is already running', 'warning')
            return redirect(url_for('index'))
        
        ip_range = form.ip_range.data
        
        # Start the scanner with custom IP range
        success = scanner_manager.start_scan(
            scan_type='range',
            batch_size=100,  # Smaller batch for targeted scanning
            max_concurrent=50,
            user_id=current_user.id,
            custom_ip_range=ip_range
        )
        
        if success:
            flash(f'Started scan of IP range {ip_range}', 'success')
        else:
            flash('Failed to start scanner', 'danger')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('index'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    """Application settings page"""
    form = SettingsForm()
    password_form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Update configuration settings
        config.PROXY_REFRESH_INTERVAL = form.proxy_refresh_interval.data
        config.TELNET_CONNECT_TIMEOUT = form.telnet_connect_timeout.data
        config.TELNET_LOGIN_TIMEOUT = form.telnet_login_timeout.data
        config.SCAN_BATCH_DELAY = form.scan_batch_delay.data
        
        flash('Settings updated successfully', 'success')
    
    # Set initial values
    form.proxy_refresh_interval.data = config.PROXY_REFRESH_INTERVAL
    form.telnet_connect_timeout.data = config.TELNET_CONNECT_TIMEOUT
    form.telnet_login_timeout.data = config.TELNET_LOGIN_TIMEOUT
    form.scan_batch_delay.data = config.SCAN_BATCH_DELAY
    
    return render_template('settings.html', form=form, password_form=password_form)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Verify current password
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('settings'))
        
        # Update password
        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        flash('Password changed successfully', 'success')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{getattr(form, field).label.text}: {error}', 'danger')
    
    return redirect(url_for('settings'))

@app.route('/api/scanner_status')
@login_required
def api_scanner_status():
    """API endpoint for getting scanner status"""
    status = scanner_manager.get_status()
    
    # Add timestamp
    status['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return jsonify(status)

@app.route('/api/stats_history')
@login_required
def api_stats_history():
    """API endpoint for getting scanner stats history"""
    # Get stats from the last hour
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    stats = ScannerStat.query.filter(ScannerStat.timestamp >= hour_ago).order_by(ScannerStat.timestamp).all()
    
    # Format data for charts
    data = {
        'timestamps': [stat.timestamp.strftime('%H:%M:%S') for stat in stats],
        'ips_scanned': [stat.ips_scanned for stat in stats],
        'login_attempts': [stat.login_attempts for stat in stats],
        'successful_logins': [stat.successful_logins for stat in stats],
        'scan_rate': [stat.scan_rate for stat in stats]
    }
    
    return jsonify(data)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Initialize the app and scanner when running directly
if __name__ == '__main__':
    # Run the Flask app
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
