"""
Scanner Manager module to handle telnet scanning operations
Provides an interface between the web application and the scanner components
"""
import asyncio
import logging
import threading
import time
import random
import os
from datetime import datetime
from contextlib import suppress

from models import db, ScannerLog, ScannerStat, TelnetHit, Credential, Proxy
import config

# Import existing scanner components
from auth_handler import AuthHandler
from proxy_manager import ProxyManager
from improved_telnet_scanner import StatTracker

logger = logging.getLogger("ScannerManager")

class ScannerManager:
    """
    Manages telnet scanning operations and interfaces with the database
    """
    def __init__(self, app=None):
        """Initialize the scanner manager"""
        self.app = app
        self.is_running = False
        self.current_task = None
        self.stats = StatTracker()
        self.last_stats_update = None
        self.auth_handler = None
        self.proxy_manager = None
        self.scan_log_id = None
        self.stop_event = asyncio.Event()
        
        # Create necessary files if they don't exist
        self._ensure_files_exist()
    
    def _ensure_files_exist(self):
        """Create necessary files if they don't exist"""
        for file_path in [config.DEFAULT_CREDENTIALS_FILE, config.DEFAULT_HITS_FILE, config.DEFAULT_PROXY_FILE]:
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    if file_path == config.DEFAULT_CREDENTIALS_FILE:
                        f.write("# Add credentials in format username:password\n")
                        f.write("admin:admin\n")
                        f.write("root:root\n")
                        f.write("user:user\n")
                    elif file_path == config.DEFAULT_PROXY_FILE:
                        f.write("# Add proxies in format host:port\n")
                        f.write("# Use 127.0.0.1:0 for direct connections\n")
                        f.write("127.0.0.1:0\n")
                    elif file_path == config.DEFAULT_HITS_FILE:
                        f.write("# Successful telnet logins\n")
                        f.write("# Format: timestamp | ip:port | username:password\n")
                logger.info(f"Created file: {file_path}")
    
    async def initialize(self):
        """Initialize the scanner components"""
        logger.info("Initializing scanner components...")
        
        # Create proxy manager and auth handler
        self.proxy_manager = ProxyManager(proxy_file=config.DEFAULT_PROXY_FILE, 
                                          connect_timeout=config.TELNET_CONNECT_TIMEOUT)
        self.auth_handler = AuthHandler(creds_file=config.DEFAULT_CREDENTIALS_FILE,
                                        hits_file=config.DEFAULT_HITS_FILE,
                                        login_timeout=config.TELNET_LOGIN_TIMEOUT,
                                        retry_attempts=config.TELNET_RETRY_ATTEMPTS)
        
        # Initialize the proxy manager
        await self.proxy_manager.initialize()
        
        logger.info("Scanner components initialized")
        return True
    
    def start_scan(self, scan_type='manual', batch_size=None, max_concurrent=None, user_id=None, custom_ip_range=None):
        """Start a new scan in a background task"""
        if self.is_running:
            logger.warning("Scanner is already running")
            return False
        
        # Set default values if not provided
        batch_size = batch_size or config.IP_BATCH_SIZE
        max_concurrent = max_concurrent or config.MAX_CONCURRENT_SCANS
        
        # Create a scan log entry in the database
        with self.app.app_context():
            scan_log = ScannerLog(
                scan_type=scan_type,
                is_running=True,
                user_id=user_id
            )
            db.session.add(scan_log)
            db.session.commit()
            self.scan_log_id = scan_log.id
            logger.info(f"Created scan log with ID: {self.scan_log_id}")
        
        # Reset stats
        self.stats = StatTracker()
        self.stop_event.clear()
        
        # Start the scan in a background task
        def run_scan_wrapper():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._run_scan(batch_size, max_concurrent, custom_ip_range))
            except Exception as e:
                logger.error(f"Error in scan task: {e}")
            finally:
                loop.close()
        
        self.current_task = threading.Thread(target=run_scan_wrapper, daemon=True)
        self.current_task.start()
        self.is_running = True
        
        logger.info(f"Started {scan_type} scan with batch size {batch_size} and max concurrent {max_concurrent}")
        return True
    
    def stop_scan(self):
        """Stop the current scan"""
        if not self.is_running:
            logger.warning("No scan is running")
            return False
        
        logger.info("Stopping scan...")
        self.stop_event.set()
        self.is_running = False
        
        # Update scan log
        with self.app.app_context():
            scan_log = ScannerLog.query.get(self.scan_log_id)
            if scan_log:
                scan_log.is_running = False
                scan_log.scan_duration = self.stats.elapsed_time()
                scan_log.ips_scanned = self.stats.scanned
                scan_log.login_attempts = self.stats.attempts
                scan_log.successful_logins = self.stats.hits
                db.session.commit()
        
        return True
    
    async def _run_scan(self, batch_size, max_concurrent, custom_ip_range=None):
        """Run the scan process"""
        try:
            # Initialize components if not already initialized
            if not self.proxy_manager or not self.auth_handler:
                await self.initialize()
            
            logger.info("Starting scan process...")
            self.is_running = True
            
            # Set up concurrency control
            semaphore = asyncio.Semaphore(max_concurrent)
            
            while not self.stop_event.is_set():
                # Generate a batch of IPs
                if custom_ip_range:
                    try:
                        ip_batch = self._generate_ips_from_range(custom_ip_range, batch_size)
                        # If we've exhausted the range, stop the scan
                        if not ip_batch:
                            logger.info("Finished scanning custom IP range")
                            break
                    except Exception as e:
                        logger.error(f"Error generating IPs from range: {e}")
                        break
                else:
                    ip_batch = self._get_random_ip_batch(batch_size)
                
                # Create tasks to scan each IP
                tasks = []
                for ip in ip_batch:
                    for port in config.SCAN_PORTS:
                        task = asyncio.create_task(
                            self._scan_target(ip, port, semaphore)
                        )
                        tasks.append(task)
                
                # Wait for all tasks to complete
                await asyncio.gather(*tasks)
                
                # Update stats in the database
                await self._update_stats()
                
                # Short delay between batches
                await asyncio.sleep(config.SCAN_BATCH_DELAY)
            
            logger.info("Scan process completed or stopped")
        except Exception as e:
            logger.error(f"Error in scan process: {e}")
        finally:
            # Update final stats and scan log
            await self._update_stats(final=True)
            self.is_running = False
    
    async def _scan_target(self, ip, port, semaphore):
        """Scan a specific IP:port target"""
        # Use the auth handler to try all credentials for the target
        try:
            await self.auth_handler.try_all_creds_for_target(
                ip, port, semaphore, self.proxy_manager, self.stats
            )
        except Exception as e:
            logger.error(f"Error scanning {ip}:{port}: {e}")
    
    async def _update_stats(self, final=False):
        """Update scanner statistics in the database"""
        # Only update every few seconds to avoid database load
        now = time.time()
        if not final and self.last_stats_update and (now - self.last_stats_update < 5):
            return
        
        self.last_stats_update = now
        
        # Update stats in the database
        with self.app.app_context():
            try:
                # Update the scan log
                scan_log = ScannerLog.query.get(self.scan_log_id)
                if scan_log:
                    scan_log.ips_scanned = self.stats.scanned
                    scan_log.login_attempts = self.stats.attempts
                    scan_log.successful_logins = self.stats.hits
                    scan_log.scan_duration = self.stats.elapsed_time()
                    
                    # If final update, mark as not running
                    if final:
                        scan_log.is_running = False
                    
                    db.session.commit()
                
                # Add a new stats entry
                stat_entry = ScannerStat(
                    ips_scanned=self.stats.scanned,
                    login_attempts=self.stats.attempts,
                    successful_logins=self.stats.hits,
                    proxies_used=len(self.proxy_manager.working_proxies),
                    scan_rate=self.stats.attempts_per_second()
                )
                db.session.add(stat_entry)
                db.session.commit()
                
                # Sync hits from file to database if any new ones
                await self._sync_hits_from_file()
            except Exception as e:
                logger.error(f"Error updating stats: {e}")
                db.session.rollback()
    
    async def _sync_hits_from_file(self):
        """Sync successful hits from file to database"""
        try:
            # Get existing hits from database
            existing_hits = set()
            for hit in TelnetHit.query.all():
                existing_hits.add(f"{hit.ip_address}:{hit.port}|{hit.username}:{hit.password}")
            
            # Read hits file
            if os.path.exists(config.DEFAULT_HITS_FILE):
                with open(config.DEFAULT_HITS_FILE, 'r') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Parse hit line format: timestamp | ip:port | username:password
                        parts = line.split('|')
                        if len(parts) != 3:
                            continue
                        
                        timestamp_str = parts[0].strip()
                        ip_port = parts[1].strip()
                        username_password = parts[2].strip()
                        
                        # Split IP:port and username:password
                        ip_address, port = ip_port.split(':')
                        username, password = username_password.split(':')
                        
                        # Check if this hit already exists
                        hit_key = f"{ip_address}:{port}|{username}:{password}"
                        if hit_key in existing_hits:
                            continue
                        
                        # Add new hit to database
                        # Find credential if it exists
                        cred = Credential.query.filter_by(username=username, password=password).first()
                        
                        hit = TelnetHit(
                            timestamp=datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S") if timestamp_str else datetime.utcnow(),
                            ip_address=ip_address,
                            port=int(port),
                            username=username,
                            password=password,
                            credential_id=cred.id if cred else None
                        )
                        db.session.add(hit)
                        
                        # Increment credential success count if needed
                        if cred:
                            cred.success_count += 1
                        
                        existing_hits.add(hit_key)
                    except Exception as e:
                        logger.error(f"Error parsing hit line '{line}': {e}")
                
                db.session.commit()
        except Exception as e:
            logger.error(f"Error syncing hits from file: {e}")
            db.session.rollback()
    
    def _get_random_ip_batch(self, batch_size):
        """Generate a batch of random IPs avoiding reserved ranges"""
        batch = set()
        while len(batch) < batch_size:
            ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            if not self._is_reserved(ip):
                batch.add(ip)
        return list(batch)
    
    def _is_reserved(self, ip):
        """Check if an IP is in a reserved network"""
        return any(ip.startswith(prefix) for prefix in config.RESERVED_PREFIXES)
    
    def _generate_ips_from_range(self, ip_range, max_ips):
        """Generate IPs from a CIDR range"""
        import ipaddress
        network = ipaddress.ip_network(ip_range, strict=False)
        
        # Get previously scanned IPs for this range from database
        with self.app.app_context():
            # This is a simplified approach - in a real implementation you'd track
            # which IPs have been scanned for each range
            previously_scanned = set()
        
        # Get all hosts in the network
        all_hosts = list(network.hosts())
        
        # Filter out previously scanned and reserved IPs
        available_hosts = [
            str(ip) for ip in all_hosts 
            if str(ip) not in previously_scanned and not self._is_reserved(str(ip))
        ]
        
        # If no hosts available, return empty list
        if not available_hosts:
            return []
        
        # Return a batch of IPs up to max_ips
        return available_hosts[:max_ips]
    
    async def sync_credentials_to_file(self):
        """Sync credentials from database to file"""
        with self.app.app_context():
            try:
                # Get enabled credentials from database
                credentials = Credential.query.filter_by(is_enabled=True).all()
                
                # Write to credentials file
                async with suppress(Exception):
                    with open(config.DEFAULT_CREDENTIALS_FILE, 'w') as f:
                        f.write("# Credentials for telnet scanning - Auto-updated by ScannerManager\n")
                        f.write("# Format: username:password\n")
                        f.write("# Last updated: {}\n\n".format(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ))
                        
                        for cred in credentials:
                            f.write(f"{cred.username}:{cred.password}\n")
                
                logger.info(f"Synced {len(credentials)} credentials to file")
                
                # Clear credentials cache in auth handler
                if self.auth_handler:
                    self.auth_handler.credentials = None
            except Exception as e:
                logger.error(f"Error syncing credentials to file: {e}")
    
    async def sync_proxies_to_file(self):
        """Sync proxies from database to file"""
        with self.app.app_context():
            try:
                # Get proxies from database
                proxies = Proxy.query.all()
                
                # Prepare proxy strings
                proxy_strings = set()
                for proxy in proxies:
                    proxy_strings.add(f"{proxy.host}:{proxy.port}")
                
                # Always include direct connection option
                direct_connection = "127.0.0.1:0"
                if direct_connection not in proxy_strings:
                    proxy_strings.add(direct_connection)
                
                # Write to proxy file
                async with suppress(Exception):
                    with open(config.DEFAULT_PROXY_FILE, 'w') as f:
                        f.write("# Proxy list for telnet scanner - Auto-updated by ScannerManager\n")
                        f.write("# Format: host:port\n")
                        f.write("# Last updated: {}\n\n".format(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ))
                        
                        for proxy in sorted(proxy_strings):
                            f.write(f"{proxy}\n")
                
                logger.info(f"Synced {len(proxy_strings)} proxies to file")
                
                # If proxy manager is initialized, trigger a refresh
                if self.proxy_manager:
                    await self.proxy_manager.load_proxies()
                    await self.proxy_manager.refresh_proxies()
            except Exception as e:
                logger.error(f"Error syncing proxies to file: {e}")
    
    def get_status(self):
        """Get current scanner status and statistics"""
        return {
            "is_running": self.is_running,
            "scanned": self.stats.scanned,
            "attempts": self.stats.attempts,
            "hits": self.stats.hits,
            "elapsed_time": self.stats.elapsed_time() if self.stats else 0,
            "attempts_per_second": self.stats.attempts_per_second() if self.stats else 0,
            "hit_ratio": self.stats.hit_ratio() if self.stats else 0,
            "working_proxies": len(self.proxy_manager.working_proxies) if self.proxy_manager else 0
        }
