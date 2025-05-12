"""
Utility functions for the Telnet Scanner
"""
import logging
import sys
import os
from datetime import datetime

def setup_logging(level=logging.INFO):
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"telnet_scan_{timestamp}.log")
    
    # Configure logging
    handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )
    
    # Reduce verbosity of some libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    return logging.getLogger("TelnetScanner")

def print_banner():
    """Print the application banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║                TELNET SCANNER & AUTHENTICATOR              ║
    ║                                                            ║
    ║  Asynchronous network scanner for telnet services          ║
    ║  Scans random IPs and attempts authentication              ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

class StatTracker:
    """Track statistics for the scan"""
    def __init__(self):
        self.scanned = 0    # Number of IPs scanned
        self.attempts = 0   # Number of login attempts
        self.hits = 0       # Number of successful logins
        self.start_time = datetime.now()
    
    def elapsed_time(self):
        """Get elapsed time in seconds"""
        return (datetime.now() - self.start_time).total_seconds()
    
    def attempts_per_second(self):
        """Calculate attempts per second"""
        elapsed = self.elapsed_time()
        return self.attempts / elapsed if elapsed > 0 else 0
    
    def hit_ratio(self):
        """Calculate hit ratio"""
        return self.hits / self.attempts if self.attempts > 0 else 0
    
    def get_stats_dict(self):
        """Get statistics as a dictionary"""
        return {
            'scanned': self.scanned,
            'attempts': self.attempts,
            'hits': self.hits,
            'elapsed': self.elapsed_time(),
            'attempts_per_second': self.attempts_per_second(),
            'hit_ratio': self.hit_ratio()
        }
