"""
Configuration module for the Telnet Scanner
Handles loading configuration from files and command line arguments
"""
import os
import configparser
import logging
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger("TelnetScanner.Config")

@dataclass
class Config:
    """Configuration class for Telnet Scanner"""
    # Connection settings
    max_conns: int = 50
    ip_batch_size: int = 200
    connect_timeout: float = 5.0
    login_timeout: float = 6.0
    batch_delay: float = 1.0
    retry_attempts: int = 2
    
    # Ports to scan (initialize ports properly)
    ports: List[int] = field(default_factory=lambda: [23, 2323])
    
    # File paths
    proxy_list: str = "proxies.txt"
    creds_file: str = "creds.txt"
    hits_file: str = "hits.txt"
    
    def __init__(self, args=None):
        """Initialize configuration from config file and command line arguments"""
        # Set default ports before loading the config file
        self.ports = [23, 2323]  # Default ports
        
        # Load defaults from config file if it exists
        self._load_from_file(args.config if args and args.config else "config.ini")
        
        # Override with command line arguments if provided
        if args:
            if args.batch_size:
                self.ip_batch_size = args.batch_size
            if args.max_conns:
                self.max_conns = args.max_conns
            if args.creds:
                self.creds_file = args.creds
            if args.hits:
                self.hits_file = args.hits
            if args.proxies:
                self.proxy_list = args.proxies
                
        # Ensure all required files exist or can be created
        self._verify_files()
        
        # Log the configuration
        logger.debug(f"Configuration: {self.__dict__}")
    
    def _load_from_file(self, config_file):
        """Load configuration from file"""
        config = configparser.ConfigParser()
        
        # Create default config if it doesn't exist
        if not os.path.exists(config_file):
            logger.info(f"Creating default configuration file: {config_file}")
            config['DEFAULT'] = {
                'max_conns': str(self.max_conns),
                'ip_batch_size': str(self.ip_batch_size),
                'connect_timeout': str(self.connect_timeout),
                'login_timeout': str(self.login_timeout),
                'batch_delay': str(self.batch_delay),
                'retry_attempts': str(self.retry_attempts),
                'ports': ','.join(map(str, self.ports)),
                'proxy_list': self.proxy_list,
                'creds_file': self.creds_file,
                'hits_file': self.hits_file
            }
            
            with open(config_file, 'w') as f:
                config.write(f)
        else:
            # Load existing config
            try:
                config.read(config_file)
                self.max_conns = config.getint('DEFAULT', 'max_conns', fallback=self.max_conns)
                self.ip_batch_size = config.getint('DEFAULT', 'ip_batch_size', fallback=self.ip_batch_size)
                self.connect_timeout = config.getfloat('DEFAULT', 'connect_timeout', fallback=self.connect_timeout)
                self.login_timeout = config.getfloat('DEFAULT', 'login_timeout', fallback=self.login_timeout)
                self.batch_delay = config.getfloat('DEFAULT', 'batch_delay', fallback=self.batch_delay)
                self.retry_attempts = config.getint('DEFAULT', 'retry_attempts', fallback=self.retry_attempts)
                
                ports_str = config.get('DEFAULT', 'ports', fallback='23,2323')
                self.ports = [int(p.strip()) for p in ports_str.split(',')]
                
                self.proxy_list = config.get('DEFAULT', 'proxy_list', fallback=self.proxy_list)
                self.creds_file = config.get('DEFAULT', 'creds_file', fallback=self.creds_file)
                self.hits_file = config.get('DEFAULT', 'hits_file', fallback=self.hits_file)
                
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Failed to load configuration from {config_file}: {e}")
                logger.info("Using default configuration")
    
    def _verify_files(self):
        """Verify that required files exist or can be created"""
        # Check credentials file
        if not os.path.exists(self.creds_file):
            logger.warning(f"Credentials file not found: {self.creds_file}")
            # Create empty file
            with open(self.creds_file, 'w') as f:
                f.write("admin:admin\n")
                f.write("root:root\n")
                f.write("user:user\n")
            logger.info(f"Created sample credentials file: {self.creds_file}")
        
        # Ensure hits file directory exists
        hits_dir = os.path.dirname(self.hits_file)
        if hits_dir and not os.path.exists(hits_dir):
            os.makedirs(hits_dir)
            logger.info(f"Created directory for hits file: {hits_dir}")
        
        # Create hits file if it doesn't exist (or ensure it's writable)
        try:
            with open(self.hits_file, 'a') as f:
                pass
            logger.debug(f"Hits file is writable: {self.hits_file}")
        except Exception as e:
            logger.error(f"Cannot write to hits file {self.hits_file}: {e}")
            self.hits_file = "hits.txt"  # Fallback
            logger.info(f"Using fallback hits file: {self.hits_file}")
