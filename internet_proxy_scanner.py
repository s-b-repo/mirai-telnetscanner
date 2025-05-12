"""
Internet Proxy Scanner
Scans the public internet for HTTP proxies, tests them, and adds working ones to the database.
Avoids scanning private networks and reserved IP ranges.
"""

import asyncio
import ipaddress
import logging
import random
import socket
import time
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set, Tuple, Union

import aiohttp
from aiohttp import ClientTimeout

from models import db, Proxy, ProxyLog

# Setup logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s [%(levelname)s] InternetProxyScanner: %(message)s',
                   datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Constants
HTTP_PROXY_PORTS = [80, 8080, 3128, 8000, 8888, 8118, 53281, 1080, 8081, 8060]
TEST_URLS = [
    'http://www.example.com',
    'http://www.google.com',
    'http://www.amazon.com'
]
DEFAULT_TIMEOUT = 5.0  # Seconds
DEFAULT_MAX_CONCURRENT = 50
MAX_ATTEMPTS = 3
RESERVED_NETWORKS = [
    # RFC 1918 Private Networks
    '10.0.0.0/8',        # Private network
    '172.16.0.0/12',     # Private network
    '192.168.0.0/16',    # Private network
    # Other Special Purpose
    '0.0.0.0/8',         # Current network
    '100.64.0.0/10',     # Shared address space
    '127.0.0.0/8',       # Localhost
    '169.254.0.0/16',    # Link-local
    '192.0.0.0/24',      # IETF Protocol Assignments
    '192.0.2.0/24',      # Documentation (TEST-NET-1)
    '192.88.99.0/24',    # IPv6 to IPv4 relay
    '198.18.0.0/15',     # Benchmark testing
    '198.51.100.0/24',   # Documentation (TEST-NET-2)
    '203.0.113.0/24',    # Documentation (TEST-NET-3)
    '224.0.0.0/4',       # Multicast
    '240.0.0.0/4',       # Reserved
    '255.255.255.255/32' # Broadcast
]


class InternetProxyScanner:
    """
    Scans random public IP addresses across the internet for HTTP proxies.
    Features:
    - Random IP generation avoiding reserved ranges
    - Parallel scanning and testing of proxies
    - Database integration for storing working proxies
    """

    def __init__(self, app=None, proxy_file="proxies.txt", max_concurrent=DEFAULT_MAX_CONCURRENT,
                 connect_timeout=DEFAULT_TIMEOUT):
        """Initialize the proxy scanner"""
        self.app = app
        self.proxy_file = proxy_file
        self.max_concurrent = max_concurrent
        self.timeout = connect_timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Parse reserved networks
        self.reserved_networks = [ipaddress.ip_network(net) for net in RESERVED_NETWORKS]

        # Statistics tracking
        self.stats = {
            'start_time': None,
            'end_time': None,
            'ips_scanned': 0,
            'ports_scanned': 0,
            'proxies_tested': 0,
            'working_proxies': 0,
            'new_proxies': 0,
            'existing_proxies': 0,
            'failed_proxies': 0
        }

    def is_reserved(self, ip: str) -> bool:
        """Check if an IP is in a reserved network"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in net for net in self.reserved_networks)
        except ValueError:
            return True  # If we can't parse the IP, consider it reserved

    def generate_random_ips(self, count: int) -> List[str]:
        """Generate a batch of random IPs avoiding reserved ranges"""
        ips = []
        attempts = 0
        max_attempts = count * 3  # Allow up to 3x attempts to find valid IPs

        while len(ips) < count and attempts < max_attempts:
            # Generate a random IP
            ip_parts = [random.randint(1, 254) for _ in range(4)]
            ip = '.'.join(map(str, ip_parts))

            # Check if it's not in a reserved range
            if not self.is_reserved(ip):
                ips.append(ip)

            attempts += 1

        logger.info(f"Generated {len(ips)} random IPs")
        return ips

    async def load_existing_proxies(self) -> Set[str]:
        """Load existing proxies from the proxy file"""
        existing_proxies = set()

        try:
            with open(self.proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        existing_proxies.add(line)
        except FileNotFoundError:
            # Create the file if it doesn't exist
            with open(self.proxy_file, 'w') as f:
                f.write("# Proxy list - format: host:port\n")
                f.write("# Direct connection fallback\n")
                f.write("127.0.0.1:0\n")
            existing_proxies.add("127.0.0.1:0")

        return existing_proxies

    async def save_proxies(self, proxies: Set[str]) -> None:
        """Save proxies to the proxy file, preserving comments"""
        comments = []
        existing_entries = set()

        # Read existing file to preserve comments and structure
        try:
            with open(self.proxy_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#'):
                        comments.append(line)
                    elif line:
                        existing_entries.add(line)
        except FileNotFoundError:
            comments = ["# Proxy list - format: host:port",
                       "# Generated by InternetProxyScanner",
                       "# Direct connection fallback"]

        # Combine existing and new proxies
        all_proxies = existing_entries.union(proxies)

        # Ensure direct connection fallback is included
        all_proxies.add("127.0.0.1:0")

        # Sort proxies for consistency
        sorted_proxies = sorted(list(all_proxies))

        # Write to file
        with open(self.proxy_file, 'w') as f:
            # Write comments first
            for comment in comments:
                f.write(f"{comment}\n")

            # Add new comment if we added proxies
            if len(proxies - existing_entries) > 0:
                f.write(f"# Added {len(proxies - existing_entries)} new proxies on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

            # Write proxies
            for proxy in sorted_proxies:
                f.write(f"{proxy}\n")

        logger.info(f"Saved {len(all_proxies)} proxies to {self.proxy_file}")

    async def test_proxy(self, proxy: str) -> bool:
        """Test if a proxy is working by making HTTP requests to test URLs"""
        host, port = proxy.split(':')
        port = int(port)

        # Skip testing direct connection
        if host == "127.0.0.1" and port == 0:
            return True

        proxy_url = f"http://{host}:{port}"

        for test_url in TEST_URLS:
            for attempt in range(MAX_ATTEMPTS):
                try:
                    # Set up timeout and headers
                    timeout = ClientTimeout(total=self.timeout)

                    # Try to connect through the proxy
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(test_url, proxy=proxy_url,
                                              headers={'User-Agent': 'Mozilla/5.0'}) as response:
                            if response.status == 200:
                                # Read a bit of the response to ensure it's a valid proxy
                                content = await response.text(encoding='utf-8', errors='ignore')
                                if len(content) > 100:  # Ensure we got a real response
                                    return True
                except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError,
                       socket.gaierror) as e:
                    logger.debug(f"Proxy test failed for {proxy}: {str(e)}")
                    await asyncio.sleep(0.1)
                    continue

        return False

    async def check_proxy(self, host: str, port: int, semaphore: asyncio.Semaphore) -> Optional[str]:
        """Check if a specific host:port combination is an open proxy"""
        proxy_str = f"{host}:{port}"

        async with semaphore:
            self.stats['ports_scanned'] += 1

            try:
                # Try to connect to the port first
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()

                # If we can connect, test it as a proxy
                self.stats['proxies_tested'] += 1
                if await self.test_proxy(proxy_str):
                    logger.info(f"Found working proxy: {proxy_str}")
                    self.stats['working_proxies'] += 1

                    # If we have an app context, add to database
                    if self.app:
                        # Check if proxy already exists in the database
                        existing = None
                        # Use synchronous context manager instead of async
                        with self.app.app_context():
                            existing = Proxy.query.filter_by(host=host, port=port).first()

                        if existing:
                            logger.debug(f"Proxy already in database: {proxy_str}")
                            self.stats['existing_proxies'] += 1
                        else:
                            # Add to database using synchronous context manager
                            with self.app.app_context():
                                new_proxy = Proxy(
                                    host=host,
                                    port=port,
                                    is_working=True,
                                    last_tested=datetime.utcnow(),
                                    response_time=self.timeout / 2,  # Estimate response time
                                    created_at=datetime.utcnow()
                                )
                                db.session.add(new_proxy)
                                db.session.commit()
                                self.stats['new_proxies'] += 1
                                logger.info(f"Added new proxy to database: {proxy_str}")

                    return proxy_str
                else:
                    logger.debug(f"Proxy test failed for {proxy_str}")
                    self.stats['failed_proxies'] += 1
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                logger.debug(f"Connection failed to {proxy_str}: {e.__class__.__name__}")

            return None

    async def scan_ip(self, ip: str, semaphore: asyncio.Semaphore) -> List[str]:
        """Scan a single IP for open proxy ports"""
        tasks = []
        working_proxies = []

        # Try common proxy ports
        for port in HTTP_PROXY_PORTS:
            task = asyncio.create_task(self.check_proxy(ip, port, semaphore))
            tasks.append(task)

        # Wait for all tasks to complete
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                working_proxies.append(result)

        return working_proxies

    async def scan_random_ips(self, batch_size: int = 100) -> Dict:
        """Scan random IPs across the internet for open proxy ports"""
        # Reset or initialize stats
        if not self.stats['start_time']:
            self.stats['start_time'] = time.time()

        # Generate random IPs
        ips = self.generate_random_ips(batch_size)
        self.stats['ips_scanned'] += len(ips)

        # Create semaphore for limiting concurrent connections
        semaphore = asyncio.Semaphore(self.max_concurrent)

        # Scan each IP
        tasks = []
        for ip in ips:
            task = asyncio.create_task(self.scan_ip(ip, semaphore))
            tasks.append(task)

        # Wait for all tasks to complete
        working_proxies = set()
        for task in asyncio.as_completed(tasks):
            proxies = await task
            working_proxies.update(proxies)

        # Save results
        if working_proxies:
            existing_proxies = await self.load_existing_proxies()
            new_proxies = working_proxies - existing_proxies

            if new_proxies:
                await self.save_proxies(working_proxies)

        # Update end time
        self.stats['end_time'] = time.time()
        self.stats['newly_found'] = self.stats['new_proxies']

        return self.stats

    async def continuous_scan(self, num_batches: int = 10, batch_size: int = 100,
                             delay_between_batches: float = 2.0) -> Dict:
        """Run a continuous scan for a specified number of batches"""
        # Reset stats
        self.stats = {
            'start_time': time.time(),
            'end_time': None,
            'ips_scanned': 0,
            'ports_scanned': 0,
            'proxies_tested': 0,
            'working_proxies': 0,
            'new_proxies': 0,
            'existing_proxies': 0,
            'failed_proxies': 0,
            'newly_found': 0
        }

        # Run batches
        for i in range(num_batches):
            logger.info(f"Starting batch {i+1}/{num_batches} of {batch_size} IPs")
            await self.scan_random_ips(batch_size)

            # Log progress
            elapsed = time.time() - self.stats['start_time']
            logger.info(f"Batch {i+1}/{num_batches} complete. " +
                      f"Found {self.stats['working_proxies']} working proxies " +
                      f"({self.stats['new_proxies']} new) in {elapsed:.1f}s")

            # Delay between batches
            if i < num_batches - 1:
                await asyncio.sleep(delay_between_batches)

        # Final stats
        self.stats['end_time'] = time.time()
        self.stats['elapsed_time'] = self.stats['end_time'] - self.stats['start_time']

        # Log results
        logger.info(f"Scan complete. Scanned {self.stats['ips_scanned']} IPs " +
                  f"and {self.stats['ports_scanned']} ports in {self.stats['elapsed_time']:.1f}s")
        logger.info(f"Found {self.stats['working_proxies']} working proxies " +
                  f"({self.stats['new_proxies']} new)")

        # Log to database if we have an app context
        if self.app:
            with self.app.app_context():
                proxy_log = ProxyLog(
                    scan_type='internet',
                    proxies_tested=self.stats['ports_scanned'],
                    proxies_found=self.stats['new_proxies'],
                    scan_duration=self.stats['elapsed_time']
                )
                db.session.add(proxy_log)
                db.session.commit()

        return self.stats


async def main():
    """Run a standalone proxy scan"""
    scanner = InternetProxyScanner()
    await scanner.continuous_scan(num_batches=5, batch_size=50)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
