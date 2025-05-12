"""
Basic Proxy Scanner
Scans popular proxy lists and subnet ranges for HTTP proxies
"""

import asyncio
import ipaddress
import logging
import random
import socket
import time
from datetime import datetime
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s [%(levelname)s] ProxyScanner: %(message)s',
                   datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 5.0  # seconds
DEFAULT_CONCURRENCY = 50
PROXY_PORTS = [80, 8080, 3128, 8000, 8888, 8118, 1080, 8081, 53281]
TEST_URLS = [
    'http://www.example.com',
    'http://www.google.com'
]

# Common proxy subnet ranges (local and data center ranges)
PROXY_SUBNETS = [
    '163.172.0.0/16',  # OVH
    '51.15.0.0/16',    # Scaleway
    '91.121.0.0/16',   # OVH
    '149.56.0.0/16',   # OVH Canada
    '167.71.0.0/16',   # DigitalOcean
    '138.68.0.0/16',   # DigitalOcean
    '165.227.0.0/16',  # DigitalOcean
    '46.101.0.0/16',   # DigitalOcean
    '128.199.0.0/16',  # DigitalOcean
    '159.203.0.0/16',  # DigitalOcean
    '104.131.0.0/16',  # DigitalOcean
    '192.241.0.0/16',  # DigitalOcean
    '45.55.0.0/16',    # DigitalOcean
]


class ProxyScanner:
    """Basic proxy scanner that checks common data center subnets for proxies"""
    
    def __init__(self, max_concurrency=DEFAULT_CONCURRENCY, timeout=DEFAULT_TIMEOUT):
        """Initialize the scanner"""
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.found_proxies = set()
    
    async def test_proxy(self, host, port):
        """Test if a host:port combination works as an HTTP proxy"""
        proxy_url = f"http://{host}:{port}"
        
        try:
            # Set timeout
            timeout = ClientTimeout(total=self.timeout)
            
            # Try to connect through the proxy
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for test_url in TEST_URLS:
                    try:
                        async with session.get(test_url, proxy=proxy_url, 
                                              headers={'User-Agent': 'Mozilla/5.0'}) as response:
                            if response.status == 200:
                                # Read a bit of the response to ensure it's a valid proxy
                                content = await response.text(encoding='utf-8', errors='ignore')
                                if len(content) > 100:  # Ensure we got a real response
                                    logger.info(f"Found working proxy: {host}:{port}")
                                    self.found_proxies.add(f"{host}:{port}")
                                    return True
                    except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeDecodeError):
                        continue
        except (aiohttp.ClientError, asyncio.TimeoutError, socket.gaierror):
            pass
        
        return False
    
    async def scan_ip(self, ip, semaphore):
        """Scan a single IP for proxy ports"""
        async with semaphore:
            for port in PROXY_PORTS:
                # Quick connection check first
                try:
                    # Try to connect to the port
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=1.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    # If we can connect, test it as a proxy
                    await self.test_proxy(ip, port)
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass  # Connection failed, skip this port
    
    async def scan_subnet(self, subnet_str):
        """Scan a subnet for proxy servers"""
        try:
            network = ipaddress.ip_network(subnet_str)
            logger.info(f"Scanning subnet {subnet_str} ({network.num_addresses} addresses)")
            
            # Create semaphore for limiting concurrent connections
            semaphore = asyncio.Semaphore(self.max_concurrency)
            
            # For large subnets, take a sample
            if network.num_addresses > 1000:
                # Generate random IPs within the subnet
                all_ips = list(network.hosts())
                sample_size = min(1000, len(all_ips))
                sample_ips = random.sample(all_ips, sample_size)
                logger.info(f"Taking a sample of {sample_size} IPs from {subnet_str}")
            else:
                sample_ips = list(network.hosts())
            
            # Start tasks to scan each IP
            tasks = []
            for ip in sample_ips:
                task = asyncio.create_task(self.scan_ip(str(ip), semaphore))
                tasks.append(task)
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks)
            
            logger.info(f"Finished scanning subnet {subnet_str}")
        
        except ValueError as e:
            logger.error(f"Invalid subnet: {subnet_str} - {str(e)}")
    
    async def run_scan(self):
        """Run the proxy scanner"""
        start_time = time.time()
        logger.info("Starting proxy scan")
        
        # Reset found proxies
        self.found_proxies = set()
        
        # Create tasks for scanning each subnet
        tasks = []
        for subnet in PROXY_SUBNETS:
            task = asyncio.create_task(self.scan_subnet(subnet))
            tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        # Ensure direct connection is always available
        self.found_proxies.add("127.0.0.1:0")
        
        # Done
        elapsed = time.time() - start_time
        logger.info(f"Scan completed in {elapsed:.1f} seconds")
        logger.info(f"Found {len(self.found_proxies)} working proxies")
        
        return {
            'proxies': list(self.found_proxies),
            'total': len(PROXY_SUBNETS) * 1000,  # Approximate
            'time': elapsed
        }


async def main():
    """Run a standalone proxy scan"""
    scanner = ProxyScanner()
    result = await scanner.run_scan()
    
    print("\nFound Proxies:")
    for proxy in sorted(result['proxies']):
        print(proxy)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())