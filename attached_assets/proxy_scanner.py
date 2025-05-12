#!/usr/bin/env python3
"""
Proxy Scanner module for discovering and testing HTTP proxies
Automatically scans and tests proxies for use with the telnet scanner
"""
import asyncio
import random
import aiofiles
import aiohttp
import ipaddress
import logging
import time
from datetime import datetime
from contextlib import suppress

logger = logging.getLogger("ProxyScanner")

# List of proxy verification services to test against
PROXY_TEST_URLS = [
    "http://httpbin.org/ip",
    "http://ip-api.com/json/",
    "http://ifconfig.me/ip"
]

class ProxyScanner:
    """
    Scans for and tests HTTP proxies
    Features:
    - Auto-discovery of proxies
    - Testing of proxy functionality
    - Proxy list management
    """
    
    def __init__(self, proxy_file="proxies.txt", max_concurrent=20, connect_timeout=5.0):
        """Initialize the proxy scanner"""
        self.proxy_file = proxy_file
        self.connect_timeout = connect_timeout
        self.max_concurrent = max_concurrent
        self.working_proxies = set()
        self.scanned_proxies = set()
        self.file_lock = asyncio.Lock()
        
    async def load_existing_proxies(self):
        """Load existing proxies from the proxy file"""
        try:
            existing = set()
            if os.path.exists(self.proxy_file):
                async with aiofiles.open(self.proxy_file, "r") as f:
                    async for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            existing.add(line)
            return existing
        except Exception as e:
            logger.error(f"Error loading existing proxies: {e}")
            return set()
            
    async def save_proxies(self, proxies):
        """Save proxies to the proxy file, preserving comments"""
        try:
            comments = []
            # First read any comments from the existing file
            if os.path.exists(self.proxy_file):
                async with aiofiles.open(self.proxy_file, "r") as f:
                    async for line in f:
                        line = line.strip()
                        if line.startswith("#"):
                            comments.append(line)
            
            # Now write the file with comments at the top
            async with self.file_lock:
                async with aiofiles.open(self.proxy_file, "w") as f:
                    # Write comments first
                    for comment in comments:
                        await f.write(f"{comment}\n")
                    
                    # Add header if no comments exist
                    if not comments:
                        await f.write("# Proxy list for telnet scanner - Auto-updated by ProxyScanner\n")
                        await f.write("# Format: ip:port\n")
                        await f.write("# Last updated: {}\n\n".format(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ))
                    
                    # Write proxies
                    for proxy in sorted(proxies):
                        await f.write(f"{proxy}\n")
                        
            logger.info(f"Saved {len(proxies)} proxies to {self.proxy_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving proxies: {e}")
            return False
    
    async def test_proxy(self, proxy):
        """Test if a proxy is working by making HTTP requests to test URLs"""
        if ":" not in proxy:
            return False
            
        ip, port = proxy.split(":")
        
        # Skip already validated proxies
        if proxy in self.working_proxies:
            return True
            
        # Skip proxies we've already tested and found not working
        if proxy in self.scanned_proxies:
            return False
            
        self.scanned_proxies.add(proxy)
        
        # Try connecting to different test URLs
        for test_url in random.sample(PROXY_TEST_URLS, min(2, len(PROXY_TEST_URLS))):
            try:
                proxy_url = f"http://{proxy}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        test_url, 
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=self.connect_timeout)
                    ) as response:
                        if response.status == 200:
                            logger.debug(f"Proxy {proxy} is working with {test_url}")
                            self.working_proxies.add(proxy)
                            return True
            except Exception as e:
                logger.debug(f"Proxy test failed for {proxy} with {test_url}: {e}")
                continue
                
        return False
        
    async def scan_network_range(self, cidr, ports=[8080, 3128, 8118, 80, 8888]):
        """Scan a network range for open proxy ports"""
        try:
            logger.info(f"Scanning network range {cidr} for proxies on ports {ports}")
            
            # Parse CIDR notation
            network = ipaddress.ip_network(cidr, strict=False)
            
            # For large networks, limit the scan
            if network.num_addresses > 256:
                logger.warning(f"Network {cidr} is too large, limiting scan to 256 hosts")
                hosts = [str(ip) for ip in list(network.hosts())[:256]]
            else:
                hosts = [str(ip) for ip in network.hosts()]
                
            found_proxies = set()
            scan_semaphore = asyncio.Semaphore(self.max_concurrent)
            
            # Create tasks for scanning each host:port combination
            tasks = []
            for host in hosts:
                for port in ports:
                    tasks.append(self.check_proxy(host, port, scan_semaphore, found_proxies))
                    
            # Wait for all tasks to complete
            await asyncio.gather(*tasks)
            
            logger.info(f"Found {len(found_proxies)} proxies in network {cidr}")
            return found_proxies
        except Exception as e:
            logger.error(f"Error scanning network range {cidr}: {e}")
            return set()
            
    async def check_proxy(self, host, port, semaphore, found_proxies):
        """Check if a specific host:port combination is an open proxy"""
        proxy = f"{host}:{port}"
        
        async with semaphore:
            try:
                # First check if the port is open with a simple connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0  # Quick timeout for port check
                )
                
                # If we can connect, close the connection and test as a proxy
                writer.close()
                await writer.wait_closed()
                
                # Now test if it's a working proxy
                if await self.test_proxy(proxy):
                    logger.info(f"Found working proxy: {proxy}")
                    found_proxies.add(proxy)
                    
            except (asyncio.TimeoutError, ConnectionRefusedError):
                # Port is closed or filtered, skip silently
                pass
            except Exception as e:
                logger.debug(f"Error checking {proxy}: {e}")
                
    async def discover_common_proxies(self):
        """
        Scan local networks and common proxy ranges
        Returns a set of discovered proxies
        """
        # Common CIDR ranges where proxies might be found
        # These are examples - in practice you'd want to be more selective
        common_ranges = [
            "10.0.0.0/24",      # Local network
            "192.168.0.0/24",   # Local network
            "172.16.0.0/24"     # Local network
        ]
        
        all_found = set()
        
        for cidr in common_ranges:
            found = await self.scan_network_range(cidr)
            all_found.update(found)
            
        return all_found
        
    async def bulk_test_proxies(self, proxy_list):
        """Test multiple proxies in parallel"""
        if not proxy_list:
            return []
            
        logger.info(f"Testing {len(proxy_list)} proxies...")
        
        # Use semaphore to limit concurrent tests
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def test_with_semaphore(proxy):
            async with semaphore:
                result = await self.test_proxy(proxy)
                return (proxy, result)
                
        # Create test tasks
        tasks = [test_with_semaphore(proxy) for proxy in proxy_list]
        results = await asyncio.gather(*tasks)
        
        # Filter working proxies
        working = [proxy for proxy, result in results if result]
        
        logger.info(f"Found {len(working)}/{len(proxy_list)} working proxies")
        return working
        
    async def run_scan(self):
        """Run a complete proxy scan and update the proxy list"""
        # Load existing proxies
        existing = await self.load_existing_proxies()
        logger.info(f"Loaded {len(existing)} existing proxies from {self.proxy_file}")
        
        # Test existing proxies
        existing_working = set(await self.bulk_test_proxies(existing))
        logger.info(f"{len(existing_working)}/{len(existing)} existing proxies are working")
        
        # Discover new proxies
        new_discovered = await self.discover_common_proxies()
        logger.info(f"Discovered {len(new_discovered)} new potential proxies")
        
        # Combine all proxies
        all_proxies = existing_working.union(new_discovered)
        
        # Direct connection option (always add this)
        if "127.0.0.1:0" not in all_proxies:
            all_proxies.add("127.0.0.1:0")
            
        # Save updated list
        await self.save_proxies(all_proxies)
        
        return {
            "total": len(all_proxies),
            "working_existing": len(existing_working),
            "new_discovered": len(new_discovered),
            "proxies": list(all_proxies)
        }
        
    async def add_and_test_proxy(self, proxy):
        """Add a user-provided proxy and test it"""
        if not proxy or ":" not in proxy:
            return False
            
        # Test the proxy
        is_working = await self.test_proxy(proxy)
        
        if is_working:
            # Load existing proxies
            existing = await self.load_existing_proxies()
            
            # Add the new proxy if not already present
            if proxy not in existing:
                existing.add(proxy)
                await self.save_proxies(existing)
                logger.info(f"Added new working proxy: {proxy}")
                
            return True
        else:
            logger.info(f"Proxy not working: {proxy}")
            return False

# Run as standalone module if executed directly
if __name__ == "__main__":
    import os
    import sys
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Run the scanner
    async def main():
        scanner = ProxyScanner()
        result = await scanner.run_scan()
        print(f"Scan completed: {result['total']} total proxies")
        print(f"Working existing: {result['working_existing']}")
        print(f"Newly discovered: {result['new_discovered']}")
        
    asyncio.run(main())