"""
Proxy Manager module for handling HTTP proxies
Includes automatic proxy rotation and health checking
"""
import asyncio
import random
import logging
import aiofiles
import socket
import os
import time
import threading
from datetime import datetime, timedelta

logger = logging.getLogger("TelnetScanner.ProxyManager")

class ProxyManager:
    """
    Handles proxy connections and tunnel creation
    Features:
    - Automatic proxy rotation
    - Continuous health checking (every minute)
    - Persistent proxy statistics
    - Fallback to direct connections when needed
    """
    
    def __init__(self, proxy_file="proxies.txt", connect_timeout=5):
        """Initialize the proxy manager"""
        self.proxy_file = proxy_file
        self.connect_timeout = float(connect_timeout)  # Convert to float to ensure compatibility
        self.proxies = []
        self.working_proxies = set()
        self.proxy_stats = {}  # Track stats per proxy
        self.last_refresh = None
        self.refresh_interval = 60  # Check proxies every 60 seconds
        self.refresh_lock = asyncio.Lock()
        self.is_refreshing = False
        self.health_check_thread = None
    
    async def initialize(self):
        """Load and verify proxies and start health check thread"""
        await self.load_proxies()
        
        # Always add direct connection option
        direct_connection = "127.0.0.1:0"
        if direct_connection not in self.proxies:
            self.proxies.append(direct_connection)
        
        if len(self.proxies) == 1 and direct_connection in self.proxies:
            logger.warning("No external proxies available, using direct connections only")
            self.working_proxies = set(self.proxies)
        else:
            # Verify proxies are working
            logger.info(f"Verifying {len(self.proxies)} proxies...")
            await self.refresh_proxies()
            
            working_count = len(self.working_proxies)
            if working_count == 0:
                logger.warning("No working proxies found, using direct connections only")
                # Make sure direct connection is in working proxies
                self.working_proxies = {direct_connection}
            else:
                logger.info(f"Found {working_count}/{len(self.proxies)} working proxies")
        
        # Start continuous health check in a separate thread
        if not self.health_check_thread or not self.health_check_thread.is_alive():
            self.start_health_check_thread()
            
        # Always return True to allow the scanner to run with direct connections
        # even if no external proxies are available
        return True
        
    def start_health_check_thread(self):
        """Start a background thread that continuously checks proxy health"""
        def health_check_worker():
            logger.info("Starting proxy health check thread")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            while True:
                try:
                    # Run the proxy refresh
                    loop.run_until_complete(self.refresh_proxies())
                    
                    # Sleep until next check
                    time.sleep(self.refresh_interval)
                except Exception as e:
                    logger.error(f"Error in health check thread: {e}")
                    time.sleep(10)  # Wait a bit before retrying
                    
        self.health_check_thread = threading.Thread(
            target=health_check_worker, 
            daemon=True,  # Allow the thread to be terminated when the main process exits
            name="ProxyHealthCheck"
        )
        self.health_check_thread.start()
        
    async def refresh_proxies(self):
        """Check all proxies and update the working proxies set"""
        # Use a lock to prevent multiple refreshes at the same time
        if self.is_refreshing:
            return
            
        async with self.refresh_lock:
            try:
                self.is_refreshing = True
                start_time = time.time()
                logger.debug("Refreshing proxy list...")
                
                # Make a copy of the current proxies for testing
                test_proxies = self.proxies.copy()
                
                # Test all proxies in parallel with a semaphore to limit concurrency
                semaphore = asyncio.Semaphore(10)  # Test 10 proxies at a time
                
                async def test_with_semaphore(proxy):
                    async with semaphore:
                        return (proxy, await self.test_proxy(proxy))
                
                # Run all tests
                tasks = [test_with_semaphore(proxy) for proxy in test_proxies]
                results = await asyncio.gather(*tasks)
                
                # Update working proxies set
                self.working_proxies = {proxy for proxy, is_working in results if is_working}
                
                # Always ensure direct connection is available
                if "127.0.0.1:0" not in self.working_proxies:
                    self.working_proxies.add("127.0.0.1:0")
                
                duration = time.time() - start_time
                logger.debug(f"Proxy refresh completed in {duration:.2f}s - {len(self.working_proxies)}/{len(self.proxies)} working")
                
                # Update refresh timestamp
                self.last_refresh = datetime.now()
                
            except Exception as e:
                logger.error(f"Error refreshing proxies: {e}")
            finally:
                self.is_refreshing = False
    
    async def load_proxies(self):
        """Load proxies from file or create default"""
        try:
            if os.path.exists(self.proxy_file):
                async with aiofiles.open(self.proxy_file, "r") as f:
                    proxies = []
                    async for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            proxies.append(line)
                    
                    if not proxies:
                        # File exists but is empty
                        logger.warning(f"Proxy file {self.proxy_file} is empty")
                        self.proxies = ["127.0.0.1:8888"]  # Default local proxy
                    else:
                        self.proxies = proxies
                        logger.info(f"Loaded {len(self.proxies)} proxies from {self.proxy_file}")
            else:
                # If file doesn't exist, create a default one
                logger.warning(f"Proxy file {self.proxy_file} not found")
                async with aiofiles.open(self.proxy_file, "w") as f:
                    await f.write("# Add proxies in format ip:port\n")
                    await f.write("127.0.0.1:8888\n")
                self.proxies = ["127.0.0.1:8888"]  # Default local proxy
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
            self.proxies = ["127.0.0.1:8888"]  # Default local proxy
    
    async def test_proxy(self, proxy):
        """Test if a proxy is working"""
        if proxy == "127.0.0.1:0":  # Placeholder for direct connections
            self.working_proxies.add(proxy)
            return True
            
        try:
            # For HTTP proxy
            if ":" in proxy:
                proxy_ip, proxy_port = proxy.split(":")
                reader, writer = await self.open_http_proxy_tunnel(
                    proxy_ip, int(proxy_port), "example.com", 80
                )
                
                if reader and writer:
                    writer.close()
                    await writer.wait_closed()
                    self.working_proxies.add(proxy)
                    return True
        except Exception as e:
            logger.debug(f"Proxy test failed for {proxy}: {e}")
        
        return False
    
    async def open_http_proxy_tunnel(self, proxy_ip, proxy_port, target_ip, target_port):
        """Open an HTTP proxy tunnel to target"""
        if proxy_ip == "127.0.0.1" and proxy_port == 0:
            # Direct connection (no proxy)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.connect_timeout)
                sock.connect((target_ip, int(target_port)))
                reader, writer = await asyncio.open_connection(
                    sock=sock
                )
                return reader, writer
            except Exception as e:
                logger.debug(f"Direct connection failed to {target_ip}:{target_port}: {e}")
                return None, None
                
        try:
            # Attempt to establish connection to proxy
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_ip, int(proxy_port)),
                timeout=self.connect_timeout
            )
            
            # Prepare CONNECT request
            connect_req = (
                f"CONNECT {target_ip}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_ip}:{target_port}\r\n"
                "User-Agent: Mozilla/5.0 (compatible)\r\n"
                "Proxy-Connection: Keep-Alive\r\n"
                "\r\n"
            )
            
            # Send request and retrieve response
            writer.write(connect_req.encode())
            await writer.drain()
            
            try:
                response = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), 
                    timeout=self.connect_timeout
                )
                
                # Check for successful connection
                if b"200 Connection established" in response or b"200 OK" in response:
                    # Update proxy stats
                    self._update_proxy_stats(f"{proxy_ip}:{proxy_port}", True)
                    return reader, writer
                
                logger.debug(f"Proxy tunnel rejected: {response.decode(errors='ignore')}")
                writer.close()
                await writer.wait_closed()
                self._update_proxy_stats(f"{proxy_ip}:{proxy_port}", False)
                
            except asyncio.TimeoutError:
                logger.debug(f"Timeout waiting for proxy response from {proxy_ip}:{proxy_port}")
                writer.close()
                await writer.wait_closed()
                self._update_proxy_stats(f"{proxy_ip}:{proxy_port}", False)
                
        except Exception as e:
            logger.debug(f"Failed to establish proxy tunnel via {proxy_ip}:{proxy_port}: {e}")
            self._update_proxy_stats(f"{proxy_ip}:{proxy_port}", False)
            
        return None, None
    
    def get_proxy(self):
        """
        Get a working proxy using intelligent rotation
        Features:
        - Prioritizes working proxies
        - Rotates based on proxy score (success rate)
        - Includes occasional testing of non-working proxies for recovery
        - Falls back to direct connection if needed
        """
        # Force a proxy refresh if it's been too long since the last one
        if not self.last_refresh or (datetime.now() - self.last_refresh).total_seconds() > self.refresh_interval*2:
            logger.debug("Forcing proxy refresh due to stale data")
            asyncio.create_task(self.refresh_proxies())
            
        working_proxies = list(self.working_proxies)
        
        # If we have no working proxies, return direct connection
        if not working_proxies:
            return "127.0.0.1:0"  # Direct connection
            
        # Get weighted selection based on proxy score
        weighted_proxies = []
        for proxy in working_proxies:
            if proxy == "127.0.0.1:0":  # Direct connection is always a last resort
                weighted_proxies.append((proxy, 1))
                continue
                
            # Get success rate score for this proxy
            stats = self.proxy_stats.get(proxy, {"success": 0, "failure": 0})
            total = stats["success"] + stats["failure"]
            score = 1  # Default score
            
            if total > 0:
                success_rate = stats["success"] / total
                # Scale score based on success rate - higher success rate means higher weight
                score = max(1, int(10 * success_rate))
                
            weighted_proxies.append((proxy, score))
            
        # Weighted random selection
        options, weights = zip(*weighted_proxies)
        selected_proxy = random.choices(options, weights=weights, k=1)[0]
        
        # Every 10th selection, try a proxy that wasn't working before
        # This helps recover proxies that might be working again
        if random.random() < 0.1 and len(self.proxies) > len(working_proxies):
            # Get a list of proxies that aren't in working_proxies
            non_working = [p for p in self.proxies if p not in self.working_proxies and p != "127.0.0.1:0"]
            if non_working:
                test_proxy = random.choice(non_working)
                logger.debug(f"Testing previously non-working proxy: {test_proxy}")
                # Create a task to test this proxy in the background
                asyncio.create_task(self._test_and_update_proxy(test_proxy))
                
        return selected_proxy
        
    async def _test_and_update_proxy(self, proxy):
        """Test a proxy and update the working set if it's working"""
        result = await self.test_proxy(proxy)
        if result and proxy not in self.working_proxies:
            logger.info(f"Recovered working proxy: {proxy}")
            self.working_proxies.add(proxy)
    
    def _update_proxy_stats(self, proxy, success):
        """Update statistics for a proxy"""
        if proxy not in self.proxy_stats:
            self.proxy_stats[proxy] = {"success": 0, "failure": 0}
        
        if success:
            self.proxy_stats[proxy]["success"] += 1
            # Ensure proxy is in working set
            self.working_proxies.add(proxy)
        else:
            self.proxy_stats[proxy]["failure"] += 1
            
            # If proxy has failed too many times, remove it from working set
            if (self.proxy_stats[proxy]["failure"] > 5 and 
                self.proxy_stats[proxy]["success"] / 
                (self.proxy_stats[proxy]["failure"] + self.proxy_stats[proxy]["success"]) < 0.3):
                if proxy in self.working_proxies:
                    self.working_proxies.remove(proxy)
                    logger.debug(f"Removed unreliable proxy: {proxy}")
