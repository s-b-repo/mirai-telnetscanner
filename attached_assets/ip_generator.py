"""
IP Generator module for creating batches of random IPs for scanning
"""
import random
import ipaddress
import logging

logger = logging.getLogger("TelnetScanner.IPGenerator")

class IPGenerator:
    """Generates random IP addresses for scanning, avoiding reserved ranges"""
    
    def __init__(self):
        """Initialize the IP generator with reserved networks"""
        self.reserved_networks = [
            ipaddress.ip_network("0.0.0.0/8"),        # Current network
            ipaddress.ip_network("10.0.0.0/8"),       # Private network
            ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
            ipaddress.ip_network("127.0.0.0/8"),      # Localhost
            ipaddress.ip_network("169.254.0.0/16"),   # Link-local
            ipaddress.ip_network("172.16.0.0/12"),    # Private network
            ipaddress.ip_network("192.0.0.0/24"),     # IETF protocol assignments
            ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
            ipaddress.ip_network("192.88.99.0/24"),   # IPv6 to IPv4 relay
            ipaddress.ip_network("192.168.0.0/16"),   # Private network
            ipaddress.ip_network("198.18.0.0/15"),    # Network benchmark tests
            ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
            ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
            ipaddress.ip_network("224.0.0.0/4"),      # Multicast
            ipaddress.ip_network("240.0.0.0/4"),      # Reserved for future use
            ipaddress.ip_network("255.255.255.255/32")  # Broadcast
        ]
        
        # Cached list of previously generated IPs to avoid immediate duplicates
        self.recent_ips = set()
        self.max_recent = 10000  # Maximum number of recent IPs to remember
    
    def get_random_ips(self, count):
        """Generate a batch of random IPs that aren't in reserved networks"""
        ip_batch = set()
        attempts = 0
        max_attempts = count * 10  # Limit attempts to avoid infinite loop
        
        while len(ip_batch) < count and attempts < max_attempts:
            attempts += 1
            
            # Generate random IP as integer (more efficient)
            ip_int = random.randint(1, (2**32)-2)  # Exclude 0.0.0.0 and 255.255.255.255
            
            # Convert to IPv4Address object
            ip = ipaddress.IPv4Address(ip_int)
            
            # Skip if in reserved network or recently used
            if self._is_reserved(ip) or str(ip) in self.recent_ips:
                continue
                
            ip_batch.add(str(ip))
            
            # Add to recent IPs and maintain max size
            self.recent_ips.add(str(ip))
            if len(self.recent_ips) > self.max_recent:
                self.recent_ips.pop()
        
        logger.debug(f"Generated {len(ip_batch)} IPs in {attempts} attempts")
        return list(ip_batch)
    
    def _is_reserved(self, ip):
        """Check if IP is in a reserved network"""
        return any(ip in network for network in self.reserved_networks)

    def get_targeted_ips(self, prefix, count):
        """Generate IPs within a specific prefix (CIDR notation)"""
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            hosts = list(network.hosts())
            
            if count >= len(hosts):
                return [str(ip) for ip in hosts]
            
            # Select random IPs from the network
            selected = random.sample(hosts, count)
            return [str(ip) for ip in selected]
            
        except Exception as e:
            logger.error(f"Invalid network prefix {prefix}: {e}")
            return []
