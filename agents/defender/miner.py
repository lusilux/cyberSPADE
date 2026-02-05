"""
Version Miner Agent - Network Defender Swarm
Part 2 of the defensive pipeline

Responsibilities:
- Receive service enumeration from Scan Agent
- Extract software version information from service banners
- Normalize version strings for consistent CVE lookup
- Cache version data to optimize repeated queries
- Forward enriched service data to Vulnerability Checker Agent

Metrics collected:
- Number of services processed
- Versions successfully extracted
- Cache hit rate
- Processing time
"""

import json
import logging
import re
import time
from datetime import datetime
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# ═══════════════════════════════════════════════════════════════════════════
# VERSION EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def extract_version(service, banner):
    """
    Extract version string from service banner using regex patterns
    
    Args:
        service: Service type identifier (e.g., 'nginx', 'ssh', 'mysql')
        banner: Raw banner text captured during scanning
    
    Returns:
        Normalized version string or 'unknown' if extraction fails
    """
    banner = banner or ""
    
    try:
        # Service-specific extraction patterns
        if service == "nginx":
            match = re.search(r"nginx/([\d\.p]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service in ["apache", "http"]:
            match = re.search(r"apache/([\d\.]+)", banner, re.I)
            if match:
                return match.group(1)
            # Fallback: look for Server header
            match = re.search(r"server:\s*(apache[\w\.\-/]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service == "ssh":
            match = re.search(r"openssh[_\-]?([\d\.p]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service == "mysql":
            match = re.search(r"mysql[\s\-]?([\d\.]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service in ["postgresql", "postgres"]:
            match = re.search(r"postgresql[\s\-]?([\d\.]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service in ["xmpp-client", "xmpp-server"]:
            # XMPP typically doesn't expose version in banner
            return "unknown"
        
        elif service in ["http", "http-proxy"]:
            # Generic HTTP server detection
            match = re.search(r"server:\s*([\w\.\-/]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        elif service == "zeus-admin":
            match = re.search(r"zeus/([\d\.]+)", banner, re.I)
            return match.group(1) if match else "unknown"
        
        else:
            return "unknown"
    
    except Exception as e:
        logging.debug(f"Version extraction error for {service}: {e}")
        return "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# RESULTS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

def print_version_results(results, processing_time, cache_hits, cache_total):
    """
    Pretty print version mining results with metrics
    
    Args:
        results: List of version extraction results
        processing_time: Time taken for processing
        cache_hits: Number of cache hits
        cache_total: Total cache lookups attempted
    """
    if not results:
        print("\n⚠ No version data to display")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cache_rate = (cache_hits / cache_total * 100) if cache_total > 0 else 0
    
    print("\n" + "╔" + "="*98 + "╗")
    print("║" + " "*35 + "VERSION MINING RESULTS" + " "*41 + "║")
    print("╚" + "="*98 + "╝\n")
    
    print(f"Mining Timestamp: {timestamp}")
    print(f"Processing Time: {processing_time:.2f} seconds")
    print(f"\n{'─'*100}")
    print(f"Services Processed:         {len(results):>10}")
    print(f"Versions Extracted:         {sum(1 for r in results if r.get('version') != 'unknown'):>10}")
    print(f"Cache Hit Rate:             {cache_rate:>9.1f}%")
    print(f"Throughput:                 {len(results)/processing_time if processing_time > 0 else 0:>9.1f} services/sec")
    print(f"{'─'*100}\n")
    
    print(f"{'PORT':<10} {'SERVICE':<20} {'VERSION':<20} {'BANNER (truncated)':<50}")
    print("─"*100)
    
    for item in results:
        port = str(item.get('port', 'N/A'))
        service = item.get('service', 'unknown')[:19]
        version = item.get('version', 'unknown')[:19]
        banner = item.get('banner', '') or ''
        
        # Clean banner
        banner_clean = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in banner)
        banner_clean = banner_clean.replace("\r", " ").replace("\n", " ")
        banner_clean = banner_clean[:50]
        
        print(f"{port:<10} {service:<20} {version:<20} {banner_clean:<50}")
    
    print("─"*100)
    
    # Version extraction summary
    version_stats = {}
    for r in results:
        v = r.get('version', 'unknown')
        version_stats[v] = version_stats.get(v, 0) + 1
    
    print(f"\n📊 Version Extraction Statistics:")
    for version, count in sorted(version_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"   • {version}: {count} service(s)")
    
    print()


# ═══════════════════════════════════════════════════════════════════════════
# VERSION MINER AGENT - SPADE IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════

class VersionMinerAgent(Agent):
    """
    Service version extraction agent
    
    Receives service data from ScanAgent and extracts version information
    for vulnerability assessment.
    """
    
    class MineVersionBehaviour(CyclicBehaviour):
        """
        Main version extraction loop
        
        Processes incoming service enumeration data and extracts
        version information from banners.
        """
        
        async def run(self):
            """Process incoming scan results and extract versions"""
            msg = await self.receive(timeout=10)
            
            if not msg:
                return
            
            sender = str(msg.sender).split('@')[0]
            
            # Record start time
            mining_start = time.perf_counter()
            
            logging.info("╔" + "═"*78 + "╗")
            logging.info("║" + " "*20 + "VERSION MINER - Network Defender Swarm" + " "*19 + "║")
            logging.info("╚" + "═"*78 + "╝")
            logging.info(f"Received service data from {sender}")

            try:
                data = json.loads(msg.body)
                ports_info = data.get("ports", [])
                scan_metrics = data.get("metrics", {})
            except Exception as e:
                logging.error(f"JSON parsing error: {e}")
                return

            logging.info(f"Processing {len(ports_info)} services...")
            
            # Initialize cache metrics
            cache_hits = 0
            cache_total = 0
            
            results = []
            for item in ports_info:
                ip = item.get("ip")
                port = item.get("port")
                service = item.get("service")
                banner = item.get("banner")

                # Check cache first
                cache_key = (ip, port)
                cache_total += 1
                
                if cache_key in self.agent.version_cache:
                    version = self.agent.version_cache[cache_key]
                    cache_hits += 1
                else:
                    # Extract version from banner
                    version = extract_version(service, banner)
                    self.agent.version_cache[cache_key] = version

                results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "banner": banner
                })
            
            # Calculate processing time
            mining_time = time.perf_counter() - mining_start

            # Display results
            print_version_results(results, mining_time, cache_hits, cache_total)

            # Prepare message for Vulnerability Checker
            out_msg = Message(to="checker@localhost")
            out_msg.set_metadata("performative", "inform")
            out_msg.set_metadata("stage", "mining")
            out_msg.set_metadata("timestamp", datetime.now().isoformat())
            out_msg.body = json.dumps(results)
            
            await self.send(out_msg)
            
            logging.info(f"→ Forwarded {len(results)} enriched service records to Vulnerability Checker")
            logging.info(f"→ Mining Time: {mining_time:.2f}s")
            logging.info(f"→ Cache Efficiency: {cache_hits}/{cache_total} hits ({cache_hits/cache_total*100 if cache_total > 0 else 0:.1f}%)")
            logging.info("═"*80 + "\n")

    async def setup(self):
        """Agent initialization"""
        logging.info("╔" + "="*78 + "╗")
        logging.info("║" + " "*22 + "VERSION MINER AGENT STARTING" + " "*27 + "║")
        logging.info("╚" + "="*78 + "╝")
        logging.info("")
        logging.info("Initializing version extraction cache...")
        
        # Initialize version cache
        # Cache structure: {(ip, port): version_string}
        self.version_cache = {}
        
        logging.info("Cache initialized successfully")
        logging.info("Version Miner Agent ready to process service data")
        logging.info("")
        
        # Attach mining behavior
        self.add_behaviour(self.MineVersionBehaviour())
