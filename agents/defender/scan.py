"""
Scan Agent - Network Defender Swarm
Part 1 of the defensive pipeline

Responsibilities:
- Asynchronous TCP port scanning across full port range (1-65535)
- Banner grabbing for service identification
- Concurrent connection management (300 simultaneous connections)
- Forward results to Version Miner Agent

Metrics collected:
- Scan start/end time
- Number of ports scanned
- Number of open ports detected
- Scanning throughput (ports/second)
"""

import asyncio
import json
import socket
import ssl
import logging
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
# BANNER PROCESSING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def clean_banner(banner):
    """Clean banner text for display (remove control characters)"""
    if not banner:
        return ""
    banner = banner.replace("\r", " ").replace("\n", " ")
    banner = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in banner)
    return banner[:150]


# ═══════════════════════════════════════════════════════════════════════════
# TCP SCANNING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

async def tcp_port_open(ip, port, timeout=0.5):
    """
    Asynchronous TCP port connectivity check
    Uses asyncio.open_connection for non-blocking I/O
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


def grab_banner(ip, port, timeout=1.0):
    """
    Protocol-specific banner grabbing
    Supports: HTTP, HTTPS, SSH, XMPP, SMTP, FTP, POP3, IMAP
    """
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))

        # -------- HTTPS (Port 443) --------
        if port == 443:
            ctx = ssl.create_default_context()
            ss = ctx.wrap_socket(s, server_hostname=ip)
            ss.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return ss.recv(4096).decode(errors="ignore")

        # -------- XMPP CLIENT (Port 5222) --------
        if port == 5222:
            s.send(b"<stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>")
            return s.recv(4096).decode(errors="ignore")

        # -------- XMPP SERVER (Port 5269) --------
        if port == 5269:
            s.send(b"<stream:stream to='localhost' xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'>")
            return s.recv(4096).decode(errors="ignore")

        # -------- SSH (Port 22) --------
        if port == 22:
            return s.recv(4096).decode(errors="ignore")

        # -------- HTTP Variants --------
        if port in (80, 8080, 8000, 8888):
            s.send(b"GET / HTTP/1.0\r\n\r\n")
            return s.recv(4096).decode(errors="ignore")

        # -------- Mail Protocols --------
        if port in (21, 25, 110, 143):  # FTP, SMTP, POP3, IMAP
            return s.recv(4096).decode(errors="ignore")

        # -------- Generic --------
        try:
            s.send(b"\r\n")
        except:
            pass

        return s.recv(4096).decode(errors="ignore")

    except:
        return ""
    finally:
        try:
            s.close()
        except:
            pass


def identify_service(port, banner):
    """
    Service identification based on banner and port number
    Returns: Service name string
    """
    b = (banner or "").lower()

    # Banner-based identification
    if "<stream:stream" in b or "xmpp" in b or "jabber" in b:
        return "xmpp-client" if port == 5222 else "xmpp-server"
    if b.startswith("ssh-") or "openssh" in b:
        return "ssh"
    if "http" in b or "server:" in b or "http/1." in b or "nginx" in b or "apache" in b:
        return "http"
    if "ftp" in b:
        return "ftp"
    if "smtp" in b or "esmtp" in b:
        return "smtp"
    if "mysql" in b:
        return "mysql"
    if "postgres" in b or "postgresql" in b:
        return "postgresql"
    if "zeus" in b or "jetty" in b:
        return "zeus-admin"

    # Port-based fallback
    common_ports = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        5222: "xmpp-client",
        5269: "xmpp-server",
        8080: "http-proxy",
        9090: "zeus-admin"
    }

    return common_ports.get(port, "unknown")


# ═══════════════════════════════════════════════════════════════════════════
# RESULTS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

def print_scan_results(open_ports, scan_time, total_ports):
    """Pretty print scan results with metrics"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print("\n" + "╔" + "="*88 + "╗")
    print("║" + " "*28 + "NETWORK SCAN RESULTS" + " "*40 + "║")
    print("╚" + "="*88 + "╝\n")
    
    print(f"Scan Timestamp: {timestamp}")
    print(f"Target: 127.0.0.1 (localhost)")
    print(f"Port Range: 1-{total_ports}")
    print(f"\n{'─'*90}")
    print(f"Total Ports Scanned:        {total_ports:>15,}")
    print(f"Open Ports Detected:        {len(open_ports):>15}")
    print(f"Scan Duration:              {scan_time:>14.2f} seconds")
    print(f"Throughput:                 {total_ports/scan_time:>14,.0f} ports/second")
    print(f"{'─'*90}\n")
    
    if open_ports:
        print(f"{'PORT':<10} {'SERVICE':<20} {'BANNER (truncated)':<60}")
        print("─"*90)
        
        for p in open_ports:
            port = str(p["port"])
            service = p["service"]
            banner = clean_banner(p["banner"])
            print(f"{port:<10} {service:<20} {banner:<60}")
        
        print("─"*90)
    else:
        print("⚠ No open ports detected")
    
    print()


# ═══════════════════════════════════════════════════════════════════════════
# SCAN AGENT - SPADE IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════

class ScanAgent(Agent):
    class ScanBehaviour(CyclicBehaviour):
        
        async def scan_port(self, ip, port, sem):
            """
            Scan a single port with semaphore-controlled concurrency
            
            Args:
                ip: Target IP address
                port: Port number to scan
                sem: Asyncio semaphore for concurrency control
                
            Returns:
                Dict with port info if open, None otherwise
            """
            async with sem:
                if await tcp_port_open(ip, port):
                    # Port is open - grab banner
                    banner = await asyncio.to_thread(grab_banner, ip, port)
                    service = identify_service(port, banner)

                    return {
                        "ip": ip,
                        "port": port,
                        "banner": banner,
                        "service": service
                    }
                return None

        async def run(self):
            """Main scanning loop"""
            ip = "127.0.0.1"
            total_ports = 65535
            open_ports = []

            logging.info("╔═══════════════════════════════════════════════════════════════╗")
            logging.info("║            SCAN AGENT - Network Defender Swarm                ║")
            logging.info("╚═══════════════════════════════════════════════════════════════╝")
            logging.info(f"Target: {ip}")
            logging.info(f"Port Range: 1-{total_ports}")
            logging.info(f"Concurrent Connections: 300")
            logging.info("Starting scan...")
            
            # Start timing
            scan_start = time.perf_counter()
            
            # Create semaphore for concurrent connection limit
            sem = asyncio.Semaphore(300)

            # Create scan tasks for all ports
            tasks = [
                self.scan_port(ip, port, sem)
                for port in range(1, total_ports + 1)
            ]

            # Execute all scans concurrently
            logging.info(f"Scanning {total_ports:,} ports concurrently...")
            results = await asyncio.gather(*tasks)

            # Filter out None results (closed ports)
            open_ports = [r for r in results if r]
            
            # End timing
            scan_end = time.perf_counter()
            scan_time = scan_end - scan_start

            logging.info(f"✓ Scan complete: {len(open_ports)} open ports detected in {scan_time:.2f}s")
            
            # Display results
            print_scan_results(open_ports, scan_time, total_ports)

            # Send results to Version Miner Agent
            msg = Message(to="miner@localhost")
            msg.set_metadata("performative", "inform")
            msg.set_metadata("stage", "scan")
            msg.set_metadata("timestamp", datetime.now().isoformat())
            msg.body = json.dumps({
                "ports": open_ports,
                "metrics": {
                    "total_ports": total_ports,
                    "open_ports": len(open_ports),
                    "scan_time": scan_time,
                    "throughput": total_ports/scan_time
                }
            })
            
            await self.send(msg)
            logging.info("→ Results forwarded to Version Miner Agent")
            logging.info("═"*65 + "\n")

            # Wait before next scan cycle
            await asyncio.sleep(60)

    async def setup(self):
        """Agent initialization"""
        logging.info("ScanAgent initialized and ready")
        self.add_behaviour(self.ScanBehaviour())
