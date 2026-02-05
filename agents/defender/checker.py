"""
Vulnerability Checker Agent - Network Defender Swarm
Part 3 of the defensive pipeline

Responsibilities:
- Receive enriched service data from Version Miner Agent
- Query local vulnerability database for known CVEs
- Fallback to NVD API for missing vulnerability data
- Assess vulnerability severity (CVSS scores)
- Compile comprehensive vulnerability reports
- Forward results to Reporter Agent

Data Sources:
- Local database: data/vuln_db.json (common services)
- NVD API: https://nvd.nist.gov (comprehensive CVE database)

Metrics collected:
- Local DB queries vs NVD API calls
- Vulnerabilities found per service
- Query response times
- CVSS score distribution
"""

import logging
import time
import re
import requests
import json
from datetime import datetime

from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = {"User-Agent": "cyberSPADE-VulnChecker/1.0"}
NVD_DELAY = 1.2  # Seconds between NVD requests (rate limiting)
LOCAL_DB_PATH = "data/vuln_db.json"


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def normalize(text: str) -> str:
    """Normalize text for service matching"""
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def build_cpe(service: str, version: str):
    """
    Build CPE (Common Platform Enumeration) identifier
    
    Args:
        service: Service name
        version: Version string
    
    Returns:
        CPE 2.3 formatted string or None
    
    Note: Some vendors use different names in NVD (e.g., nginx -> f5)
    """
    s = normalize(service)
    
    # Vendor/product mapping for NVD compatibility
    common_map = {
        "apache": ("apache", "http_server"),
        "apache http server": ("apache", "http_server"),
        "nginx": ("f5", "nginx"),
        "openssl": ("openssl", "openssl"),
        "openssh": ("openssh", "openssh"),
        "mysql": ("oracle", "mysql"),
        "mariadb": ("mariadb", "mariadb"),
        "postgresql": ("postgresql", "postgresql"),
        "redis": ("redis", "redis"),
        "samba": ("samba", "samba"),
        "vsftpd": ("vsftpd", "vsftpd"),
        "php": ("php", "php"),
        "python": ("python", "python"),
    }
    
    if s in common_map:
        vendor, product = common_map[s]
    else:
        vendor = s.split()[0] if s else ""
        product = s.replace(" ", "_") if s else ""
    
    if not vendor or not product or not version:
        return None
    
    return f"cpe:2.3:a:{vendor}:{product}:{version}"


def fetch_vulns_for_cpe(cpe):
    """
    Fetch vulnerabilities from NVD API with pagination
    
    Args:
        cpe: CPE identifier string
    
    Returns:
        List of vulnerability records
    """
    results = []
    start_index = 0
    page_size = 200

    while True:
        params = {
            "cpeName": cpe,
            "startIndex": start_index,
            "resultsPerPage": page_size
        }
        
        try:
            r = requests.get(NVD_API, params=params, headers=USER_AGENT, timeout=12)
        except Exception as e:
            logging.error(f"[NVD] Connection error: {e}")
            break

        if r.status_code != 200:
            logging.error(f"[NVD] HTTP {r.status_code} error querying NVD")
            break

        try:
            data = r.json()
        except Exception as e:
            logging.error(f"[NVD] JSON parsing error: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)

        total = data.get("totalResults", 0)
        start_index += page_size
        
        if start_index >= total:
            break

        time.sleep(NVD_DELAY)

    return results


def get_vulnerabilities(service_name, version):
    """
    Query NVD API for vulnerabilities
    
    Args:
        service_name: Service identifier
        version: Version string
    
    Returns:
        List of parsed vulnerability records with CVE, CVSS, description
    """
    cpe = build_cpe(service_name, version)
    
    if not cpe:
        logging.debug("[NVD] CPE not constructed (missing service/version)")
        return []

    logging.info(f"[NVD] Querying CPE: {cpe}")
    raw = fetch_vulns_for_cpe(cpe)
    parsed = []

    for item in raw:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        
        # Extract CWE identifiers
        cwes = []
        for w in cve.get("weaknesses", []) or []:
            for d in w.get("description", []) or []:
                v = d.get("value")
                if v:
                    cwes.append(v)

        # Extract CVSS score (try v3.1, v3, then v2)
        metrics = cve.get("metrics", {}) or {}
        cvss = None
        
        metric_keys = ["cvssMetricV31", "cvssMetricV3", "cvssMetricV2"]
        for key in metric_keys:
            if key in metrics and metrics[key]:
                try:
                    cvss = metrics[key][0]["cvssData"]["baseScore"]
                    break
                except Exception:
                    continue
        
        # Extract description
        descs = cve.get("descriptions", []) or []
        description = descs[0]["value"] if descs else ""

        parsed.append({
            "cve": cve_id,
            "cwe": cwes,
            "cvss": cvss,
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })
    
    return parsed


def normalize_name(raw_name: str, raw_version: str = "") -> str:
    """
    Normalize service names for database matching
    
    Args:
        raw_name: Raw service name from miner
        raw_version: Raw version string (used for disambiguation)
    
    Returns:
        Normalized service name matching database keys
    """
    if not raw_name:
        return ""
    
    name = raw_name.lower()
    
    # Generic HTTP -> try to deduce actual server
    if name in ["http", "http-proxy", "httpd", "apache"]:
        combined_text = (raw_name or "") + (raw_version or "")
        
        if "nginx" in combined_text.lower():
            return "nginx"
        if "apache" in combined_text.lower() or "httpd" in combined_text.lower():
            return "apache http server"
        
        return "apache http server"
    
    # Service name mappings
    mapping = {
        "sshd": "openssh",
        "ssh": "openssh",
        "openssl": "openssl",
        "smbd": "samba",
        "samba": "samba",
        "vsftpd": "vsftpd",
        "nginx": "nginx",
        "mysql": "mysql",
        "postgresql": "postgresql",
        "mariadb": "mariadb",
        "php": "php",
        "python": "python",
    }
    
    for key, val in mapping.items():
        if key in name:
            return val
    
    return name


def extract_version_number(version_string: str) -> str:
    """
    Extract numeric version from version string
    
    Args:
        version_string: Raw version string (e.g., "nginx/1.22.1")
    
    Returns:
        Clean version number (e.g., "1.22.1")
    """
    matches = re.findall(r"\d+\.\d+(?:\.\d+)?", version_string or "")
    return matches[0] if matches else ""


def load_local_vulns(file_path=LOCAL_DB_PATH):
    """
    Load vulnerabilities from local JSON database
    
    Args:
        file_path: Path to local vulnerability database
    
    Returns:
        Dictionary of vulnerabilities indexed by service and version
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"[Checker] Local DB not found: {file_path}")
        return {}
    except Exception as e:
        logging.error(f"[Checker] Error reading local DB: {e}")
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# RESULTS DISPLAY
# ═══════════════════════════════════════════════════════════════════════════

def print_vulnerability_report(results, check_time, local_hits, nvd_queries):
    """
    Print formatted vulnerability assessment report
    
    Args:
        results: List of vulnerability check results
        check_time: Total processing time
        local_hits: Number of local DB hits
        nvd_queries: Number of NVD API queries
    """
    total_vulns = sum(len(r['local_vulns']) + len(r['nvd_vulns']) for r in results)
    
    print("\n" + "╔" + "="*88 + "╗")
    print("║" + " "*26 + "VULNERABILITY ASSESSMENT REPORT" + " "*31 + "║")
    print("╚" + "="*88 + "╝\n")
    
    print(f"Assessment Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Processing Time: {check_time:.2f} seconds")
    print(f"\n{'─'*90}")
    print(f"Services Assessed:          {len(results):>10}")
    print(f"Total Vulnerabilities:      {total_vulns:>10}")
    print(f"Local DB Hits:              {local_hits:>10}")
    print(f"NVD API Queries:            {nvd_queries:>10}")
    print(f"Query Efficiency:           {local_hits/(local_hits + nvd_queries)*100 if (local_hits + nvd_queries) > 0 else 0:>9.1f}%")
    print(f"{'─'*90}\n")
    
    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    
    for res in results:
        for v in res['local_vulns'] + res['nvd_vulns']:
            cvss = v.get('cvss', 0) or 0
            if cvss >= 9.0:
                severity_counts["Critical"] += 1
            elif cvss >= 7.0:
                severity_counts["High"] += 1
            elif cvss >= 4.0:
                severity_counts["Medium"] += 1
            elif cvss > 0:
                severity_counts["Low"] += 1
            else:
                severity_counts["Unknown"] += 1
    
    print("📊 Vulnerability Severity Distribution:")
    print(f"   🔴 Critical (CVSS 9.0-10.0): {severity_counts['Critical']}")
    print(f"   🟠 High (CVSS 7.0-8.9):      {severity_counts['High']}")
    print(f"   🟡 Medium (CVSS 4.0-6.9):    {severity_counts['Medium']}")
    print(f"   🟢 Low (CVSS 0.1-3.9):       {severity_counts['Low']}")
    print(f"   ⚪ Unknown (No CVSS):        {severity_counts['Unknown']}")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# VULNERABILITY CHECKER AGENT - SPADE IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════

class VulnerabilityCheckerAgent(Agent):
    """
    Vulnerability assessment agent
    
    Queries local database and NVD API to identify known vulnerabilities
    in detected services.
    """
    
    class CheckVulnerabilities(CyclicBehaviour):
        """
        Main vulnerability checking loop
        
        Processes enriched service data and performs CVE lookups
        """
        
        async def run(self):
            """Process incoming service data and check for vulnerabilities"""
            msg = await self.receive(timeout=10)
            if not msg:
                return

            sender = str(msg.sender).split('@')[0]
            check_start = time.perf_counter()
            
            logging.info("╔" + "═"*78 + "╗")
            logging.info("║" + " "*16 + "VULNERABILITY CHECKER - Network Defender Swarm" + " "*15 + "║")
            logging.info("╚" + "═"*78 + "╝")
            logging.info(f"Received service data from {sender}")

            try:
                data = json.loads(msg.body)
            except Exception as e:
                logging.error(f"[Checker] JSON parsing error: {e}")
                return

            # Load local vulnerability database
            local_db = load_local_vulns(LOCAL_DB_PATH)
            accumulated_results = []
            
            local_hits = 0
            nvd_queries = 0

            logging.info(f"Processing {len(data)} services for vulnerabilities...")
            
            for entry in data:
                port = entry.get("port")
                raw_version = entry.get("version", "")
                raw_service = entry.get("service", "")
                
                # Normalize service name and version
                software = normalize_name(raw_service, raw_version)
                version = extract_version_number(raw_version)

                logging.info(f"  Checking: {software} ({version}) on port {port}")

                local_service = local_db.get(software, None)
                local_vulns = []
                nvd_vulns = []
                
                consult_nvd = False

                # Try local database first
                if local_service is not None:
                    local_vulns = local_service.get(version, [])
                    
                    if local_vulns:
                        local_hits += 1
                        logging.info(f"    ✓ Found in local DB: {len(local_vulns)} CVEs")
                    else:
                        logging.info(f"    ⚠ {software} in DB but version {version} not cached")
                        consult_nvd = True
                else:
                    logging.info(f"    ℹ {software} not in local DB, querying NVD...")
                    consult_nvd = True
                
                # Fallback to NVD if needed
                if consult_nvd and software and version:
                    try:
                        nvd_vulns = get_vulnerabilities(software, version)
                        nvd_queries += 1
                        logging.info(f"    ✓ NVD query complete: {len(nvd_vulns)} CVEs found")
                    except Exception as e:
                        logging.error(f"    ✗ NVD query failed: {e}")
                        nvd_vulns = []
                elif consult_nvd:
                    logging.warning(f"    ⚠ Incomplete data for NVD query: {raw_service}/{raw_version}")

                accumulated_results.append({
                    "port": port,
                    "software": software,
                    "version": version,
                    "local_vulns": local_vulns,
                    "nvd_vulns": nvd_vulns
                })
            
            check_time = time.perf_counter() - check_start

            # Print vulnerability report
            print_vulnerability_report(accumulated_results, check_time, local_hits, nvd_queries)
            
            # Print detailed findings
            self.print_detailed_report(accumulated_results)

            # Send results to Reporter Agent
            await self.send_to_reporter(accumulated_results)
            
            logging.info(f"→ Vulnerability assessment complete")
            logging.info(f"→ Check Time: {check_time:.2f}s")
            logging.info(f"→ Results forwarded to Reporter Agent")
            logging.info("═"*80 + "\n")

        def print_detailed_report(self, results):
            """
            Print detailed vulnerability findings per service
            
            Args:
                results: List of vulnerability check results
            """
            print("╔" + "="*88 + "╗")
            print("║" + " "*30 + "DETAILED FINDINGS" + " "*41 + "║")
            print("╚" + "="*88 + "╝\n")

            for res in results:
                port = res['port']
                software = res['software']
                version = res['version']
                local = res['local_vulns']
                nvd = res['nvd_vulns']
                
                total_vulns = len(local) + len(nvd)
                
                print(f"\n┌─ Port {port}: {software} {version}")
                print(f"│")
                
                if total_vulns == 0:
                    print(f"│  ✅ No vulnerabilities found")
                else:
                    print(f"│  ⚠ {total_vulns} vulnerabilities detected")
                    print(f"│")
                    
                    # Local DB vulnerabilities
                    if local:
                        print(f"│  📦 LOCAL DATABASE ({len(local)} CVEs):")
                        for v in local[:5]:  # Limit to first 5
                            cvss = v.get('cvss', 'N/A')
                            cve = v.get('cve', 'Unknown')
                            desc = v.get('description', '')[:60]
                            print(f"│     • {cve} [CVSS {cvss}] - {desc}...")
                        
                        if len(local) > 5:
                            print(f"│     ... and {len(local) - 5} more")
                        print(f"│")
                    
                    # NVD vulnerabilities
                    if nvd:
                        print(f"│  🌐 NVD API ({len(nvd)} CVEs):")
                        for v in nvd[:5]:  # Limit to first 5
                            cvss = v.get('cvss', 'N/A')
                            cve = v.get('cve', 'Unknown')
                            desc = v.get('description', '')[:60]
                            print(f"│     • {cve} [CVSS {cvss}] - {desc}...")
                        
                        if len(nvd) > 5:
                            print(f"│     ... and {len(nvd) - 5} more")
                
                print(f"└" + "─"*87)
            
            print()

        async def send_to_reporter(self, results):
            """
            Forward vulnerability results to Reporter Agent
            
            Args:
                results: List of vulnerability assessment results
            """
            out = Message(to="reporter@localhost")
            out.set_metadata("performative", "inform")
            out.set_metadata("stage", "vulnerability_check")
            out.set_metadata("timestamp", datetime.now().isoformat())
            out.body = json.dumps(results)
            
            try:
                await self.send(out)
                logging.info(f"[Checker] Sent results to reporter ({len(results)} entries)")
            except Exception as e:
                logging.error(f"[Checker] Error sending to reporter: {e}")

    async def setup(self):
        """Agent initialization"""
        logging.info("╔" + "="*78 + "╗")
        logging.info("║" + " "*18 + "VULNERABILITY CHECKER AGENT STARTING" + " "*23 + "║")
        logging.info("╚" + "="*78 + "╝")
        logging.info("")
        logging.info("Loading local vulnerability database...")
        
        # Verify local database exists
        try:
            db = load_local_vulns(LOCAL_DB_PATH)
            logging.info(f"✓ Local database loaded: {len(db)} software entries")
        except Exception as e:
            logging.warning(f"⚠ Local database unavailable: {e}")
        
        logging.info("Vulnerability Checker Agent ready")
        logging.info("")
        
        # Attach checking behavior
        self.add_behaviour(self.CheckVulnerabilities())
