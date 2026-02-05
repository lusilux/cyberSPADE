"""
Reporter Agent - Network Defender Swarm
Part 4 of the defensive pipeline (Final Stage)

Responsibilities:
- Receive vulnerability data from Checker Agent
- Consolidate findings into comprehensive security report
- Generate executive summary with key metrics
- Normalize data format for Monitor Agent consumption
- Forward final report to Monitor for strategic analysis
- Archive reports for audit trail

Report Structure:
- Executive Summary (high-level metrics)
- Service Inventory (detected services and versions)
- Vulnerability Assessment (CVEs with CVSS scores)
- Risk Analysis (severity distribution, recommendations)
- Detailed Findings (per-service breakdown)

Metrics included:
- Total services scanned
- Vulnerabilities by severity
- Average CVSS score
- Compliance status
- Recommended actions
"""

import spade
import logging
import json
import time
from datetime import datetime
from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message
import asyncio


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class ReporterAgent(Agent):
    """
    Security report consolidation and generation agent
    
    Aggregates vulnerability data and produces actionable security reports
    for the Monitor Agent and security operations team.
    """
    
    class ReportBehavior(CyclicBehaviour):
        """
        Main report generation loop
        
        Processes vulnerability data and creates consolidated security reports
        """
        
        async def run(self):
            """Process incoming vulnerability data and generate reports"""
            msg = await self.receive(timeout=10)
            
            if not msg:
                return
            
            sender = str(msg.sender).split('@')[0]
            performative = msg.get_metadata("performative")
            
            if performative != "inform":
                return
            
            report_start = time.perf_counter()
            
            logging.info("╔" + "="*78 + "╗")
            logging.info("║" + " "*20 + "REPORTER - Network Defender Swarm" + " "*23 + "║")
            logging.info("╚" + "="*78 + "╝")
            logging.info(f"Received vulnerability data from {sender}")
            
            try:
                vulns = json.loads(msg.body)
                logging.info(f"Processing {len(vulns)} vulnerability records...")
            except Exception as e:
                logging.error(f"ReporterAgent: Error parsing message: {e}")
                return
            
            # Generate comprehensive report
            report = self.generate_security_report(vulns)
            
            # Display report
            self.display_report(report)
            
            # Calculate report generation time
            report_time = time.perf_counter() - report_start
            
            # Send final report to Monitor
            await self.send_to_monitor(report, report_time)
            
            logging.info(f"→ Report generated in {report_time:.2f}s")
            logging.info(f"→ Report forwarded to Monitor Agent")
            logging.info("═"*80 + "\n")
        
        def generate_security_report(self, vulnerability_data):
            """
            Generate comprehensive security report from vulnerability data
            
            Args:
                vulnerability_data: List of vulnerability records from Checker
            
            Returns:
                Dictionary containing structured report data
            """
            report = {
                'timestamp': datetime.now().isoformat(),
                'report_id': f"RPT-{int(time.time())}",
                'executive_summary': {},
                'services': [],
                'vulnerabilities': [],
                'risk_analysis': {},
                'recommendations': []
            }
            
            # Executive Summary Metrics
            total_services = len(vulnerability_data)
            total_vulns = 0
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            cvss_scores = []
            
            for service_data in vulnerability_data:
                port = service_data.get('port')
                software = service_data.get('software')
                version = service_data.get('version')
                local_vulns = service_data.get('local_vulns', [])
                nvd_vulns = service_data.get('nvd_vulns', [])
                
                all_vulns = local_vulns + nvd_vulns
                total_vulns += len(all_vulns)
                
                # Service record
                report['services'].append({
                    'port': port,
                    'software': software,
                    'version': version,
                    'vulnerability_count': len(all_vulns)
                })
                
                # Vulnerability records with severity classification
                for vuln in all_vulns:
                    cvss = vuln.get('cvss', 0) or 0
                    
                    if cvss > 0:
                        cvss_scores.append(cvss)
                    
                    # Classify severity
                    if cvss >= 9.0:
                        severity = "Critical"
                    elif cvss >= 7.0:
                        severity = "High"
                    elif cvss >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
                    
                    severity_counts[severity] += 1
                    
                    report['vulnerabilities'].append({
                        'port': port,
                        'service': f"{software} {version}",
                        'cve': vuln.get('cve'),
                        'cvss': cvss,
                        'severity': severity,
                        'description': vuln.get('description', '')[:200],
                        'url': vuln.get('url', '')
                    })
            
            # Executive Summary
            report['executive_summary'] = {
                'services_scanned': total_services,
                'vulnerabilities_found': total_vulns,
                'critical_vulnerabilities': severity_counts['Critical'],
                'high_vulnerabilities': severity_counts['High'],
                'medium_vulnerabilities': severity_counts['Medium'],
                'low_vulnerabilities': severity_counts['Low'],
                'average_cvss': sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0,
                'max_cvss': max(cvss_scores) if cvss_scores else 0
            }
            
            # Risk Analysis
            risk_level = self.calculate_risk_level(severity_counts)
            
            report['risk_analysis'] = {
                'overall_risk': risk_level,
                'severity_distribution': severity_counts,
                'most_vulnerable_services': sorted(
                    report['services'],
                    key=lambda x: x['vulnerability_count'],
                    reverse=True
                )[:5]
            }
            
            # Generate Recommendations
            report['recommendations'] = self.generate_recommendations(
                severity_counts,
                report['vulnerabilities']
            )
            
            return report
        
        def calculate_risk_level(self, severity_counts):
            """
            Calculate overall risk level based on vulnerability distribution
            
            Args:
                severity_counts: Dictionary of vulnerabilities by severity
            
            Returns:
                Risk level string (Critical/High/Medium/Low/Minimal)
            """
            if severity_counts['Critical'] > 0:
                return "Critical"
            elif severity_counts['High'] >= 3:
                return "High"
            elif severity_counts['High'] > 0 or severity_counts['Medium'] >= 5:
                return "Medium"
            elif severity_counts['Medium'] > 0 or severity_counts['Low'] > 0:
                return "Low"
            else:
                return "Minimal"
        
        def generate_recommendations(self, severity_counts, vulnerabilities):
            """
            Generate actionable security recommendations
            
            Args:
                severity_counts: Severity distribution
                vulnerabilities: List of detected vulnerabilities
            
            Returns:
                List of recommendation strings
            """
            recommendations = []
            
            if severity_counts['Critical'] > 0:
                recommendations.append(
                    "🔴 IMMEDIATE ACTION: Patch or isolate systems with critical vulnerabilities"
                )
            
            if severity_counts['High'] > 0:
                recommendations.append(
                    "🟠 HIGH PRIORITY: Schedule maintenance window for high-severity updates"
                )
            
            if severity_counts['Medium'] > 5:
                recommendations.append(
                    "🟡 MEDIUM PRIORITY: Review and address medium-severity vulnerabilities"
                )
            
            # Service-specific recommendations
            services = set(v['service'].split()[0] for v in vulnerabilities)
            
            if 'openssh' in services or 'ssh' in services:
                recommendations.append(
                    "🔒 Ensure SSH key-based authentication is enforced"
                )
            
            if 'apache' in services or 'nginx' in services:
                recommendations.append(
                    "🌐 Review web server configurations and apply security headers"
                )
            
            if 'mysql' in services or 'postgresql' in services:
                recommendations.append(
                    "💾 Verify database access controls and encryption settings"
                )
            
            if not recommendations:
                recommendations.append(
                    "✅ No immediate actions required - continue monitoring"
                )
            
            return recommendations
        
        def display_report(self, report):
            """
            Display formatted security report
            
            Args:
                report: Report dictionary from generate_security_report()
            """
            summary = report['executive_summary']
            risk = report['risk_analysis']
            
            print("\n" + "╔" + "="*88 + "╗")
            print("║" + " "*28 + "SECURITY ASSESSMENT REPORT" + " "*34 + "║")
            print("╚" + "="*88 + "╝\n")
            
            print(f"Report ID: {report['report_id']}")
            print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Overall Risk Level: {risk['overall_risk']}\n")
            
            print("─"*90)
            print("EXECUTIVE SUMMARY")
            print("─"*90)
            print(f"Services Scanned:           {summary['services_scanned']:>10}")
            print(f"Total Vulnerabilities:      {summary['vulnerabilities_found']:>10}")
            print(f"  🔴 Critical (CVSS ≥ 9.0): {summary['critical_vulnerabilities']:>10}")
            print(f"  🟠 High (CVSS 7.0-8.9):   {summary['high_vulnerabilities']:>10}")
            print(f"  🟡 Medium (CVSS 4.0-6.9): {summary['medium_vulnerabilities']:>10}")
            print(f"  🟢 Low (CVSS < 4.0):      {summary['low_vulnerabilities']:>10}")
            print(f"Average CVSS Score:         {summary['average_cvss']:>10.2f}")
            print(f"Maximum CVSS Score:         {summary['max_cvss']:>10.1f}")
            print("─"*90 + "\n")
            
            # Most Vulnerable Services
            if risk['most_vulnerable_services']:
                print("⚠️  MOST VULNERABLE SERVICES:")
                for i, svc in enumerate(risk['most_vulnerable_services'][:3], 1):
                    print(f"   {i}. Port {svc['port']}: {svc['software']} {svc['version']} "
                          f"({svc['vulnerability_count']} CVEs)")
                print()
            
            # Recommendations
            print("📋 RECOMMENDED ACTIONS:")
            for i, rec in enumerate(report['recommendations'], 1):
                print(f"   {i}. {rec}")
            
            print("\n" + "="*90 + "\n")
        
        async def send_to_monitor(self, report, generation_time):
            """
            Forward consolidated report to Monitor Agent
            
            Args:
                report: Complete security report dictionary
                generation_time: Time taken to generate report
            """
            out_msg = Message(to="monitor@localhost")
            out_msg.set_metadata("performative", "inform")
            out_msg.set_metadata("type", "security_report")
            out_msg.set_metadata("timestamp", report['timestamp'])
            out_msg.set_metadata("generation_time", str(generation_time))
            
            # Serialize report
            out_msg.body = json.dumps(report, indent=2)
            
            try:
                await self.send(out_msg)
                logging.info("ReporterAgent: Final report sent to Monitor")
            except Exception as e:
                logging.error(f"ReporterAgent: Error sending to Monitor: {e}")

    async def setup(self):
        """Agent initialization"""
        logging.info("╔" + "="*78 + "╗")
        logging.info("║" + " "*24 + "REPORTER AGENT STARTING" + " "*29 + "║")
        logging.info("╚" + "="*78 + "╝")
        logging.info("")
        logging.info("Reporter Agent initialized")
        logging.info("Ready to consolidate vulnerability reports")
        logging.info("")
        
        # Attach reporting behavior
        b = self.ReportBehavior()
        self.add_behaviour(b)
