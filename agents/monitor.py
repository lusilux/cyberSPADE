"""
Monitor Agent - Strategic Coordination Layer

The Monitor Agent serves as the central intelligence and coordination hub of cyberSPADE.
It maintains global situational awareness, orchestrates defensive swarm deployment,
and consolidates security reports from all operational hosts.

Responsibilities:
- Strategic decision-making and defensive phase orchestration
- Global state management and situational model maintenance
- Swarm deployment coordination via Deployer agents
- Report aggregation and analysis
- Vulnerability knowledge base management

Architecture Position:
- Runs exclusively on the supervisor host
- Coordinates with multiple Deployer agents across operational hosts
- Receives consolidated reports from Reporter agents
- Maintains system-wide security posture awareness
"""

import spade
import logging
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


class MonitorAgent(Agent):
    """
    Strategic coordination agent for cyberSPADE
    
    The Monitor maintains a system-wide view of the defended environment
    and orchestrates all defensive operations.
    """
    
    class ManageSystemBehavior(CyclicBehaviour):
        """
        Main coordination loop for the Monitor Agent
        
        Handles:
        - Deployment request initiation
        - Report processing and aggregation
        - System status monitoring
        - Defensive phase transitions
        """
        
        async def on_start(self):
            """Initialize Monitor Agent and request initial deployment"""
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print("\n" + "╔" + "="*78 + "╗")
            print("║" + " "*22 + "MONITOR AGENT - STRATEGIC LAYER" + " "*25 + "║")
            print("╚" + "="*78 + "╝\n")
            
            logging.info("═"*80)
            logging.info("Monitor Agent Initialization")
            logging.info("═"*80)
            logging.info(f"Start Time: {timestamp}")
            logging.info(f"Agent JID: {self.agent.jid}")
            logging.info(f"Role: Strategic Coordination and Situational Awareness")
            logging.info("─"*80)
            
            # Initialize global state
            self.deployment_time = time.perf_counter()
            self.reports_received = 0
            self.deployments_initiated = 0
            self.total_vulnerabilities = 0
            self.total_services_detected = 0
            
            # Request deployment of Network Defender Swarm
            logging.info("Initiating defensive swarm deployment...")
            msg = Message(to="deployer@localhost")
            msg.set_metadata("performative", "request")
            msg.set_metadata("type", "deployment")
            msg.set_metadata("timestamp", datetime.now().isoformat())
            msg.body = "Start Defender Swarm"
            
            await self.send(msg)
            self.deployments_initiated += 1
            
            logging.info("→ Deployment request sent to Deployer Agent")
            logging.info(f"→ Target: Network Defender Swarm")
            logging.info(f"→ Deployments initiated: {self.deployments_initiated}")
            logging.info("═"*80 + "\n")

        async def run(self):
            """Main message processing loop"""
            msg = await self.receive(timeout=10)
            
            if msg:
                performative = msg.get_metadata("performative")
                msg_type = msg.get_metadata("type", "unknown")
                sender = str(msg.sender).split('@')[0]
                
                # Process deployment acknowledgment
                if performative == "agree":
                    logging.info("┌" + "─"*78 + "┐")
                    logging.info(f"│ Deployment Acknowledged by {sender:42} │")
                    logging.info("└" + "─"*78 + "┘")
                    logging.info(f"  Status: {msg.body}")
                    logging.info("")
                
                # Process deployment completion
                elif performative == "inform" and "deployed" in msg.body.lower():
                    elapsed = time.perf_counter() - self.deployment_time
                    
                    logging.info("┌" + "─"*78 + "┐")
                    logging.info(f"│ ✓ DEPLOYMENT COMPLETE - {sender.upper():47} │")
                    logging.info("└" + "─"*78 + "┘")
                    logging.info(f"  Message: {msg.body}")
                    logging.info(f"  Deployment Time: {elapsed:.2f} seconds")
                    logging.info("")
                
                # Process security reports
                elif performative == "inform":
                    self.reports_received += 1
                    
                    print(f"\n{'═'*80}")
                    print(f"SECURITY REPORT RECEIVED - Report #{self.reports_received}")
                    print(f"{'═'*80}")
                    print(f"Source: {sender}")
                    print(f"Type: {msg_type}")
                    print(f"Timestamp: {msg.get_metadata('timestamp', 'N/A')}")
                    print(f"{'─'*80}")
                    
                    # Try to parse report content
                    try:
                        import json
                        report_data = json.loads(msg.body) if msg.body.startswith('{') or msg.body.startswith('[') else None
                        
                        if report_data and isinstance(report_data, dict):
                            # Extract metrics from report
                            if 'metrics' in report_data:
                                metrics = report_data['metrics']
                                print(f"Report Metrics:")
                                for key, value in metrics.items():
                                    print(f"  • {key.replace('_', ' ').title()}: {value}")
                            
                            # Count vulnerabilities if present
                            if 'vulnerabilities' in report_data:
                                vuln_count = len(report_data['vulnerabilities'])
                                self.total_vulnerabilities += vuln_count
                                print(f"\n  ⚠ Vulnerabilities Detected: {vuln_count}")
                            
                            # Count services if present
                            if 'services' in report_data or 'ports' in report_data:
                                service_count = len(report_data.get('services', report_data.get('ports', [])))
                                self.total_services_detected += service_count
                                print(f"  🔍 Services Identified: {service_count}")
                        else:
                            # Plain text report
                            print(f"Report Content:\n{msg.body[:500]}")
                            if len(msg.body) > 500:
                                print(f"  ... (truncated, {len(msg.body)} bytes total)")
                    
                    except Exception as e:
                        # Fallback for non-JSON reports
                        print(f"Report Summary:\n{msg.body[:300]}")
                        if len(msg.body) > 300:
                            print(f"  ... (truncated)")
                    
                    print(f"{'═'*80}\n")
                    
                    # Update global situational model
                    self._update_situational_model(sender, msg.body)
                
                else:
                    logging.info(f"[Monitor] Received message from {sender}: {msg.body}")
            
            # Periodic status display
            if not msg:
                # Only show periodic status every 30 seconds
                if not hasattr(self, '_last_status_time'):
                    self._last_status_time = time.time()
                
                if time.time() - self._last_status_time > 30:
                    self._display_status()
                    self._last_status_time = time.time()

        def _update_situational_model(self, source, report_content):
            """
            Update the global situational awareness model
            
            Args:
                source: Report source identifier
                report_content: Raw report content
            """
            # In a full implementation, this would:
            # - Parse structured report data
            # - Update threat database
            # - Correlate findings across hosts
            # - Trigger automated responses
            # - Update risk assessments
            
            logging.debug(f"Situational model updated with report from {source}")
        
        def _display_status(self):
            """Display current Monitor Agent status"""
            uptime = time.perf_counter() - self.deployment_time
            
            print(f"\n{'┌' + '─'*78 + '┐'}")
            print(f"│ MONITOR STATUS UPDATE {' '*55} │")
            print(f"{'├' + '─'*78 + '┤'}")
            print(f"│  Uptime: {uptime:.1f}s  │  Reports: {self.reports_received}  │  Deployments: {self.deployments_initiated}  │  Vulns: {self.total_vulnerabilities} {' '*10} │")
            print(f"{'└' + '─'*78 + '┘'}\n")

    async def setup(self):
        """Agent initialization and behavior attachment"""
        logging.info("╔" + "="*78 + "╗")
        logging.info("║" + " "*25 + "MONITOR AGENT STARTING" + " "*30 + "║")
        logging.info("╚" + "="*78 + "╝")
        logging.info("")
        
        # Initialize knowledge base
        self.vulnerability_kb = {}
        self.host_states = {}
        self.active_threats = []
        
        # Attach main behavior
        b = self.ManageSystemBehavior()
        self.add_behaviour(b)
        
        logging.info("Monitor Agent ready for coordination operations")
        logging.info("")
