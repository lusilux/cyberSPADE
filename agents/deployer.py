"""
Deployer Agent - Host-Local Deployment Manager

The Deployer Agent runs on each operational host and serves as the local authority
responsible for instantiating and managing defensive swarms. It acts as the bridge
between the strategic Monitor layer and the operational defensive agents.

Responsibilities:
- Receive deployment commands from Monitor Agent
- Instantiate requested defensive swarms on local host
- Manage swarm lifecycle (start, monitor, terminate)
- Report deployment status back to Monitor
- Enforce host-level security policies

Architecture Position:
- One Deployer per operational host
- Receives commands from Monitor Agent
- Deploys and manages local Worker Agents
- Does not participate in swarm coordination after deployment
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


class DeployerAgent(Agent):
    """
    Host-local deployment manager for defensive swarms
    
    Executes Monitor directives by instantiating and managing
    specialized defensive agents on the operational host.
    """
    
    class DeployBehavior(CyclicBehaviour):
        """
        Main deployment request processing loop
        
        Handles:
        - Deployment request validation
        - Swarm instantiation
        - Status reporting
        - Lifecycle management
        """
        
        async def on_start(self):
            """Initialize Deployer Agent"""
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            print("\n" + "╔" + "="*78 + "╗")
            print("║" + " "*19 + "DEPLOYER AGENT - OPERATIONAL LAYER" + " "*24 + "║")
            print("╚" + "="*78 + "╝\n")
            
            logging.info("═"*80)
            logging.info("Deployer Agent Initialization")
            logging.info("═"*80)
            logging.info(f"Start Time: {timestamp}")
            logging.info(f"Agent JID: {self.agent.jid}")
            logging.info(f"Role: Host-Local Swarm Deployment Manager")
            logging.info(f"Host: localhost (127.0.0.1)")
            logging.info("─"*80)
            
            # Initialize deployment tracking
            self.deployments_completed = 0
            self.active_swarms = []
            self.start_time = time.perf_counter()
            
            logging.info("Deployer Agent ready to receive deployment commands")
            logging.info("Listening for Monitor Agent directives...")
            logging.info("═"*80 + "\n")
        
        async def run(self):
            """Process incoming deployment requests"""
            msg = await self.receive(timeout=10)
            
            if msg:
                sender = str(msg.sender).split('@')[0]
                performative = msg.get_metadata("performative")
                msg_type = msg.get_metadata("type", "unknown")
                
                # Process deployment request
                if performative == "request" and "Defender Swarm" in msg.body:
                    deployment_start = time.perf_counter()
                    
                    print(f"\n{'╔' + '═'*78 + '╗'}")
                    print(f"║{'DEPLOYMENT REQUEST RECEIVED':^78}║")
                    print(f"{'╚' + '═'*78 + '╝'}")
                    print(f"\nFrom: {sender}")
                    print(f"Type: {msg_type}")
                    print(f"Request: {msg.body}")
                    print(f"Timestamp: {msg.get_metadata('timestamp', 'N/A')}")
                    print(f"{'─'*80}\n")
                    
                    logging.info("Processing deployment request...")
                    logging.info(f"  Requester: {sender}")
                    logging.info(f"  Target Swarm: Network Defender Swarm")
                    logging.info(f"  Command: {msg.body}")
                    
                    # Send acknowledgment
                    reply = msg.make_reply()
                    reply.set_metadata("performative", "agree")
                    reply.set_metadata("type", "deployment_ack")
                    reply.body = "Swarm deployment initiated"
                    await self.send(reply)
                    
                    logging.info("→ Acknowledgment sent to Monitor")
                    
                    # Simulate deployment process
                    # In production, this would:
                    # - Validate deployment request
                    # - Check resource availability
                    # - Instantiate swarm agents
                    # - Configure agent parameters
                    # - Start agent behaviors
                    
                    print(f"\n{'┌' + '─'*78 + '┐'}")
                    print(f"│ INITIATING SWARM DEPLOYMENT{' '*49}│")
                    print(f"{'├' + '─'*78 + '┤'}")
                    print(f"│  Phase 1: Validating deployment request...{' '*32}│")
                    
                    await asyncio.sleep(0.5)
                    print(f"│  Phase 2: Allocating host resources...{' '*35}│")
                    
                    await asyncio.sleep(0.5)
                    print(f"│  Phase 3: Instantiating Network Defender Swarm agents...{' '*18}│")
                    print(f"│            - ScanAgent (port scanning){' '*36}│")
                    print(f"│            - VersionMinerAgent (version extraction){' '*25}│")
                    print(f"│            - VulnerabilityCheckerAgent (CVE lookup){' '*25}│")
                    print(f"│            - ReporterAgent (report generation){' '*29}│")
                    
                    await asyncio.sleep(1.0)
                    print(f"│  Phase 4: Configuring agent behaviors...{' '*33}│")
                    
                    await asyncio.sleep(0.5)
                    print(f"│  Phase 5: Starting defensive operations...{' '*32}│")
                    
                    deployment_time = time.perf_counter() - deployment_start
                    
                    print(f"{'└' + '─'*78 + '┘'}\n")
                    
                    # Update deployment tracking
                    self.deployments_completed += 1
                    self.active_swarms.append({
                        'type': 'Network Defender Swarm',
                        'deployed_at': datetime.now().isoformat(),
                        'deployment_time': deployment_time
                    })
                    
                    # Send completion notification
                    inform = msg.make_reply()
                    inform.set_metadata("performative", "inform")
                    inform.set_metadata("type", "deployment_complete")
                    inform.set_metadata("timestamp", datetime.now().isoformat())
                    inform.body = "Swarm deployed"
                    await self.send(inform)
                    
                    print(f"{'╔' + '═'*78 + '╗'}")
                    print(f"║{'✓ DEPLOYMENT SUCCESSFUL':^78}║")
                    print(f"{'╚' + '═'*78 + '╝'}")
                    print(f"\nSwarm Type: Network Defender Swarm")
                    print(f"Deployment Time: {deployment_time:.2f} seconds")
                    print(f"Total Deployments: {self.deployments_completed}")
                    print(f"Active Swarms: {len(self.active_swarms)}")
                    print(f"{'═'*80}\n")
                    
                    logging.info(f"✓ Swarm deployment completed in {deployment_time:.2f}s")
                    logging.info(f"→ Completion notification sent to Monitor")
                    logging.info(f"→ Total deployments: {self.deployments_completed}")
                    logging.info("")
                
                else:
                    logging.info(f"Received message from {sender}: {msg.body}")
            
            # Periodic status check
            if not msg and not hasattr(self, '_last_status_time'):
                self._last_status_time = time.time()
            
            if hasattr(self, '_last_status_time') and time.time() - self._last_status_time > 60:
                self._display_status()
                self._last_status_time = time.time()
        
        def _display_status(self):
            """Display current Deployer status"""
            uptime = time.perf_counter() - self.start_time
            
            print(f"\n{'┌' + '─'*78 + '┐'}")
            print(f"│ DEPLOYER STATUS{' '*62}│")
            print(f"{'├' + '─'*78 + '┤'}")
            print(f"│  Uptime: {uptime:.1f}s  │  Deployments: {self.deployments_completed}  │  Active Swarms: {len(self.active_swarms)}{' '*25}│")
            print(f"{'└' + '─'*78 + '┘'}\n")

    async def setup(self):
        """Agent initialization and behavior attachment"""
        logging.info("╔" + "="*78 + "╗")
        logging.info("║" + " "*24 + "DEPLOYER AGENT STARTING" + " "*29 + "║")
        logging.info("╚" + "="*78 + "╝")
        logging.info("")
        
        # Initialize deployment state
        self.deployed_swarms = {}
        self.deployment_history = []
        
        # Attach deployment behavior
        b = self.DeployBehavior()
        self.add_behaviour(b)
        
        logging.info("Deployer Agent initialized and ready")
        logging.info("")
