#!/usr/bin/env python3
"""
cyberSPADE - ACL Message Latency Benchmark
Ping-Pong Test for SPADE vs JADE Comparison

"""

import time
import logging
import asyncio
from datetime import datetime
from spade.message import Message

from agents.monitor import MonitorAgent
from agents.deployer import DeployerAgent
from agents.defender.scan import ScanAgent
from agents.defender.miner import VersionMinerAgent
from agents.defender.checker import VulnerabilityCheckerAgent

# Import benchmark agents
from agents.benchmark.ping import PingAgent
from agents.benchmark.pong import PongAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def print_banner():
    """Print benchmark banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║              cyberSPADE - ACL Message Latency Benchmark               ║
    ║                     SPADE vs JADE Comparison Test                     ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_comparison_table(num_agents):
    """
    Print comparison table with JADE baseline values
    
    Data from: Chmiel et al. 2005, Table 5
    """
    
    # JADE baseline values (in milliseconds)
    jade_baseline = {
        2: {'spamming': 40034, 'receiving': 87053},
        3: {'spamming': 24440, 'receiving': 141778},
        4: {'spamming': 25128, 'receiving': 217501},
        5: {'spamming': 25217, 'receiving': 313625},
        6: {'spamming': 28843, 'receiving': 448181},
        7: {'spamming': 35164, 'receiving': 634847},
        8: {'spamming': 40624, 'receiving': 821341}
    }
    
    print("\n" + "="*95)
    print("ACL MESSAGE LATENCY COMPARISON: JADE vs cyberSPADE")
    print("="*95)
    print(f"Configuration: {num_agents} agents, 5000 messages per agent, 300-byte payload")
    print("="*95)
    print(f"{'Agents':<10} {'JADE Spamming':<20} {'JADE Receiving':<20} {'cyberSPADE Spamming':<22} {'cyberSPADE Receiving':<20}")
    print(f"{'Count':<10} {'(ms)':<20} {'(ms)':<20} {'(ms)':<22} {'(ms)':<20}")
    print("-"*95)
    
    if num_agents in jade_baseline:
        jade_spam = jade_baseline[num_agents]['spamming']
        jade_recv = jade_baseline[num_agents]['receiving']
        print(f"{num_agents:<10} {jade_spam:<20,} {jade_recv:<20,} {'[Running...]':<22} {'[Running...]':<20}")
    
    print("="*95)
    print("\nReference: Chmiel, K., et al. 'Efficiency of JADE Agent Platform.'")
    print("           Scientific Programming, vol. 13, 2005, pp. 159-172.\n")


def print_results_comparison(num_agents, spade_spamming, spade_receiving):
    """Print final comparison with improvements"""
    
    jade_baseline = {
        2: {'spamming': 40034, 'receiving': 87053},
        3: {'spamming': 24440, 'receiving': 141778},
        4: {'spamming': 25128, 'receiving': 217501},
        5: {'spamming': 25217, 'receiving': 313625},
        6: {'spamming': 28843, 'receiving': 448181},
        7: {'spamming': 35164, 'receiving': 634847},
        8: {'spamming': 40624, 'receiving': 821341}
    }
    
    print("\n" + "╔" + "="*93 + "╗")
    print("║" + " "*34 + "BENCHMARK RESULTS" + " "*42 + "║")
    print("╚" + "="*93 + "╝")
    
    print(f"\nTest Configuration:")
    print(f"  • Number of Ping Agents: {num_agents}")
    print(f"  • Messages per Agent: 5,000")
    print(f"  • Message Payload: 300 bytes")
    print(f"  • Total Messages: {num_agents * 5000:,}")
    
    if num_agents in jade_baseline:
        jade_spam = jade_baseline[num_agents]['spamming']
        jade_recv = jade_baseline[num_agents]['receiving']
        
        improvement_spam = jade_spam / spade_spamming if spade_spamming > 0 else 0
        improvement_recv = jade_recv / spade_receiving if spade_receiving > 0 else 0
        
        print(f"\n┌{'─'*91}┐")
        print(f"│ {'Metric':<30} │ {'JADE':<15} │ {'cyberSPADE':<15} │ {'Improvement':<15} │")
        print(f"├{'─'*91}┤")
        print(f"│ {'Spamming Time (ms)':<30} │ {jade_spam:>13,} │ {spade_spamming:>13,.2f} │ {improvement_spam:>13,.1f}x │")
        print(f"│ {'Receiving Time (ms)':<30} │ {jade_recv:>13,} │ {spade_receiving:>13,.2f} │ {improvement_recv:>13,.1f}x │")
        print(f"│ {'Total Time (ms)':<30} │ {jade_spam + jade_recv:>13,} │ {spade_spamming + spade_receiving:>13,.2f} │ {(jade_spam + jade_recv)/(spade_spamming + spade_receiving):>13,.1f}x │")
        print(f"└{'─'*91}┘")
        
        print(f"\n Performance Summary:")
        print(f"   • Spamming: cyberSPADE is {improvement_spam:.1f}x faster than JADE")
        print(f"   • Receiving: cyberSPADE is {improvement_recv:.1f}x faster than JADE")
        print(f"   • Overall: cyberSPADE is {(jade_spam + jade_recv)/(spade_spamming + spade_receiving):.1f}x faster than JADE")
    else:
        print(f"\n┌{'─'*91}┐")
        print(f"│ {'Metric':<30} │ {'cyberSPADE Result':<58} │")
        print(f"├{'─'*91}┤")
        print(f"│ {'Spamming Time (ms)':<30} │ {spade_spamming:>56,.2f} │")
        print(f"│ {'Receiving Time (ms)':<30} │ {spade_receiving:>56,.2f} │")
        print(f"│ {'Total Time (ms)':<30} │ {spade_spamming + spade_receiving:>56,.2f} │")
        print(f"└{'─'*91}┘")
        
        print(f"\n No JADE baseline available for {num_agents} agents")
    
    # Per-message statistics
    total_messages = num_agents * 5000
    avg_spam_per_msg = spade_spamming / total_messages
    avg_recv_per_msg = spade_receiving / total_messages
    
    print(f"\n Per-Message Statistics:")
    print(f"   • Average Spamming Time: {avg_spam_per_msg:.6f} ms/message")
    print(f"   • Average Receiving Time: {avg_recv_per_msg:.6f} ms/message")
    print(f"   • Average Round-Trip Time: {avg_spam_per_msg + avg_recv_per_msg:.6f} ms/message")
    
    print(f"\nExperimental Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*95 + "\n")
    
    # Save results
    results_file = f'results/latency_benchmark_{num_agents}agents.txt'
    with open(results_file, 'w') as f:
        f.write(f"cyberSPADE ACL Message Latency Benchmark\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Number of Agents: {num_agents}\n")
        f.write(f"Messages per Agent: 5000\n")
        f.write(f"Message Payload: 300 bytes\n")
        f.write(f"Spamming Time: {spade_spamming:.2f} ms\n")
        f.write(f"Receiving Time: {spade_receiving:.2f} ms\n")
        f.write(f"Total Time: {spade_spamming + spade_receiving:.2f} ms\n")
        
        if num_agents in jade_baseline:
            f.write(f"\nComparison vs JADE:\n")
            f.write(f"JADE Spamming: {jade_baseline[num_agents]['spamming']} ms\n")
            f.write(f"JADE Receiving: {jade_baseline[num_agents]['receiving']} ms\n")
            f.write(f"Improvement Factor (Spamming): {improvement_spam:.2f}x\n")
            f.write(f"Improvement Factor (Receiving): {improvement_recv:.2f}x\n")
    
    logging.info(f"Results saved to {results_file}")


async def main():
    """Main benchmark execution"""
    print_banner()
    
    # Configuration
    NUM_PING_AGENTS = 8  # Number of ping agents (2-8 for JADE comparison)
    
    print(f"\n[*] Starting ACL Message Latency Benchmark...")
    print(f"[*] Configuration: {NUM_PING_AGENTS} Ping agents → 1 Pong agent")
    print(f"[*] NOTE: Requires running XMPP server on localhost.\n")
    
    # Show comparison table
    print_comparison_table(NUM_PING_AGENTS)
    
    # Initialize pong agent
    pong = PongAgent("pong@localhost", "password")
    
    # Initialize ping agents
    ping_agents = []
    for i in range(1, NUM_PING_AGENTS + 1):
        ping = PingAgent(f"ping{i}@localhost", "password")
        ping_agents.append(ping)
    
    # Start pong agent first
    logging.info("Starting Pong agent (receiver)...")
    await pong.start()
    await asyncio.sleep(0.5)
    
    # Start ping agents
    logging.info(f"Starting {NUM_PING_AGENTS} Ping agents (senders)...")
    for i, ping in enumerate(ping_agents, 1):
        await ping.start()
        if i < NUM_PING_AGENTS:
            await asyncio.sleep(0.2)
    
    await asyncio.sleep(1)
    
    print(f"\n{'='*95}")
    print("All benchmark agents started successfully")
    print(f"{'='*95}\n")
    print("[*] Beginning latency test...")
    print("[*] Sending 5,000 messages per agent...")
    print("[*] Please wait...\n")
    
    try:
        # Wait for benchmark completion
        # Each ping agent will automatically stop after completing its test
        await asyncio.sleep(120)  # Give enough time for completion
        
    except KeyboardInterrupt:
        print("\n[!] Benchmark interrupted by user")
    finally:
        print("\n[*] Stopping benchmark agents...")
        
        for ping in ping_agents:
            await ping.stop()
        await pong.stop()
        
        print("All agents stopped.\n")
        
        # Note: Actual timing results will be printed by PingAgent
        # Here we would aggregate if running multiple concurrent tests


if __name__ == "__main__":
    import os
    os.makedirs('results', exist_ok=True)
    
    asyncio.run(main())
