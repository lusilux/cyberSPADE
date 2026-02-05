"""
Ping Agent - ACL Message Latency Benchmark Sender

This agent sends N messages to a Pong agent and measures:
- Spamming time: Time to send all messages
- Receiving time: Time to receive all responses
- Per-message latency statistics
"""

import time
import json
from datetime import datetime
from spade.agent import Agent
from spade.behaviour import OneShotBehaviour
from spade.message import Message


class PingAgent(Agent):
    class PingBehaviour(OneShotBehaviour):
        async def run(self):
            # Configuration
            N = 5000                    # Number of messages (as in JADE paper)
            payload = "A" * 300         # ~300 bytes payload
            
            agent_name = str(self.agent.jid).split('@')[0]
            
            print(f"\n{'─'*80}")
            print(f" {agent_name.upper()} - Starting Benchmark")
            print(f"{'─'*80}")
            print(f"Target: pong@localhost")
            print(f"Messages: {N:,}")
            print(f"Payload: {len(payload)} bytes")
            print(f"{'─'*80}\n")

            # -------------------------
            # PHASE 1: SPAMMING (Sending)
            # -------------------------
            print(f"[{agent_name}] Phase 1: Sending {N:,} messages...")
            
            t_spam_start = time.perf_counter()
            
            for i in range(N):
                msg = Message(to="pong@localhost")
                msg.set_metadata("type", "latency_test")
                msg.set_metadata("sequence", str(i))
                msg.set_metadata("sender", agent_name)
                msg.body = payload
                await self.send(msg)
                
                # Progress indicator every 1000 messages
                if (i + 1) % 1000 == 0:
                    print(f"[{agent_name}]   Sent: {i + 1:,}/{N:,} messages ({(i+1)/N*100:.1f}%)")
            
            t_spam_end = time.perf_counter()
            spamming_time = (t_spam_end - t_spam_start) * 1000  # Convert to ms
            
            print(f"[{agent_name}] ✓ Phase 1 complete: {spamming_time:.2f} ms")
            print(f"[{agent_name}]   Average send time: {spamming_time/N:.6f} ms/message\n")

            # -------------------------
            # PHASE 2: RECEIVING (Processing responses)
            # -------------------------
            print(f"[{agent_name}] Phase 2: Receiving {N:,} responses...")
            
            t_recv_start = time.perf_counter()
            received = 0
            missed = 0
            
            while received < N:
                reply = await self.receive(timeout=10)
                if reply:
                    received += 1
                    
                    # Progress indicator every 1000 messages
                    if received % 1000 == 0:
                        print(f"[{agent_name}]   Received: {received:,}/{N:,} messages ({received/N*100:.1f}%)")
                else:
                    missed += 1
                    if missed > 100:  # Safety timeout
                        print(f"[{agent_name}] ⚠ Timeout: Only {received:,}/{N:,} messages received")
                        break
            
            t_recv_end = time.perf_counter()
            receiving_time = (t_recv_end - t_recv_start) * 1000  # Convert to ms
            
            print(f"[{agent_name}] ✓ Phase 2 complete: {receiving_time:.2f} ms")
            print(f"[{agent_name}]   Average receive time: {receiving_time/received:.6f} ms/message\n")

            # -------------------------
            # RESULTS SUMMARY
            # -------------------------
            total_time = spamming_time + receiving_time
            avg_rtt = total_time / received if received > 0 else 0
            
            print(f"\n{'═'*80}")
            print(f" {agent_name.upper()} - BENCHMARK RESULTS")
            print(f"{'═'*80}")
            print(f"Messages Sent:                  {N:>15,}")
            print(f"Messages Received:              {received:>15,}")
            print(f"Success Rate:                   {received/N*100:>14.2f}%")
            print(f"{'─'*80}")
            print(f"Spamming Time:                  {spamming_time:>14.2f} ms")
            print(f"Receiving Time:                 {receiving_time:>14.2f} ms")
            print(f"Total Time:                     {total_time:>14.2f} ms")
            print(f"{'─'*80}")
            print(f"Avg. Message Send Time:         {spamming_time/N:>14.6f} ms")
            print(f"Avg. Message Receive Time:      {receiving_time/received if received > 0 else 0:>14.6f} ms")
            print(f"Avg. Round-Trip Time (RTT):     {avg_rtt:>14.6f} ms")
            print(f"{'─'*80}")
            print(f"Throughput (messages/sec):      {N/(total_time/1000):>14.2f}")
            print(f"{'═'*80}\n")
            
            # Save individual results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            results = {
                'agent': agent_name,
                'timestamp': timestamp,
                'messages_sent': N,
                'messages_received': received,
                'success_rate': received/N*100,
                'spamming_time_ms': spamming_time,
                'receiving_time_ms': receiving_time,
                'total_time_ms': total_time,
                'avg_send_time_ms': spamming_time/N,
                'avg_receive_time_ms': receiving_time/received if received > 0 else 0,
                'avg_rtt_ms': avg_rtt,
                'throughput_msgs_per_sec': N/(total_time/1000)
            }
            
            filename = f'results/{agent_name}_results_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"[{agent_name}] Results saved to: {filename}")
            
            # Stop this agent
            print(f"[{agent_name}] Stopping agent...\n")
            await self.agent.stop()

    async def setup(self):
        """Agent initialization"""
        print(f"[{str(self.jid).split('@')[0]}] Agent initialized and ready")
        self.add_behaviour(self.PingBehaviour())
