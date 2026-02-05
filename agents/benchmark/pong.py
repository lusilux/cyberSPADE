"""
Pong Agent - ACL Message Latency Benchmark Receiver

This agent receives messages from Ping agents and immediately replies.
Provides statistics on messages processed.
"""

from spade.agent import Agent
from spade.behaviour import CyclicBehaviour
from spade.message import Message


class PongAgent(Agent):
    class PongBehaviour(CyclicBehaviour):
        async def on_start(self):
            """Initialize message counter"""
            self.messages_received = 0
            self.messages_sent = 0
            print(f"[pong] Agent ready to receive messages")
        
        async def run(self):
            """Process incoming messages and reply"""
            msg = await self.receive(timeout=5)
            
            if msg and msg.get_metadata("type") == "latency_test":
                self.messages_received += 1
                
                # Echo reply
                reply = Message(to=str(msg.sender))
                reply.set_metadata("type", "latency_reply")
                reply.set_metadata("sequence", msg.get_metadata("sequence", ""))
                reply.body = msg.body
                
                await self.send(reply)
                self.messages_sent += 1
                
                # Progress indicator every 5000 messages
                if self.messages_received % 5000 == 0:
                    print(f"[pong] Processed: {self.messages_received:,} messages")
        
        async def on_end(self):
            """Print final statistics"""
            print(f"\n[pong] Benchmark session complete")
            print(f"[pong] Total messages received: {self.messages_received:,}")
            print(f"[pong] Total replies sent: {self.messages_sent:,}")

    async def setup(self):
        """Agent initialization"""
        print(f"[pong] Pong Agent initialized")
        self.add_behaviour(self.PongBehaviour())
