# cyberSPADE: A Hierarchical Multi-Agent Architecture for Coordinated Cyberdefense
## Overview

**cyberSPADE** is a distributed multi-agent system (MAS) architecture for autonomous cyberdefense operations. Built on the SPADE platform (Smart Python Agent Development Environment), it implements a hierarchical coordination model where a central Monitor agent orchestrates specialized defensive swarms deployed across multiple operational hosts.

This repository contains the reference implementation accompanying the research paper:

> **cyberSPADE: A Hierarchical Multi-Agent Architecture for Coordinated Cyberdefense**  
> *Journal of Cybersecurity and Privacy*, 2026


## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SUPERVISOR HOST                              │
│  ┌────────────────────────────────────────────────────────┐    │
│  │              Monitor Agent                             │    │
│  │  (Strategic Coordination & Situational Awareness)      │    │
│  └────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                             │
                    XMPP Message Server
                             │
        ┌────────────────────┴────────────────────┐
        │                                         │
┌───────▼─────────────────────┐    ┌─────────────▼───────────────┐
│   OPERATIONAL HOST 1        │    │   OPERATIONAL HOST 2        │
│  ┌────────────────────┐     │    │  ┌────────────────────┐     │
│  │ Deployer Agent     │     │    │  │ Deployer Agent     │     │
│  └────────────────────┘     │    │  └────────────────────┘     │
│  ┌────────────────────┐     │    │  ┌────────────────────┐     │
│  │ Defensive Swarms:  │     │    │  │ Defensive Swarms:  │     │
│  │ • Scan Agent       │     │    │  │ • Scan Agent       │     │
│  │ • Miner Agent      │     │    │  │ • Miner Agent      │     │
│  │ • Checker Agent    │     │    │  │ • Checker Agent    │     │
│  │ • Reporter Agent   │     │    │  │ • Reporter Agent   │     │
│  └────────────────────┘     │    │  └────────────────────┘     │
└─────────────────────────────┘    └─────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.8 or higher
- XMPP server (ejabberd, Prosody, or use SPADE's embedded Pyjabber)
- Linux/Unix environment recommended (tested on Ubuntu 24 / Parrot OS)

### Setup

1. **Clone the repository**:
```bash
git clone https://github.com/lusilux/cyberSPADE.git
cd cyberSPADE
```

2. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure XMPP server**:

Option A - Use embedded Pyjabber (simplest for testing):
```bash
spade run
```

## Usage

### Running the Network Defender Swarm

The Network Defender Swarm demonstrates the full detection pipeline: port scanning, version mining, and vulnerability checking.

```bash
# Terminal 1: Start XMPP server (if using Pyjabber)
spade run

# Terminal 2: Run the main system
python main.py
```

**Expected Output:**
- Port scan results (detected services)
- Version mining report (extracted software versions)
- Vulnerability assessment (CVEs from local DB and NVD API)
- Total Detection Time (TDT) metrics

### Running the Benchmark Tests

To reproduce the ACL message latency benchmarks from the paper:

```bash
# Terminal 1: XMPP server
spade run

# Terminal 2: Run ping-pong benchmark
python PingPongMain.py
```

**Benchmark Configuration:**
- 5000 messages per agent pair
- 300-byte message payload
- Compares against JADE baseline from literature

## Experimental Results

### Network Defender Swarm Performance

| Configuration | Total Detection Time (TDT) |
|--------------|---------------------------|
| Single Scan Agent | 11.89 ± 0.33 s |
| 2 Scan Agents | 15.12 s |
| 4 Scan Agents | 13.25 s |
| 16 Scan Agents | **12.88 s** (optimal) |
| 256 Scan Agents | 121.37 s |

**Baseline Comparison:**
- nmap full scan: 173.66 ± 5.32 s
- cyberSPADE: **11.89 ± 0.33 s** (14.6× faster)

### ACL Message Latency (vs. JADE)

| Agents | JADE Spamming (ms) | cyberSPADE Spamming (ms) | Improvement |
|--------|-------------------|--------------------------|-------------|
| 2 | 40,034 | 86 | **465×** |
| 4 | 25,128 | 87 | **289×** |
| 8 | 40,624 | 96 | **423×** |

## Project Structure

```
cyberSPADE/
├── agents/
│   ├── monitor.py          # Strategic coordination agent
│   ├── deployer.py         # Host-local deployment agent
│   ├── defender/
│   │   ├── scan.py         # Port scanning agent
│   │   ├── miner.py        # Version extraction agent
│   │   ├── checker.py      # Vulnerability assessment agent
│   │   └── reporter.py     # Report consolidation agent
│   └── benchmark/
│       ├── ping.py         # Latency test sender
│       └── pong.py         # Latency test receiver
├── data/
│   └── vuln_db.json        # Local vulnerability database
├── main.py                 # Network Defender Swarm demo
├── PingPongMain.py         # Benchmark test harness
├── requirements.txt
└── README.md
```

## Key Components

### Monitor Agent
- Maintains global situational awareness
- Orchestrates swarm deployment
- Consolidates defensive reports
- Manages vulnerability knowledge base

### Network Defender Swarm
1. **Scan Agent**: Asynchronous TCP port scanning (300 concurrent connections)
2. **Miner Agent**: Service version extraction via banner grabbing
3. **Checker Agent**: Vulnerability lookup (local DB + NVD API)
4. **Reporter Agent**: Consolidated security report generation

### Communication Layer
- XMPP-based messaging
- Asyncio-based concurrent execution
- Location-transparent addressing (JID-based)
- Sub-millisecond message latency

## Configuration

### Adjusting Scan Parameters

Edit `agents/defender/scan.py`:

```python
# Concurrent connection limit
sem = asyncio.Semaphore(300)  # Default: 300

# Port range
range(1, 65535)  # Full range, or customize
```

### Vulnerability Database

The local vulnerability database (`data/vuln_db.json`) contains common CVEs for:
- Apache HTTP Server
- Nginx
- OpenSSH
- MySQL/MariaDB
- PostgreSQL
- PHP, Python
- Samba, vsftpd

To update with latest CVEs, the Checker agent automatically queries NVD API for missing entries.

## Research Context

This implementation supports the experimental evaluation presented in:

> L. Alba Torres, M. Rebollo, J. Palanca, and M. Aragonés Lozano, "cyberSPADE: A Hierarchical Multi-Agent Architecture for Coordinated Cyberdefense," *Journal of Cybersecurity and Privacy*, vol. 1, 2026.


## Limitations & Future Work

**Current Limitations:**
- Single-host evaluation (localhost only)
- Network Defender Swarm only (other swarms at conceptual stage)
- Secure authentication protocol not yet implemented
- No fault tolerance mechanisms active

**Future Directions:**
- Multi-host distributed deployment
- Full implementation of Host Defender, Anomaly Detection, and Forensic swarms
- TOTP + post-quantum key exchange for secure communication
- Large-scale cyber range evaluation
- Integration with existing SIEM platforms


## License

This project is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).

**Affiliation:** VRAIN–Valencian Research Institute for Artificial Intelligence, Universitat Politècnica de València



---

**Note:** This is research software intended for experimental evaluation in controlled environments. It is not production-ready and should not be deployed in operational security infrastructure without significant hardening.
