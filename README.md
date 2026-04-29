# NAT Implementation (COMP3331)

## Overview
This project implements a **Network Address Port Translation (NAPT)** device in Python.  
It simulates how a NAT router translates traffic between an internal network (`10.0.0.0/8`) and the external network.

The system supports UDP traffic, ICMP error handling, fragmentation, and asynchronous packet processing.

---

## Project Structure


.
├── nat.py # NAT implementation
├── sample_client.py # Sends test packets to NAT
├── logical_packets.py # Pre-crafted logical packets (provided)
├── server.py # (Your test server)
└── README.md


---

## Features

### Core NAT Functionality
- Outbound translation: `internal_ip:port → external_ip:port`
- Inbound translation: reverse mapping using NAT table
- Port allocation and reuse

### Networking Features
- UDP packet handling
- IP + UDP checksum verification
- TTL decrement + ICMP Time Exceeded
- ICMP error generation:
  - Destination unreachable
  - Fragmentation needed
  - TTL expired

### Advanced Features
- Translation table with idle timeouts
- Fragmentation and reassembly
- MTU handling
- Async I/O using `selectors`

---

## How It Works

### Outbound Flow
1. Client sends packet → NAT internal socket  
2. NAT:
   - Allocates external port
   - Rewrites source IP + port
   - Decrements TTL
   - Forwards to next hop  

### Inbound Flow
1. External packet arrives  
2. NAT:
   - Looks up mapping via destination port  
   - Rewrites destination to internal client  
   - Forwards internally  

---

## Running the NAT

```bash
python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port>
Arguments
Argument	Description
external_ip	Public-facing NAT IP
num_external_ports	Number of available NAT ports
timeout	Mapping timeout (seconds)
mtu	Maximum Transmission Unit
real_internal_port	Port NAT listens on for clients
real_next_hop_port	Port of the external server/router
Example
python3 nat.py 192.168.1.1 100 30 1500 5000 6000
Running the Sample Client

The provided sample_client.py sends pre-crafted packets to test the NAT.

python3 sample_client.py <nat_real_internal_port>
Example
python3 sample_client.py 5000
Notes
Sends packets defined in logical_packets.py
Does not receive responses
Useful for initial outbound testing
Running a Test Server

You can use your own server.py to simulate the external network.

Typical flow:

Start NAT
Start server (listening on <real_next_hop_port>)
Run client
Client → NAT → Server → NAT → Client
Key Components
NAT (nat.py)
Main class handling packet processing
Contains inbound and outbound logic
TranslationTable
Stores active NAT mappings
Handles port allocation + expiration
FragmentBuffer
Reassembles fragmented IP packets
Handles timeout cleanup
Packet Utilities
IP/UDP parsing and building
Checksum computation
ICMP packet creation
Supported Protocols
Protocol	Support
UDP	✅ Full
ICMP	✅ Errors only
TCP	❌ Not supported
Error Handling

The NAT generates ICMP messages for:

TTL expiration
Fragmentation required (DF set)
Port exhaustion
Fragment timeout
Limitations
Only supports UDP
Assumes fixed IP header (no options)
Runs on localhost simulation
No TCP or real routing
Testing Tips
Modify logical_packets.py to test:
TTL expiry
Fragmentation
Invalid checksums
Port exhaustion
Build your own client for better coverage
Add logging to trace packet flow
Learning Outcomes
NAT and NAPT behaviour
Packet structure (IP, UDP, ICMP)
Checksum algorithms
Fragmentation + reassembly
Event-driven networking (selectors)
