# NAT Implementation (COMP3331)

## Description
Implemented a **Network Address Port Translation (NAPT) system in Python**, simulating a NAT router between an internal network (`10.0.0.0/8`) and the external network.  
The system supports UDP traffic with dynamic port mapping, asynchronous packet processing, and realistic networking behaviours including checksum validation, fragmentation, and ICMP error handling.

---

## Features

- **Bidirectional NAT translation** (internal ↔ external)
- **Dynamic port allocation** with reuse
- **Stateful translation table** with idle timeouts
- **Asynchronous I/O** using `selectors`
- **IP and UDP checksum verification**
- **TTL handling** with ICMP Time Exceeded messages
- **Fragmentation and reassembly** (MTU-aware)
- **ICMP error generation**:
  - Destination unreachable
  - Fragmentation needed (DF flag)
  - TTL expired
  - Fragment timeout

---

## Technologies

- Python 3
- Socket programming (UDP)
- Low-level packet manipulation (IP, UDP, ICMP)
- Event-driven architecture (`selectors`)
- Thread-safe data structures

---

## How It Works

### Outbound (Internal → External)
1. Internal client sends a UDP packet
2. NAT allocates an external port
3. Source IP/port is rewritten
4. TTL is decremented and checks validated
5. Packet is forwarded to the next hop

### Inbound (External → Internal)
1. Packet arrives at NAT external interface
2. NAT looks up mapping using destination port
3. Destination IP/port rewritten to internal client
4. Packet forwarded internally

---

## Usage

```bash
python3 nat.py <external_ip> <num_external_ports> <timeout> <mtu> <real_internal_port> <real_next_hop_port>
