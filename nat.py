#!/usr/bin/env python3
"""
COMP3331: NAT implementation

NAPT device sitting between an internal 10.0.0.0/8 network and the outside world

stage 1: basic outbound/inbound address+port translation
stage 2: translation table with idle timeouts
stage 3: async I/O with selectors so both sockets can run at the same time
stage 4: checksum verification, TTL handling, fragmentation, ICMP errors

"""

import sys
import socket
import struct
import time
import threading
import selectors
import ipaddress


# STAGE 1
#******************************protocol constants******************************

# IP protocol numbers
PROTO_ICMP = 1
PROTO_UDP = 17

# all headers are of fixed size
IP_HEADER_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_LEN = 8

# ICMP-related
ICMP_DEST_UNREACH = 3
ICMP_CODE_FRAG_NEEDED = 4 # packet too big, DF set
ICMP_CODE_ADMIN_PROHIB = 13 # no ports left
ICMP_TIME_EXCEEDED = 11
ICMP_CODE_TTL_EXPIRED = 0 # TTL hit zero
ICMP_CODE_FRAG_TIMEOUT = 1 # fragments timed out

# TTL for ICMP error messages
ICMP_TTL = 64

# IP flags (3-bit field, MSB = reserved)
IP_FLAG_DF = 0x2
IP_FLAG_MF = 0x1


#********************************checksum- related******************************

def internet_checksum(data: bytes) -> int:
    # ones' complement checksum used by IP, UDP and ICMP
    # sums all 16-bit words, folds carries back in, returns bitwise NOT
    # odd-length data gets a zero byte padded
    if len(data) % 2 != 0:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def verify_ip_checksum(ip_header: bytes) -> bool:
    # run checksum over the full IP header, it's valid if the result is 0
    result = internet_checksum(ip_header[:IP_HEADER_LEN])
    if result == 0:
        return True
    return False


def compute_ip_checksum(ip_header: bytearray) -> None:
    # zero the checksum field then compute and write it in place
    ip_header[10] = 0
    ip_header[11] = 0
    checksum = internet_checksum(bytes(ip_header[:IP_HEADER_LEN]))
    struct.pack_into('!H', ip_header, 10, checksum)


def compute_udp_checksum(ip_header: bytes, udp_packet: bytes) -> int:
    # if the computed value is 0x0000 we send 0xFFFF instead
    source_ip = ip_header[12:16]
    destination_ip = ip_header[16:20]
    udp_length = len(udp_packet)

    # pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2)
    pseudo_header = struct.pack('!4s4sBBH', source_ip, destination_ip, 0, 
    PROTO_UDP, udp_length)
    checksum = internet_checksum(pseudo_header + udp_packet)

    if checksum != 0:
        return checksum
    return 0xFFFF

def verify_udp_checksum(ip_header: bytes, udp_packet: bytes) -> bool:
    # rebuild the pseudo-header and check the UDP checksum
    # if the stored checksum is 0 treat it as not set and allow it through
    stored_checksum = struct.unpack('!H', udp_packet[6:8])[0]
    if stored_checksum == 0:
        return True

    source_ip = ip_header[12:16]
    destination_ip = ip_header[16:20]
    udp_length = len(udp_packet)
    pseudo_header = struct.pack('!4s4sBBH', source_ip, destination_ip, 0, 
    PROTO_UDP, udp_length)

    # valid if sum over pseudo + full UDP packet (checksum included) == 0
    result = internet_checksum(pseudo_header + udp_packet)
    if result == 0:
        return True
    return False


#***************************packet builders/parsers***************************

def parse_ip_header(raw: bytes):
    # unpack a raw 20-byte IP header into a dict
    # returns None if the data is too short
    if len(raw) < IP_HEADER_LEN:
        return None

    (version_ihl, dscp_ecn, total_length, identifier,
     flags_frag, time_to_live, protocol, checksum,
     source, destination) = struct.unpack('!BBHHHBBH4s4s', raw[:IP_HEADER_LEN])

    version = (version_ihl >> 4) & 0xF
    ihl = version_ihl & 0xF
    flags = (flags_frag >> 13) & 0x7
    fragment_offset = flags_frag & 0x1FFF
    df = bool(flags & IP_FLAG_DF)
    mf = bool(flags & IP_FLAG_MF)

    return {
        'version': version,
        'ihl': ihl,
        'dscp_ecn': dscp_ecn,
        'total_len': total_length,
        'ident': identifier,
        'flags': flags,
        'frag_off': fragment_offset,
        'df': df,
        'mf': mf,
        'ttl': time_to_live,
        'proto': protocol,
        'checksum': checksum,
        'src': socket.inet_ntoa(source),
        'dst': socket.inet_ntoa(destination),
    }


def build_ip_header(src_ip: str, dst_ip: str, protocol: int, total_length: int,
    ttl: int = 64, identifier: int = 0, flags: int = 0, frag_off: int = 0) -> bytes:
    # build a 20-byte IP header + compute its checksum

    version_ihl = (4 << 4) | 5
    dscp_ecn = 0
    flags_frag = ((flags & 0x7) << 13) | (frag_off & 0x1FFF)

    header = bytearray(struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl, dscp_ecn, total_length, identifier,
        flags_frag, ttl, protocol, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    ))
    compute_ip_checksum(header)
    return bytes(header)


def build_udp_packet(ip_header: bytes, src_port: int, dst_port: int,
    payload: bytes) -> bytes:
    # build a UDP packet (header + payload) with a valid checksum
    udp_length = UDP_HEADER_LEN + len(payload)
    udp = bytearray(struct.pack('!HHHH', src_port, dst_port, udp_length, 0))
    udp += payload

    checksum = compute_udp_checksum(ip_header, bytes(udp))
    struct.pack_into('!H', udp, 6, checksum)
    return bytes(udp)


def build_icmp_error(icmp_type: int, icmp_code: int, bad_ip_header: bytes,
bad_udp_header: bytes, next_hop_mtu: int = 0) -> bytes:
    # build an ICMP error: 8-byte header + the original IP+UDP headers
    if icmp_type == ICMP_DEST_UNREACH and icmp_code == ICMP_CODE_FRAG_NEEDED:
        rest = struct.pack('!HH', 0, next_hop_mtu)
    else:
        rest = b'\x00\x00\x00\x00'

    quoted = bad_ip_header[:IP_HEADER_LEN] + bad_udp_header[:UDP_HEADER_LEN]

    icmp = bytearray(4)
    icmp[0] = icmp_type
    icmp[1] = icmp_code
    icmp[2] = 0
    icmp[3] = 0
    icmp += rest + quoted

    checksum = internet_checksum(bytes(icmp))
    struct.pack_into('!H', icmp, 2, checksum)
    return bytes(icmp)


# STAGE 2
#*******************************translation table*******************************

class NATMapping:
    # one entry in the NAT table: maps an internal (IP, port) to an external port
    # last_active is updated whenever a matching packet goes through in either direction

    def __init__(self, internal_ip: str, internal_port: int, external_port: int):
        self.internal_ip = internal_ip
        self.internal_port = internal_port
        self.external_port = external_port
        self.last_active = time.monotonic()

    def touch(self):
        # reset the idle timer whenever a packet matches this mapping
        self.last_active = time.monotonic()


class TranslationTable:
    # NAPT translation table
    # two dicts pointing at the same NATMapping objects

    def __init__(self, num_ports: int, timeout: int):
        self.timeout = timeout
        self.lock = threading.Lock()
        self.free_ports = list(range(1, num_ports + 1))
        self.by_internal = {}
        self.by_external = {}

    def _expire(self):
        # remove any mappings idle for anything longer than self.timeout, 
        # must be called while holding self.lock
        now = time.monotonic()
        expired_mappings = []
        for mapping in self.by_internal.values():
            if now - mapping.last_active >= self.timeout:
                expired_mappings.append(mapping)

        for mapping in expired_mappings:
            del self.by_internal[(mapping.internal_ip, mapping.internal_port)]
            del self.by_external[mapping.external_port]
            self.free_ports.append(mapping.external_port)

    def get_or_create(self, internal_ip: str, internal_port: int):
        # look up an existing mapping for (internal_ip, internal_port) or create
        # returns (mapping, created, port_available) where port_available=False
        # send ICMP admin prohibited

        with self.lock:
            self._expire()
            key = (internal_ip, internal_port)

            if key in self.by_internal:
                mapping = self.by_internal[key]
                mapping.touch()
                return mapping, False, True

            if not self.free_ports:
                return None, True, False

            external_port = self.free_ports.pop(0)
            mapping = NATMapping(internal_ip, internal_port, external_port)
            self.by_internal[key] = mapping
            self.by_external[external_port] = mapping
            return mapping, True, True

    def lookup_by_external(self, external_port: int):
        # find the mapping for an inbound packet arriving on external_port,
        # returns None if no mapping exists
        with self.lock:
            self._expire()
            mapping = self.by_external.get(external_port)
            if mapping:
                mapping.touch()
            return mapping


# STAGE 4
#***********************fragment reassembly buffer******************************

class FragmentBuffer:
    # handles reassembling of fragmented IP datagrams, based on IP identification

    def __init__(self, timeout: int):
        self.timeout = timeout
        self.lock = threading.Lock()
        self.buffers = {}

    def _get_expired_identifiers(self):
        # find datagrams whose most recent fragment arrived too long ago
        now = time.monotonic()
        expired = []
        for identifier, info in self.buffers.items():
            if now - info['last_arrival'] >= self.timeout:
                expired.append(identifier)
        return expired

    def add_fragment(self, identifier: int, fragment_offset: int, mf: bool,
        ip_header: bytes, payload: bytes):
        # store a new fragment and try to reassemble
        # returns (result, expired_info) else None
        with self.lock:
            expired_identifiers = self._get_expired_identifiers()

            # grabing info from expired buffers before deleting so callers can 
            # send ICMP
            expired_info = []
            for expired_identifier in expired_identifiers:
                buffer = self.buffers[expired_identifier]
                zero_header = buffer.get('zero_header')
                zero_payload = buffer['fragments'].get(0)
                expired_info.append((expired_identifier, zero_header, zero_payload))
                del self.buffers[expired_identifier]

            if identifier not in self.buffers:
                self.buffers[identifier] = {
                    'fragments': {},
                    'total_len': None,
                    'last_arrival': time.monotonic(),
                    'zero_header': None,
                }

            buffer = self.buffers[identifier]
            buffer['last_arrival'] = time.monotonic()
            buffer['fragments'][fragment_offset] = payload

            if fragment_offset == 0:
                buffer['zero_header'] = ip_header

            # last fragment tells us the total payload size
            if not mf:
                buffer['total_len'] = fragment_offset * 8 + len(payload)

            result = self._try_reassemble(identifier)
            if result:
                del self.buffers[identifier]

            return result, expired_info

    def _try_reassemble(self, identifier: int):
        # try to assemble a full datagram from buffered fragments
        # walks sorted offsets and checks each fragment starts exactly where 
        # the last one ended
        buffer = self.buffers[identifier]

        if buffer['total_len'] is None or buffer['zero_header'] is None:
            return None

        total_length = buffer['total_len']
        fragments = buffer['fragments']
        offsets = sorted(fragments.keys())

        assembled = bytearray()
        for offset in offsets:
            fragment_data = fragments[offset]
            expected_start = offset * 8

            if len(assembled) != expected_start:
                return None 

            assembled += fragment_data

        if len(assembled) < total_length:
            return None

        # rebuild a clean IP header from the offset-0 fragment
        base_header = bytearray(buffer['zero_header'][:IP_HEADER_LEN])
        new_total = IP_HEADER_LEN + len(assembled)
        struct.pack_into('!H', base_header, 2, new_total)

        # clear MF flag and fragment offset (complete datagram)
        flags_frag = struct.unpack('!H', base_header[6:8])[0]
        flags_frag = flags_frag & ~0x3FFF
        struct.pack_into('!H', base_header, 6, flags_frag)

        compute_ip_checksum(base_header)
        return bytes(base_header), bytes(assembled)

    def get_expired(self):
        # remove and return all timed-out reassembly buffers
        with self.lock:
            now = time.monotonic()
            expired = []
            to_delete = []

            for identifier, info in self.buffers.items():
                if now - info['last_arrival'] >= self.timeout:
                    zero_header = info.get('zero_header')
                    zero_payload = info['fragments'].get(0)
                    expired.append((identifier, zero_header, zero_payload))
                    to_delete.append(identifier)

            for identifier in to_delete:
                del self.buffers[identifier]

            return expired


#************************************NAT core***********************************

class NAT:
    # the NAT device sits between an internal socket (client process) and 
    # external socket (next hop)
    # translates addresses and ports in both directions using the translation table

    def __init__(self, external_ip, num_external_ports, timeout, mtu,
    real_internal_port, real_next_hop_port):
        self.external_ip = external_ip
        self.num_external_ports = num_external_ports
        self.timeout = timeout
        self.mtu = mtu
        self.real_next_hop_port = real_next_hop_port

        self.table = TranslationTable(num_external_ports, timeout)
        self.fragment_buffer = FragmentBuffer(timeout)

        self.icmp_id_counter = 0
        self.icmp_id_lock = threading.Lock()

        # we learn the client's real UDP address from the first packet it sends
        self.client_addr = None

        # internal socket: clients send logical packets here
        self.internal_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.internal_socket.bind(('127.0.0.1', real_internal_port))

        self.external_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.external_socket.bind(('127.0.0.1', 0))

        print(f"[NAT] internal socket on port {real_internal_port}")
        print(f"[NAT] external socket on port {self.external_socket.getsockname()[1]}")
        print(f"[NAT] external IP: {external_ip}, port pool: 1-{num_external_ports}")
        print(f"[NAT] timeout: {timeout}s, MTU: {mtu} bytes")


    #**************************************************************************
    #********************************helpers***********************************

    def _next_icmp_id(self) -> int:
        # wraps at 16 bits
        with self.icmp_id_lock:
            self.icmp_id_counter = (self.icmp_id_counter + 1) & 0xFFFF
            return self.icmp_id_counter

    def _is_internal(self, ip_address_str: str) -> bool:
        # check whether an IP is in our internal range 10.0.0.0/8
        try:
            addr = ipaddress.ip_address(ip_address_str)
            network = ipaddress.ip_network('10.0.0.0/8')
            if addr in network:
                return True
            return False
        except ValueError:
            return False

    #**************************************************************************
    #*******************************send helpers*******************************

    def _send_internal(self, ip_packet: bytes):
        # send a logical packet back into the internal network
        if self.client_addr:
            self.internal_socket.sendto(ip_packet, self.client_addr)
        else:
            print("[NAT] WARN: client addr not known yet, dropping inbound packet")

    def _send_external(self, ip_packet: bytes):
        # forward a logical packet out to the next hop
        self.external_socket.sendto(ip_packet, ('127.0.0.1', self.real_next_hop_port))

    def _send_icmp_to_internal(self, icmp_type: int, icmp_code: int,
    bad_ip_header: bytes, bad_udp_header: bytes, original_dst_ip: str, 
    next_hop_mtu: int = 0):
        # generate an ICMP error and send it back to the internal host
        icmp_payload = build_icmp_error(
            icmp_type, icmp_code,
            bad_ip_header, bad_udp_header,
            next_hop_mtu=next_hop_mtu
        )
        parsed = parse_ip_header(bad_ip_header)
        original_src_ip = parsed['src']
        total_length = IP_HEADER_LEN + len(icmp_payload)
        identifier = self._next_icmp_id()

        ip_header = build_ip_header(
            src_ip=self.external_ip,
            dst_ip=original_src_ip,
            protocol=PROTO_ICMP,
            total_length=total_length,
            ttl=ICMP_TTL,
            identifier=identifier,
        )
        self._send_internal(ip_header + icmp_payload)
        print(f"[NAT] ICMP {icmp_type}/{icmp_code} -> {original_src_ip}")


    #*****************outbound path: internal -> external***********************

    def handle_outbound(self, raw: bytes, addr):
        # process a logical IP packet from the internal socket

        if self.client_addr is None:
            self.client_addr = addr

        if len(raw) < IP_HEADER_LEN:
            print("[NAT] outbound: packet too short, dropping")
            return

        ip = parse_ip_header(raw)
        if ip is None:
            return

        if not verify_ip_checksum(raw):
            print("[NAT] outbound: bad IP checksum, dropping")
            return

        protocol = ip['proto']
        total_length = ip['total_len']
        fragment_offset = ip['frag_off']
        mf = ip['mf']
        identifier = ip['ident']

        # if this is a fragment, buffer it and wait for all pieces
        # we check IP checksum per-fragment but hold off on UDP checksum and 
        # translation until its reassembled completely
        if fragment_offset != 0 or mf:
            payload_raw = raw[IP_HEADER_LEN:total_length]
            result, expired = self.fragment_buffer.add_fragment(
                identifier, fragment_offset, mf, raw[:IP_HEADER_LEN], payload_raw
            )

            for exp_identifier, zero_header, zero_payload in expired:
                if zero_header is not None and zero_payload is not None:
                    if len(zero_payload) >= UDP_HEADER_LEN:
                        exp_dst = parse_ip_header(zero_header)['dst']
                        self._send_icmp_to_internal(
                            ICMP_TIME_EXCEEDED, ICMP_CODE_FRAG_TIMEOUT,
                            zero_header, zero_payload[:UDP_HEADER_LEN],
                            exp_dst
                        )

            if result is None:
                # waiting for fragments
                return

            ip_header_raw, udp_raw = result
            ip = parse_ip_header(ip_header_raw)
            raw = ip_header_raw + udp_raw
            total_length = ip['total_len']
            protocol = ip['proto']

        if protocol != PROTO_UDP:
            print(f"[NAT] outbound: non-UDP protocol {protocol}, dropping")
            return

        udp_raw = raw[IP_HEADER_LEN:total_length]
        if len(udp_raw) < UDP_HEADER_LEN:
            print("[NAT] outbound: UDP packet too short")
            return

        if not verify_udp_checksum(raw[:IP_HEADER_LEN], udp_raw):
            print("[NAT] outbound: bad UDP checksum, dropping")
            return

        src_ip = ip['src']
        dst_ip = ip['dst']
        src_port = struct.unpack('!H', udp_raw[0:2])[0]
        dst_port = struct.unpack('!H', udp_raw[2:4])[0]
        udp_payload = udp_raw[UDP_HEADER_LEN:]

        print(f"[NAT] outbound: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # routers decrement TTL and drop at 0, send ICMP time exceeded 
        # so the sender knows the packet didn't make it
        time_to_live = ip['ttl']
        if time_to_live <= 1:
            print("[NAT] outbound: TTL expired, sending ICMP time exceeded")
            self._send_icmp_to_internal(
                ICMP_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED,
                raw[:IP_HEADER_LEN], udp_raw[:UDP_HEADER_LEN],
                dst_ip
            )
            return
        new_ttl = time_to_live - 1

        mapping, created, port_available = self.table.get_or_create(src_ip, src_port)
        if not port_available:
            print("[NAT] outbound: port pool exhausted, sending ICMP admin prohibited")
            self._send_icmp_to_internal(
                ICMP_DEST_UNREACH, ICMP_CODE_ADMIN_PROHIB,
                raw[:IP_HEADER_LEN], udp_raw[:UDP_HEADER_LEN],
                dst_ip
            )
            return

        external_port = mapping.external_port
        print(f"[NAT] mapping: {src_ip}:{src_port} <-> {self.external_ip}:{external_port}")

        new_total = IP_HEADER_LEN + UDP_HEADER_LEN + len(udp_payload)

        # if the translated packet is too large: DF set means we can't fragment 
        # so send ICMP frag needed, otherwise fragment and send each piece
        if new_total > self.mtu:
            if ip['df']:
                print(f"[NAT] outbound: packet too large ({new_total}>{self.mtu}) and DF set")
                self._send_icmp_to_internal(
                    ICMP_DEST_UNREACH, ICMP_CODE_FRAG_NEEDED,
                    raw[:IP_HEADER_LEN], udp_raw[:UDP_HEADER_LEN],
                    dst_ip, next_hop_mtu=self.mtu
                )
                return

            self._fragment_and_send(
                src_ip=self.external_ip,
                dst_ip=dst_ip,
                src_port=external_port,
                dst_port=dst_port,
                udp_payload=udp_payload,
                orig_identifier=ip['ident'],
                ttl=new_ttl,
            )
            return

        # build the translated packet and forward it
        new_ip_header = build_ip_header(
            src_ip=self.external_ip,
            dst_ip=dst_ip,
            protocol=PROTO_UDP,
            total_length=new_total,
            ttl=new_ttl,
            identifier=ip['ident'],
            flags=ip['flags'] & ~IP_FLAG_MF,
            frag_off=0,
        )
        new_udp = build_udp_packet(new_ip_header, external_port, dst_port, udp_payload)

        self._send_external(new_ip_header + new_udp)
        print(f"[NAT] outbound forwarded: {self.external_ip}:{external_port} -> {dst_ip}:{dst_port}")

    def _fragment_and_send(self, src_ip, dst_ip, src_port, dst_port,
                           udp_payload, orig_identifier, ttl):
        # split an oversized outbound packet into MTU-sized fragments and send each one

        # build the full UDP packet first to get a valid checksum over 
        # everything, then each fragment just carries a slice of it
        full_length = IP_HEADER_LEN + UDP_HEADER_LEN + len(udp_payload)
        temp_ip_header = build_ip_header(src_ip, dst_ip, PROTO_UDP, full_length,
                                         ttl=ttl, identifier=orig_identifier)
        full_udp = build_udp_packet(temp_ip_header, src_port, dst_port, udp_payload)

        data_to_send = full_udp
        max_data_per_fragment = self.mtu - IP_HEADER_LEN
        max_data_per_fragment = (max_data_per_fragment // 8) * 8

        current_offset = 0
        fragment_number = 0

        while current_offset < len(data_to_send):
            remaining = len(data_to_send) - current_offset

            if remaining <= self.mtu - IP_HEADER_LEN:
                chunk = data_to_send[current_offset:]
                mf = False
            else:
                chunk = data_to_send[current_offset:current_offset + max_data_per_fragment]
                mf = True

            fragment_offset_blocks = current_offset // 8

            if mf:
                flags = IP_FLAG_MF
            else:
                flags = 0

            fragment_total = IP_HEADER_LEN + len(chunk)

            fragment_ip_header = build_ip_header(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=PROTO_UDP,
                total_length=fragment_total,
                ttl=ttl,
                identifier=orig_identifier,
                flags=flags,
                frag_off=fragment_offset_blocks,
            )
            self._send_external(fragment_ip_header + chunk)
            print(f"[NAT] fragment {fragment_number}: offset={fragment_offset_blocks * 8}B, "
                  f"len={len(chunk)}B, mf={int(mf)}")

            current_offset += len(chunk)
            fragment_number += 1

    #*****************inbound path: external to internal************************

    def handle_inbound(self, raw: bytes):
        # process an IP packet from the external socket
        if len(raw) < IP_HEADER_LEN:
            print("[NAT] inbound: packet too short, dropping")
            return

        ip = parse_ip_header(raw)
        if ip is None:
            return

        if not verify_ip_checksum(raw):
            print("[NAT] inbound: bad IP checksum, dropping")
            return

        fragment_offset = ip['frag_off']
        mf = ip['mf']
        identifier = ip['ident']
        total_length = ip['total_len']

        if fragment_offset != 0 or mf:
            payload_raw = raw[IP_HEADER_LEN:total_length]
            result, expired = self.fragment_buffer.add_fragment(
                identifier, fragment_offset, mf, raw[:IP_HEADER_LEN], payload_raw
            )

            # spec says we don't need to generate ICMP for inbound frag timeout
            for exp_identifier, zero_header, zero_payload in expired:
                print(f"[NAT] inbound reassembly timed out for identifier={exp_identifier}, discarding")

            if result is None:
                return

            ip_header_raw, udp_raw_reassembled = result
            ip = parse_ip_header(ip_header_raw)
            raw = ip_header_raw + udp_raw_reassembled
            total_length = ip['total_len']

        protocol = ip['proto']
        if protocol != PROTO_UDP:
            print(f"[NAT] inbound: non-UDP protocol {protocol}, dropping")
            return

        udp_raw = raw[IP_HEADER_LEN:total_length]
        if len(udp_raw) < UDP_HEADER_LEN:
            return

        if not verify_udp_checksum(raw[:IP_HEADER_LEN], udp_raw):
            print("[NAT] inbound: bad UDP checksum, dropping")
            return

        src_ip = ip['src']
        dst_ip = ip['dst']
        src_port = struct.unpack('!H', udp_raw[0:2])[0]
        dst_port = struct.unpack('!H', udp_raw[2:4])[0]
        udp_payload = udp_raw[UDP_HEADER_LEN:]

        print(f"[NAT] inbound: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        # only forward if there's an active mapping for this destination port
        # unsolicited inbound packets with no matching flow get dropped silently 
        mapping = self.table.lookup_by_external(dst_port)
        if mapping is None:
            print(f"[NAT] inbound: no mapping for external port {dst_port}, dropping")
            return

        time_to_live = ip['ttl']
        if time_to_live <= 1:
            print("[NAT] inbound: TTL expired, sending ICMP time exceeded")
            self._send_icmp_externally(
                ICMP_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED,
                raw[:IP_HEADER_LEN], udp_raw[:UDP_HEADER_LEN],
            )
            return
        new_ttl = time_to_live - 1

        # reverse translation: rewrite dst_ip/port back to the internal host
        internal_ip = mapping.internal_ip
        internal_port = mapping.internal_port

        new_total = IP_HEADER_LEN + UDP_HEADER_LEN + len(udp_payload)
        new_ip_header = build_ip_header(
            src_ip=src_ip,
            dst_ip=internal_ip,
            protocol=PROTO_UDP,
            total_length=new_total,
            ttl=new_ttl,
            identifier=ip['ident'],
            flags=ip['flags'] & ~IP_FLAG_MF,
            frag_off=0,
        )
        new_udp = build_udp_packet(new_ip_header, src_port, internal_port, udp_payload)

        self._send_internal(new_ip_header + new_udp)
        print(f"[NAT] inbound forwarded: {src_ip}:{src_port} -> {internal_ip}:{internal_port}")

    def _send_icmp_externally(self, icmp_type: int, icmp_code: int,
     bad_ip_header: bytes, bad_udp_header: bytes, next_hop_mtu: int = 0):
        # generate an ICMP error and send it back to the external sender
        icmp_payload = build_icmp_error(
            icmp_type, icmp_code,
            bad_ip_header, bad_udp_header,
            next_hop_mtu=next_hop_mtu
        )
        parsed = parse_ip_header(bad_ip_header)
        original_src_ip = parsed['src']
        total_length = IP_HEADER_LEN + len(icmp_payload)
        identifier = self._next_icmp_id()

        ip_header = build_ip_header(
            src_ip=self.external_ip,
            dst_ip=original_src_ip,
            protocol=PROTO_ICMP,
            total_length=total_length,
            ttl=ICMP_TTL,
            identifier=identifier,
        )
        self._send_external(ip_header + icmp_payload)
        print(f"[NAT] ICMP {icmp_type}/{icmp_code} -> {original_src_ip} (external)")


    def _check_frag_timeouts(self):
        # called once per second to catch stale reassembly buffers
        expired = self.fragment_buffer.get_expired()
        for identifier, zero_header, zero_payload in expired:
            print(f"[NAT] reassembly timed out for identifier={identifier}, discarding")

    #*********************STAGE 3: main event loop (async)**********************

    def run(self):
        # main I/O loop using selectors to watch both sockets at once
        # 1-second timeout on select() let's us run maintenance even if no traffic
        selector = selectors.DefaultSelector()
        selector.register(self.internal_socket, selectors.EVENT_READ, data='internal')
        selector.register(self.external_socket, selectors.EVENT_READ, data='external')

        print("[NAT] running. press Ctrl+C to stop.")
        last_check = time.monotonic()

        try:
            while True:
                events = selector.select(timeout=1.0)

                for key, mask in events:
                    sock = key.fileobj
                    direction = key.data
                    try:
                        raw, addr = sock.recvfrom(65535)
                    except Exception as e:
                        print(f"[NAT] recvfrom error: {e}")
                        continue

                    if direction == 'internal':
                        self.handle_outbound(raw, addr)
                    else:
                        self.handle_inbound(raw)

                now = time.monotonic()
                if now - last_check >= 1.0:
                    self._check_frag_timeouts()
                    last_check = now

        except KeyboardInterrupt:
            print("\n[NAT] shutting down.")
        finally:
            selector.close()
            self.internal_socket.close()
            self.external_socket.close()



#******************************** MAIN *****************************************

def main():
    if len(sys.argv) != 7:
        print(
            "usage: python3 nat.py <external_ip> <num_external_ports> "
            "<timeout> <mtu> <real_internal_port> <real_next_hop_port>"
        )
        sys.exit(1)

    try:
        external_ip = sys.argv[1]
        num_external_ports = int(sys.argv[2])
        timeout = int(sys.argv[3])
        mtu = int(sys.argv[4])
        real_internal_port = int(sys.argv[5])
        real_next_hop_port = int(sys.argv[6])
    except ValueError:
        print("Error: Port numbers, timeout, and MTU must be integers.")
        sys.exit(1)

    nat = NAT(
        external_ip=external_ip,
        num_external_ports=num_external_ports,
        timeout=timeout,
        mtu=mtu,
        real_internal_port=real_internal_port,
        real_next_hop_port=real_next_hop_port
    )
    
    nat.run()

if __name__ == "__main__":
    main()