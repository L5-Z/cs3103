#!/usr/bin/env python3
"""
CS3103 - Computer Networks Practice
Assignment 3B - Real-Time GeoTracer

Name: Muhammad Alfaatih Bin Mohamed Faizal
Matric: A0253120Y
"""

import socket
import struct
import time
import select
import sys
import random
import requests
from typing import List

# -------------------------------------------------------------
# Configuration (default values but can be overridden by CLI args)
# -------------------------------------------------------------
DEFAULT_DEST_PORT = 80 # HTTP port (can be changed to 443 or any other)
DEFAULT_MAX_HOPS  = 30
DEFAULT_PROBES    = 3
DEFAULT_TIMEOUT_S = 2.5

# -------------------------------------------------------------
# Utilities: checksums & header builders
# -------------------------------------------------------------
def checksum(msg: bytes):

    # Pad with 0 if the length is odd
    if len(msg) % 2 == 1:
        msg += b'\x00'
    
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = (s + w) & 0xffffffff # Keep a wider accumulator (at least 32 bits) to hold carries
    
    # Fold 32 bit sum to 16 bits by adding carries
    while (s >> 16) != 0:
        s = (s & 0xffff) + (s >> 16)
    
    #complement and mask to 4 byte short
    return (~s) & 0xffff

def build_ip_header(source_ip: str, dest_ip: str, ip_ttl: int, payload_len: int, ip_id: int):

    # IP Header fields
    ip_ihl = 5  # Internet Header Length (5 * 4 = 20 bytes)
    ip_ver = 4 # IPv4
    ip_ihl_ver = (ip_ver << 4) + ip_ihl # Version + IHL
    ip_tos = 0 # Type of Service
    ip_tot_len = 20 + payload_len # total length (IP header + payload)
    ip_frag_off = 0 # Flags + Fragment offset
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0 # initial checksum (0 before calculation), prev 10
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)

    # Pack the initial IP header with checksum = 0 for calculation
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    chksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, chksum, ip_saddr, ip_daddr)
    
    return ip_header

def build_tcp_header(src_ip: str, dst_ip: str, source_port: int, dest_port: int, tcp_seq: int, payload: bytes=b''):
    
    # tcp_seq = 0 
    tcp_ack_seq = 0
    tcp_doff = 5  # 5 * 4 = 20 bytes
    offset_res = (tcp_doff << 4) + 0
    tcp_flags = 0b000010
    tcp_window = socket.htons(5840)
    tcp_check = 0 
    tcp_urg_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, tcp_seq, tcp_ack_seq, offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    # Pseudo-header
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    pseudo_header = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
    
    tcp_check = checksum(pseudo_header + tcp_header + payload)

    tcp_header = struct.pack('!HHLLBBH', source_port, dest_port, tcp_seq, tcp_ack_seq, offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    return tcp_header

# -------------------------------------------------------------
# Geolocation by API
# -------------------------------------------------------------
def geo_lookup(ip: str):

    url = f"http://ip-api.com/json/{ip or ''}"
    params = {
        "fields": "status,country,regionName,as,org"
    }
    r = requests.get(url, params=params, timeout=5)
    r.raise_for_status()

    data = r.json()
    if data.get("status") != "success":
        return ["Unknown Location", "NIL"]

    country = data.get("country")
    location = data.get("regionName")
    As = data.get("as")
    org = data.get("org")

    return [f"({location}, {country})", f"{org} [{As}]"]

# -------------------------------------------------------------
# Packet parsers
# -------------------------------------------------------------
def parse_ipv4_header(pkt: bytes, offset: int = 0):

    iph = pkt[offset:offset+20]
    if len(iph) < 20:
        raise ValueError("Short IP header")
    ver_ihl, _, tot_len, _, _, ttl, proto, _, saddr, daddr = struct.unpack('!BBHHHBBH4s4s', iph)
    ihl = (ver_ihl & 0x0F) * 4

    return (socket.inet_ntoa(saddr), socket.inet_ntoa(daddr), proto, ihl, tot_len, ttl)

def parse_icmp_header(pkt: bytes, offset: int = 0):

    if len(pkt) < offset + 8:
        raise ValueError("Short ICMP header")
    icmp_type, icmp_code, icmp_chksum = struct.unpack('!BBH', pkt[offset:offset+4])

    return icmp_type, icmp_code, icmp_chksum

# Parse full TCP header (20+B)
def parse_tcp_header(pkt: bytes, offset: int):

    if len(pkt) < offset + 20:
        raise ValueError("Short TCP header")
    src_port, dst_port, seq, ack_seq, doff_res, flags, _, _, _ = struct.unpack('!HHLLBBHHH', pkt[offset:offset+20])
    data_offset = (doff_res >> 4) * 4
    return src_port, dst_port, seq, ack_seq, data_offset, flags

"""
def tcp_flags_to_str(flags: int) -> str:
    names = []
    if flags & 0x01: names.append("FIN")
    if flags & 0x02: names.append("SYN")
    if flags & 0x04: names.append("RST")
    if flags & 0x08: names.append("PSH")
    if flags & 0x10: names.append("ACK")
    if flags & 0x20: names.append("URG")
    if flags & 0x40: names.append("ECE")
    if flags & 0x80: names.append("CWR")
    return "|".join(names) if names else "NONE"
"""

# For matching our probe inside ICMP Time Exceeded payloads(includes original IP header + first 8 bytes of transport header)
def parse_tcp_first8(pkt: bytes, offset: int):

    if len(pkt) < offset + 8:
        raise ValueError("Short TCP first8")
    src_port, dst_port, seq = struct.unpack('!HHI', pkt[offset:offset+8])
    return src_port, dst_port, seq

def rdns_name(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]  # hostname from PTR
    except (socket.herror, socket.gaierror, TimeoutError):
        return None

# -------------------------------------------------------------
# Geotrace core
# -------------------------------------------------------------
def geotrace(destination: str, dest_port: int = DEFAULT_DEST_PORT, max_hops: int = DEFAULT_MAX_HOPS, probes_per_hop: int = DEFAULT_PROBES, timeout_s: float = DEFAULT_TIMEOUT_S):

    # Resolve destination
    try:
        dest_ip = socket.gethostbyname(destination)
    except Exception as e:
        print(f"[ERROR] Could not resolve destination '{destination}': {e}")
        return

    # Pick a source IP by creating a dummy UDP socket (no send) to the target
    # to force OS to select the outgoing interface & source address.
    temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        temp.connect((dest_ip, 9))
        src_ip = temp.getsockname()[0]
    finally:
        temp.close()
    print("[INFO] Geolocation via ip-api.com (free tier ~45 req/min; results cached).\n")
    print(f"GeoTracer to {destination} ({dest_ip}), TCP port {dest_port}")
    print(f"Source: {src_ip}  |  Max Hops: {max_hops}  |  Max Retries: {probes_per_hop - 1}  |  Timeout: {timeout_s} \n")

    # Create RAW sockets (Snippet 1)
    try:
        send_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_tcp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_tcp_sock  = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # Non-blocking
        recv_icmp_sock.setblocking(False)
        recv_tcp_sock.setblocking(False)
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo/root to use RAW sockets.")
        return
    except Exception as e:
        print(f"[ERROR] Could not open RAW sockets: {e}")
        return

    # Base parameters for probe matching and identification
    src_port = random.randint(30000, 60000)
    base_seq = random.randint(0, 0x7fffffff)

    dest_reached = False
    hops_taken = 0

    for ttl in range(1, max_hops + 1):
        hop_rtts: List[float] = []
        hop_ips: List[str] = []
        
        print(f"Hop {ttl}:", end="", flush=True)

        for p in range(probes_per_hop):
            # Unique identifier per probe
            tcp_seq = base_seq + ttl * 100 + p

            # Build IP+TCP SYN (Snippet 2)
            ip_id = 54321 # Unique IP ID per packet
            payload_len = 20
            ip_header = build_ip_header(src_ip, dest_ip, ttl, payload_len, ip_id)
            tcp_header = build_tcp_header(src_ip, dest_ip, src_port, dest_port, tcp_seq)
            packet = ip_header + tcp_header

            # Send
            t0 = time.time()
            try:
                # Set socket TTL also (kernel may ignore IP_HDRINCL TTL on some systems)
                send_tcp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                send_tcp_sock.sendto(packet, (dest_ip, dest_port))
            except Exception as e:
                print(f"[send-err:{e}]", end=" ", flush=True)
                hop_rtts.append(None)  # type: ignore
                continue

            # Wait for either ICMP (time exceeded) or TCP (RST/ACK) matching this probe
            got_reply = False
            end_time = t0 + timeout_s
            key = (src_port, tcp_seq)
            while time.time() < end_time:
                remaining = end_time - time.time()
                if remaining <= 0:
                    break
                receive_socks, _, _ = select.select([recv_icmp_sock, recv_tcp_sock], [], [], remaining)

                # Check ICMP
                if recv_icmp_sock in receive_socks:
                    try:
                        pkt, _ = recv_icmp_sock.recvfrom(65535)
                        outer_src_ip, _, _, outer_ihl, _, _ = parse_ipv4_header(pkt, 0)
                        # ICMP header afterwards
                        icmp_type, _, _ = parse_icmp_header(pkt, outer_ihl)
                        # ICMP payload contains original IP header + first 8 bytes of TCP header
                        inner_offset = outer_ihl + 8
                        _, _, inner_proto, inner_ihl, _, _ = parse_ipv4_header(pkt, inner_offset)
                        if inner_proto != socket.IPPROTO_TCP:
                            continue
                        tcp_off = inner_offset + inner_ihl
                        sp, _, sseq = parse_tcp_first8(pkt, tcp_off)
                        if (sp, sseq) != key:
                            continue  # not correct probe
                        if icmp_type == 11:  # Time Exceeded
                            rtt = (time.time() - t0) * 1000.0
                            hop_rtts.append(rtt)
                            hop_ips.append(outer_src_ip)
                            got_reply = True
                            break
                        else:
                            # Other ICMP (dest unreachable) record it as a response anyway
                            rtt = (time.time() - t0) * 1000.0
                            hop_rtts.append(rtt)
                            hop_ips.append(outer_src_ip)
                            got_reply = True
                            break
                    except Exception:
                        pass

                # Check TCP
                if recv_tcp_sock in receive_socks:
                    try:
                        pkt, _ = recv_tcp_sock.recvfrom(65535)
                        outer_src_ip, _, _, outer_ihl, _, _ = parse_ipv4_header(pkt, 0)
                        if outer_src_ip != dest_ip:
                            # Only consider destination's TCP responses as hop completion
                            continue
                        sp, dp, sseq, aseq, _, fl = parse_tcp_header(pkt, outer_ihl)
                        # Expect a TCP response to SYN: match ports and ack/seq
                        if dp != src_port:
                            continue
                        # RST or SYN-ACK are considered as "destination reached"
                        is_rst = (fl & 0x04) != 0
                        is_ack = (fl & 0x10) != 0
                        is_syn = (fl & 0x02) != 0
                        if is_rst or (is_syn and is_ack and aseq == (tcp_seq + 1)):
                            rtt = (time.time() - t0) * 1000.0
                            hop_rtts.append(rtt)
                            hop_ips.append(outer_src_ip)  # dest IP
                            got_reply = True
                            dest_reached = True
                            break
                    except Exception:
                        pass

            if not got_reply:
                print("  *   ", end="", flush=True)
                hop_rtts.append(None)  # type: ignore

        # End of 3 probes for this hop, locate IP
        display_ip = hop_ips[0] if hop_ips else None
        if display_ip:
            geostr = geo_lookup(display_ip)

        # Compute min/avg/max over non-None RTTs
        rtt = [r for r in hop_rtts if isinstance(r, float)]
        if rtt:
            mn = min(rtt); mx = max(rtt); avg = sum(rtt)/len(rtt)
            rtt_summary = f"min/avg/max = {mn:.1f}/{avg:.1f}/{mx:.1f} ms"
        else:
            rtt_summary = "min/avg/max = -/-/-"

        # Print summary
        ip_display = display_ip if display_ip else "(no reply)"
        mixed = " (mixed responders)" if hop_ips and len(set(hop_ips)) > 1 else ""

        no_reply = (ip_display == "(no reply)")
        rdns = (rdns_name(display_ip) or "NIL") if not no_reply else "NIL"
        print(f" {ip_display} ({rdns})  |  {geostr[0] if not no_reply else 'Unknown Location'}")
        print(f"    ↳ {geostr[1] if not no_reply else 'NIL'}")
        print(f"    ↳ {rtt_summary}{mixed}\n")

        hops_taken = ttl

        if dest_reached:
            break

    print(f"\nTotal hops to destination: {hops_taken}")
    if not dest_reached:
        print("Note: Destination not reached within max_hops (may be filtered).")

# -------------------------------------------------------------
# CLI handling
# -------------------------------------------------------------
def print_usage():
    print("Usage: sudo python3 geotrace.py <destination> [<port>] [--port|-p 80] [--max-hops 30] [--probes 3] [--timeout 2.5]")
    print("Example: sudo python3 geotrace.py www.google.com --port 80")


def parse_cli(argv: List[str]):
    if len(argv) < 2:
        print_usage()
        sys.exit(1)
    args = {
        "destination": argv[1],
        "port": str(DEFAULT_DEST_PORT),
        "max_hops": str(DEFAULT_MAX_HOPS),
        "probes": str(DEFAULT_PROBES),
        "timeout": str(DEFAULT_TIMEOUT_S)
    }

    # Also accept positional port (argv[2])
    i = 2
    if i < len(argv) and argv[i].isdigit():
        args["port"] = argv[i]
        i += 1
    # Parse flags
    while i < len(argv):
        if argv[i] in ("--port", "-p") and i+1 < len(argv):
            args["port"] = argv[i+1]; i += 2
        elif argv[i] == "--max-hops" and i+1 < len(argv):
            args["max_hops"] = argv[i+1]; i += 2
        elif argv[i] == "--probes" and i+1 < len(argv):
            args["probes"] = argv[i+1]; i += 2
        elif argv[i] == "--timeout" and i+1 < len(argv):
            args["timeout"] = argv[i+1]; i += 2
        else:
            print(f"[WARN] Unknown/ignored argument: {argv[i]}")
            i += 1
    return args


# Execute code
argv = sys.argv
if len(argv) > 1:
    opts = parse_cli(argv)
    geotrace(
        destination=opts["destination"],
        dest_port=int(opts["port"]),
        max_hops=int(opts["max_hops"]),
        probes_per_hop=int(opts["probes"]),
        timeout_s=float(opts["timeout"])
    )
else:
    print_usage()
