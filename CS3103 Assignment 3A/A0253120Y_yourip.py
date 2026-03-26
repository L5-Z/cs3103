#!/usr/bin/env python3
"""
CS3103 - Assignment 3 (Section A)
TCP Client to retrieve and display current public IP
Author: Muhammad Alfaatih Bin Mohamed Faizal
Matric: A0253120Y


Usage:
    python3 A0253120Y_yourip.py
"""

import re
import socket
import ssl

HOST = "varlabs.comp.nus.edu.sg"
PORT = 443 # HTTPS 443
PATH = "/tools/yourip.php"


def fetch_public_ip():
    # 1. Build, connect, set timeout TCP socket
    raw_sock = socket.create_connection((HOST, PORT), timeout=60)

    # 2. Wrap with TLS context
    ctx = ssl.create_default_context()
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=HOST)
    
    # 3. Send GET Request
    rq = (
            f"GET {PATH} HTTP/1.1\r\n"
            f"Host: {HOST}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
    tls_sock.sendall(rq.encode())

    # 4. Receive
    rsp = tls_sock.recv(10000)
    
    # 5. Clean into lines
    lines = rsp.decode().splitlines()

    # 6. Find IP and validate exact match with a regex that matches “a.b.c.d” where each octet is 0–255
    myIP = None
    for line in lines:
        m = re.match(
        r"^"
        r"("                                         #  group: full IPv4 address
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])" # first octet: 0–255
        r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])){3}" # dot + next octet, repeated 3 times
        r")"                                         #  end of group
        r"$",
        str(line)
        )
        if m:
            myIP = m.group(0).strip()
            break

    tls_sock.close()

    if myIP is not None:
        return myIP

print(f"My public IP address is {fetch_public_ip()}")