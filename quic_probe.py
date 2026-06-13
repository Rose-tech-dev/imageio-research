#!/usr/bin/env python3
"""
Apple QUIC (_asquic._udp) PoC Probe
Tests whether rapportd sends QUIC Initial packets to arbitrary _asquic._udp services.
"""
import socket
import subprocess
import time
import sys

def hex_dump(data, prefix='  ', max_bytes=128):
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join('%02x' % b for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print('%s%04x: %-48s  %s' % (prefix, i, hex_part, ascii_part))

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 9997))
    srv.settimeout(1)

    dns = subprocess.Popen(
        ['dns-sd', '-R', 'TestQUICSvc', '_asquic._udp', 'local', '9997'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('[QUIC] Listening on UDP 9997, advertising _asquic._udp', flush=True)

    packets = []
    end_time = time.time() + 25
    while time.time() < end_time:
        try:
            data, addr = srv.recvfrom(65535)
            print('[QUIC] Got UDP packet from %s:%d - %d bytes' % (addr[0], addr[1], len(data)), flush=True)
            hex_dump(data)
            packets.append((data, addr))
            # Check if it looks like a QUIC Initial packet
            if len(data) > 0 and (data[0] & 0x80):  # Long header bit
                print('[QUIC] Looks like QUIC Long Header packet!', flush=True)
                if (data[0] & 0x30) == 0x00:
                    print('[QUIC] Packet type: Initial (0x00)', flush=True)
        except socket.timeout:
            pass

    dns.terminate()
    print('[QUIC] Total packets received: %d' % len(packets), flush=True)
    if packets:
        print('[QUIC] SUCCESS - rapportd sent QUIC packet to us!', flush=True)

if __name__ == '__main__':
    main()
