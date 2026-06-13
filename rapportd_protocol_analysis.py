#!/usr/bin/env python3
"""
Find the NSXPCInterface protocol name and method signatures for com.apple.RemoteDisplay.
Also look for exported object setup and message handler methods.
"""
import sys, os

path = "/usr/libexec/rapportd"
with open(path, "rb") as f:
    data = f.read()

print("=== Protocol names near 'RemoteDisplay' ===")
targets = [
    b"RemoteDisplay",
    b"Protocol",
    b"RPRemoteDisplay",
]

# Find all strings in the binary containing relevant substrings
def find_strings(data, needle, context=200):
    results = []
    offset = 0
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        # Extract readable string starting at idx
        start = idx
        while start > 0 and 32 <= data[start-1] < 127:
            start -= 1
        end = idx
        while end < len(data) and 32 <= data[end] < 127:
            end += 1
        if end > start:
            results.append((idx, data[start:end].decode('ascii', errors='replace')))
        offset = idx + 1
    return results

# Look for protocol names
for needle in [b"Protocol", b"RPRemoteDisplay", b"RemoteDisplay"]:
    results = find_strings(data, needle)
    print(f"\n--- Strings containing '{needle.decode()}' ---")
    seen = set()
    for offset, s in results:
        if s not in seen and len(s) > 3:
            seen.add(s)
            print(f"  0x{offset:08x}: {s}")

print()
print("=== NSXPCInterface related strings ===")
for needle in [b"NSXPCInterface", b"NSXPCConnection", b"interfaceWithProtocol",
               b"exportedInterface", b"exportedObject", b"remoteObjectInterface"]:
    idx = data.find(needle)
    if idx != -1:
        start = max(0, idx - 16)
        end = min(len(data), idx + len(needle) + 64)
        readable = []
        i = start
        while i < end:
            if 32 <= data[i] < 127:
                j = i
                while j < end and 32 <= data[j] < 127:
                    j += 1
                if j - i >= 3:
                    readable.append(data[i:j].decode())
                i = j
            else:
                i += 1
        print(f"  {needle.decode()}: {' | '.join(readable[:5])}")

print()
print("=== ObjC method names related to XPC message handling ===")
for needle in [b"handleXPC", b"receiveXPC", b"processXPC", b"xpcMessage",
               b"_handleMessage", b"_processMessage", b"_handleRequest",
               b"RPRemoteDisplayServer", b"RPRemoteDisplayClient",
               b"ServerProtocol", b"ClientProtocol"]:
    results = find_strings(data, needle)
    if results:
        print(f"\n--- '{needle.decode()}' ---")
        seen = set()
        for off, s in results[:10]:
            if s not in seen:
                seen.add(s)
                print(f"  0x{off:08x}: {s}")

print()
print("=== XPC message key strings (what messages rapportd might accept) ===")
for needle in [b"\"type\"", b"messageType", b"commandType", b"\"command\"",
               b"requestType", b"\"request\"", b"sessionID", b"\"session\""]:
    results = find_strings(data, needle.strip(b'"'))
    if results:
        seen = set()
        for off, s in results[:5]:
            if s not in seen:
                seen.add(s)
                print(f"  0x{off:08x}: {s}")

print()
print("=== ObjC class method list (NSXPCExportedObject pattern) ===")
for needle in [b"@RPRemoteDisplay", b"NSXPCProxy", b"NSXPCDecoder",
               b"exportObject", b"exportedObject", b"setExportedObject",
               b"setExportedInterface"]:
    results = find_strings(data, needle)
    if results:
        seen = set()
        for off, s in results[:5]:
            if s not in seen:
                seen.add(s)
                print(f"  {s}")

print()
print("=== IPC SEND strings (method calls rapportd sends over XPC) ===")
# Look for strings that look like XPC message key names
# These would be dictionary keys in XPC messages rapportd sends/receives
xpc_candidates = []
for i in range(0, len(data) - 1):
    if data[i] == 0 and i + 1 < len(data) and 65 <= data[i+1] <= 90:
        # Start of what might be a C string starting with uppercase
        j = i + 1
        while j < len(data) and 32 <= data[j] < 127:
            j += 1
        s = data[i+1:j].decode('ascii', errors='replace')
        if (3 <= len(s) <= 40 and
            ' ' not in s and
            any(c.islower() for c in s) and
            not s.startswith('-[') and
            not s.startswith('+[')):
            xpc_candidates.append(s)

# Count and filter likely XPC key names
from collections import Counter
counts = Counter(xpc_candidates)
# XPC keys appear multiple times (send and receive)
for s, cnt in sorted(counts.items(), key=lambda x: -x[1]):
    if cnt >= 2 and any(kw in s.lower() for kw in
        ['session', 'remote', 'display', 'mirror', 'auth', 'device', 'connect',
         'request', 'response', 'start', 'stop', 'type', 'version', 'token']):
        print(f"  {s} (x{cnt})")
