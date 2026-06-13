#!/usr/bin/env python3
"""
Extract ObjC protocol names and method signatures from rapportd.
Uses nm + otool -ov to find what NSXPCInterface protocols are exported
on com.apple.RemoteDisplay and companion services.

Also searches other binaries that reference com.apple.RemoteDisplay
to find the CLIENT side protocol (which tells us what methods to call).
"""
import subprocess, re, os, sys

RAPPORTD = "/usr/libexec/rapportd"

def run(cmd, timeout=30):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr

print("=" * 60)
print("1. ObjC Protocol symbols in rapportd (nm)")
print("=" * 60)
out = run(["nm", "-g", RAPPORTD])
for line in out.splitlines():
    if any(kw in line for kw in ["Protocol", "PROTOCOL", "protocol", "RemoteDisplay", "Rapport", "rapport"]):
        print(line)

print()
print("=" * 60)
print("2. ObjC metadata dump - protocols (otool -ov)")
print("=" * 60)
# Filter the huge output for relevant sections
out = run(["otool", "-ov", RAPPORTD], timeout=60)
lines = out.splitlines()
capture = False
capture_count = 0
for i, line in enumerate(lines):
    if any(kw in line for kw in ["Protocols:", "Protocol:", "RemoteDisplay", "protocol_t",
                                   "instanceMethods", "classMethods", "RPRemote",
                                   "SFWombat", "rapport", "AutoUnlock"]):
        capture = True
        capture_count = 20
    if capture:
        print(line)
        capture_count -= 1
        if capture_count <= 0:
            capture = False
            print("...")

print()
print("=" * 60)
print("3. strings grep: Protocol names containing relevant keywords")
print("=" * 60)
out = run(["strings", RAPPORTD])
for line in out.splitlines():
    if any(re.search(p, line) for p in [
        r"Protocol",
        r"RPRemoteDisplay",
        r"remoteDisplay",
        r"Wombat",
        r"_NSXPCProxy",
        r"Server\b",
        r"Client\b.*Protocol",
        r"Delegate\b",
        r"Interface\b",
    ]):
        if len(line) > 3 and len(line) < 120:
            print(f"  {line}")

print()
print("=" * 60)
print("4. RemoteDisplay framework search")
print("=" * 60)
search_paths = [
    "/System/Library/PrivateFrameworks/RemoteDisplay.framework",
    "/System/Library/PrivateFrameworks/PhoneLink.framework",
    "/System/Library/PrivateFrameworks/ScreenContinuity.framework",
    "/System/Library/PrivateFrameworks/ScreenMirroring.framework",
    "/System/Library/PrivateFrameworks/IPhoneMirroring.framework",
    "/System/Library/PrivateFrameworks/MirrorKit.framework",
    "/System/Library/PrivateFrameworks/ContinuityCapture.framework",
    "/System/Library/PrivateFrameworks/Rapport.framework",
]
for p in search_paths:
    if os.path.exists(p):
        print(f"  FOUND: {p}")
        # List contents
        r = subprocess.run(["ls", "-la", p], capture_output=True, text=True)
        print(r.stdout[:500])
    else:
        print(f"  NOT FOUND: {p}")

print()
print("=" * 60)
print("5. Search all PrivateFrameworks for com.apple.RemoteDisplay reference")
print("=" * 60)
r = subprocess.run(
    ["grep", "-r", "-l", "com.apple.RemoteDisplay",
     "/System/Library/PrivateFrameworks/"],
    capture_output=True, text=True, timeout=30
)
if r.stdout:
    for f in r.stdout.strip().splitlines()[:20]:
        print(f"  {f}")
else:
    print("  (none found or search failed)")

print()
print("=" * 60)
print("6. Search for processes that use com.apple.RemoteDisplay")
print("=" * 60)
search_bins = [
    "/System/Library/PrivateFrameworks/PhoneLink.framework/Support",
    "/System/Library/CoreServices",
    "/usr/libexec",
    "/System/Library/Frameworks",
]
for d in search_bins:
    if not os.path.isdir(d):
        continue
    r = subprocess.run(
        ["grep", "-r", "-l", "RemoteDisplay", d],
        capture_output=True, text=True, timeout=15
    )
    for f in r.stdout.strip().splitlines()[:10]:
        print(f"  {f}")

print()
print("=" * 60)
print("7. ObjC method selectors in rapportd related to RemoteDisplay XPC")
print("=" * 60)
out = run(["strings", RAPPORTD])
for line in out.splitlines():
    if any(kw in line for kw in [
        "remoteObjectProxy",
        "exportedObject",
        "setExportedObject",
        "setExportedInterface",
        "setRemoteObjectInterface",
        "interfaceWithProtocol",
        "NSXPCInterface",
        "registerObject",
        "_blessRemote",
        "synchronousRemoteObject",
        "allowedClasses",
        "classesForSelector",
    ]):
        print(f"  {line}")

print()
print("=" * 60)
print("8. Look at /usr/libexec for mirroring-related daemons")
print("=" * 60)
r = subprocess.run(["ls", "/usr/libexec/"], capture_output=True, text=True)
for f in r.stdout.splitlines():
    if any(kw in f.lower() for kw in ["mirror", "display", "rapport", "phone", "screen",
                                        "iphone", "capture", "continu", "wifip2"]):
        full = f"/usr/libexec/{f.strip()}"
        size = ""
        try:
            size = f"  ({os.path.getsize(full)} bytes)"
        except: pass
        print(f"  {full}{size}")

print()
print("=" * 60)
print("9. NSXPCConnection listener setup in rapportd binary - section analysis")
print("=" * 60)
# Look for NSXPCListener setup strings that reveal the service names + protocol assignments
out = run(["strings", RAPPORTD])
prev_lines = []
for line in out.splitlines():
    if "NSXPCListener" in line or "serviceWithMachServiceName" in line or "listenerWithMachServiceName" in line:
        print(f"  LISTENER: {line}")
    # Print context around export
    if "setExportedInterface" in line or "exportedInterface" in line:
        print(f"  EXPORT_IFACE: {line}")
    prev_lines.append(line)
    if len(prev_lines) > 5:
        prev_lines.pop(0)

print()
print("=" * 60)
print("10. Find all XPC message key strings used by rapportd")
print("=" * 60)
# XPC dictionaries use C string keys; look for common patterns
with open(RAPPORTD, "rb") as f:
    data = f.read()

# Find null-terminated strings that look like XPC dictionary keys
# (short, no spaces, alphanumeric + underscore/dot)
xpc_keys = set()
i = 0
while i < len(data) - 1:
    if data[i] == 0 and i + 1 < len(data):
        j = i + 1
        while j < len(data) and data[j] != 0 and 32 <= data[j] < 127:
            j += 1
        if data[j] == 0:
            s = data[i+1:j].decode('ascii', errors='replace')
            # XPC key heuristic: 2-50 chars, no spaces, common patterns
            if (2 <= len(s) <= 50 and
                ' ' not in s and
                re.match(r'^[a-zA-Z][a-zA-Z0-9_.:-]*$', s) and
                any(kw in s.lower() for kw in [
                    'session', 'remote', 'display', 'mirror', 'auth',
                    'device', 'connect', 'request', 'response', 'start',
                    'stop', 'type', 'version', 'token', 'uuid', 'id',
                    'status', 'error', 'result', 'stream', 'screen',
                    'iphone', 'mac', 'host', 'port', 'service',
                ])):
                xpc_keys.add(s)
        i = j
    else:
        i += 1

print("Candidate XPC dictionary keys:")
for k in sorted(xpc_keys):
    print(f"  {k}")
