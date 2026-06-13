#!/usr/bin/env python3
"""
Targeted string extraction from rapportd binary.
Avoids slow operations. Looks for:
1. ObjC protocol names embedded as strings
2. NSXPCInterface/setExportedObject references
3. Entitlement check strings
4. XPC message key strings related to RemoteDisplay
"""
import re, sys

path = "/usr/libexec/rapportd"
with open(path, "rb") as f:
    data = f.read()

print(f"Binary size: {len(data)} bytes\n")

def extract_cstrings(data, min_len=4, max_len=200):
    """Extract all null-terminated ASCII strings from binary data."""
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            j = i
            while j < len(data) and 32 <= data[j] < 127:
                j += 1
            if data[j] == 0 and (j - i) >= min_len and (j - i) <= max_len:
                strings.append((i, data[i:j].decode('ascii', errors='replace')))
            i = j + 1
        else:
            i += 1
    return strings

print("Extracting strings...")
all_strings = extract_cstrings(data)
print(f"Total strings found: {len(all_strings)}\n")

# Categorize strings
categories = {
    "ObjC Protocol names": [],
    "NSXPCInterface setup": [],
    "Entitlement/auth checks": [],
    "RemoteDisplay specific": [],
    "XPC service names": [],
    "Debug preferences": [],
    "Audit/SecTask (process verify)": [],
}

for offset, s in all_strings:
    lo = s.lower()

    if re.search(r'Protocol$|Protocol\b', s) and not s.startswith('//'):
        categories["ObjC Protocol names"].append((offset, s))
    if any(kw in s for kw in ['NSXPCInterface', 'setExported', 'exportedObject',
                               'remoteObjectInterface', 'interfaceWithProtocol',
                               'NSXPCListener', 'NSXPCConnection']):
        categories["NSXPCInterface setup"].append((offset, s))
    if any(kw in lo for kw in ['entitlement', 'authorization', 'privilege',
                                'unauthorized', 'denied', 'forbidden', 'require.*entitle',
                                'checkEntitlement', 'hasEntitlement']):
        categories["Entitlement/auth checks"].append((offset, s))
    if 'RemoteDisplay' in s or 'remoteDisplay' in s:
        categories["RemoteDisplay specific"].append((offset, s))
    if re.match(r'^com\.apple\.', s) and len(s) < 80:
        categories["XPC service names"].append((offset, s))
    if s.startswith('_pref'):
        categories["Debug preferences"].append((offset, s))
    if any(kw in s for kw in ['auditToken', 'SecTask', 'SecCode', 'taskPort',
                               'peerAuditToken', 'connectionPID', 'getpid',
                               'peerCredentials', 'effectiveUID']):
        categories["Audit/SecTask (process verify)"].append((offset, s))

for cat, items in categories.items():
    print(f"\n{'='*60}")
    print(f"[{cat}]")
    print(f"{'='*60}")
    seen = set()
    for off, s in items:
        if s not in seen:
            seen.add(s)
            print(f"  0x{off:08x}: {s}")

# Final: look for strings that look like ObjC protocol declarations
# ObjC protocol names in binary appear near @protocol() patterns
# Pattern: strings ending in "Protocol" or containing "Delegate" near XPC setup
print(f"\n{'='*60}")
print("[ObjC selector names near 'RemoteDisplay']")
print(f"{'='*60}")
seen = set()
for off, s in all_strings:
    if 'RemoteDisplay' in s or 'Wombat' in s or 'SFPhone' in s:
        # Also print nearby strings
        for off2, s2 in all_strings:
            if abs(off2 - off) < 500 and s2 != s and s2 not in seen:
                seen.add(s2)
                if any(c.isupper() for c in s2) and len(s2) > 6:
                    print(f"  near 0x{off:08x}: {s2}")
        if s not in seen:
            seen.add(s)
            print(f"  0x{off:08x}: {s}")
