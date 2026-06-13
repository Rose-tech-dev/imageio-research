#!/usr/bin/env python3
"""
rapportd binary analysis:
- Find _prefIgnoreRemoteDisplayChecks usage context
- Find preference domain (user/system/any)
- Find nearby ObjC class/method names for call-site identification
"""
import sys, os

path = "/usr/libexec/rapportd"

if not os.path.exists(path):
    print(f"Not found: {path}")
    sys.exit(1)

with open(path, "rb") as f:
    data = f.read()

targets = [
    b"_prefIgnoreRemoteDisplayChecks",
    b"_prefIgnoreCompanionLinkChecks",
    b"_prefServerBonjourOpportunitistic",
    b"_prefServerBonjourAlways",
    b"_prefServerBonjourInfra",
    b"_prefIPEnabled",
    b"_prefNoInfra",
    b"_prefXPCMatchingTestMode",
    b"_prefUseTargetAuthTag",
]

print("=== STRING OFFSETS IN rapportd BINARY ===")
for tgt in targets:
    offset = 0
    found = []
    while True:
        idx = data.find(tgt, offset)
        if idx == -1:
            break
        found.append(idx)
        offset = idx + 1
    if found:
        for idx in found:
            print(f"  0x{idx:x}  {tgt.decode()}")
    else:
        print(f"  (not found)  {tgt.decode()}")

print()
print("=== PREFERENCE API REFERENCES ===")
for api in [
    b"NSUserDefaults",
    b"CFPreferencesCopyAppValue",
    b"CFPreferencesGetAppBooleanValue",
    b"CFPreferencesAppSynchronize",
    b"CFPreferencesSynchronize",
    b"kCFPreferencesAnyUser",
    b"kCFPreferencesCurrentUser",
    b"kCFPreferencesAnyHost",
    b"kCFPreferencesCurrentHost",
    b"boolForKey:",
    b"objectForKey:",
    b"standardUserDefaults",
    b"preferenceForKey:",
    b"defaults",
]:
    offset = 0
    found = []
    while True:
        idx = data.find(api, offset)
        if idx == -1:
            break
        found.append(f"0x{idx:x}")
        offset = idx + 1
    if found:
        print(f"  {api.decode()}: {', '.join(found[:5])}")

print()
print("=== CONTEXT AROUND _prefIgnoreRemoteDisplayChecks ===")
tgt = b"_prefIgnoreRemoteDisplayChecks"
offset = 0
while True:
    idx = data.find(tgt, offset)
    if idx == -1:
        break

    start = max(0, idx - 256)
    end = min(len(data), idx + len(tgt) + 256)
    chunk = data[start:end]

    print(f"\n--- Occurrence at file offset 0x{idx:x} ---")
    # Extract readable strings in this region
    i = 0
    strings_found = []
    while i < len(chunk):
        if 32 <= chunk[i] < 127:
            j = i
            while j < len(chunk) and 32 <= chunk[j] < 127:
                j += 1
            if j - i >= 4:
                s = chunk[i:j].decode('ascii', errors='replace')
                strings_found.append((start + i, s))
            i = j
        else:
            i += 1

    for off, s in strings_found:
        marker = " <--- TARGET" if "_prefIgnoreRemoteDisplayChecks" in s else ""
        print(f"  0x{off:08x}: {s}{marker}")

    offset = idx + 1

print()
print("=== ObjC SELECTORS NEAR _prefIgnoreRemoteDisplayChecks ===")
# Look for ObjC selector patterns near the target
for selector_pattern in [
    b"-[RP",  # rapportd ObjC methods
    b"ignoredChecks",
    b"ignoreCheck",
    b"RemoteDisplay",
    b"remoteDisplay",
    b"Authentication",
    b"authenticat",
]:
    idx = data.find(b"_prefIgnoreRemoteDisplayChecks")
    if idx == -1:
        continue
    region_start = max(0, idx - 2048)
    region_end = min(len(data), idx + 2048)
    region = data[region_start:region_end]

    sub_idx = 0
    while True:
        found = region.find(selector_pattern, sub_idx)
        if found == -1:
            break
        end_of_str = found
        while end_of_str < len(region) and region[end_of_str] != 0:
            end_of_str += 1
        s = region[found:end_of_str].decode('ascii', errors='replace')
        if len(s) >= 4:
            print(f"  0x{region_start + found:08x}: {s}")
        sub_idx = found + 1
