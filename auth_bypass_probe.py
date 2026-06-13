#!/usr/bin/env python3
"""
rapportd Authentication Bypass Probe
Investigates what TXT record values rapportd requires to recognize a device,
and whether the auth tag can be spoofed or bypassed.

Looks at:
1. What rapportd itself advertises in _rdlink._tcp TXT records (the auth tag format)
2. What NearbyAction V2 BLE advertisement data rapportd processes
3. Whether TXT record manipulation can bypass device recognition

Apple Bug Bounty research - authorized testing only.
"""
import subprocess
import time
import sys
import socket
import struct
import re

def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as e:
        return str(e)

def main():
    print("=== RAPPORTD TXT RECORD ANALYSIS ===", flush=True)

    # Look for what rapportd advertises about itself
    print("\n[1] Browse for any existing _rdlink._tcp services (rapportd as server):", flush=True)
    # dns-sd browse with resolve
    result = run_cmd("timeout 8 dns-sd -B _rdlink._tcp . 2>&1", timeout=12)
    print(result or "(none)", flush=True)

    print("\n[2] Look for rapportd's own Bonjour service registration in system:", flush=True)
    # Check if rapportd registers _rdlink._tcp itself
    result = run_cmd("dns-sd -L rapportd _rdlink._tcp . 2>&1", timeout=8)
    print(result or "(not found)", flush=True)

    print("\n[3] Check mDNSResponder for rdlink registrations:", flush=True)
    result = run_cmd(
        "log show --predicate 'process == \"mDNSResponder\"' --last 5m 2>/dev/null | "
        "grep -iE 'rdlink|companion.link|identityservice|rapport' | head -30", timeout=15)
    print(result or "(none)", flush=True)

    print("\n[4] rapportd's own mDNS registrations (what it advertises):", flush=True)
    result = run_cmd(
        "dns-sd -B _services._dns-sd._udp . 2>&1 | head -30",
        timeout=10)
    print(result or "(none)", flush=True)

    print("\n[5] Check if rapportd is advertising any service (lsof mDNSResponder socket):", flush=True)
    rapport_pid = run_cmd("pgrep rapportd").strip()
    if rapport_pid:
        result = run_cmd("lsof -p %s -i -n 2>/dev/null | head -30" % rapport_pid)
        print(result or "(none)", flush=True)

    print("\n[6] Try to trigger rapportd AWDL browsing by simulating iPhone presence:", flush=True)
    # A paired iPhone advertises _rdlink._tcp via AWDL with specific TXT keys
    # Try advertising with various TXT key combinations to see what rapportd responds to
    txt_variations = [
        "rpfl=0 rphi=0 rpha=0",          # Minimal TXT
        "rpfl=98304 rphi=test rpha=test", # Non-zero flags
        "rpfl=0",                          # Just flags
    ]
    for txt in txt_variations:
        keys = txt.split()
        cmd_parts = ["dns-sd", "-R", "FakePhone", "_rdlink._tcp", "local", "9999"] + keys
        print("  Advertising: %s" % ' '.join(cmd_parts), flush=True)
        proc = subprocess.Popen(cmd_parts, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        # Check rapportd logs for any reaction
        logs = run_cmd(
            "log show --predicate 'process == \"rapportd\"' --last 10s 2>/dev/null | "
            "grep -iE 'FakePhone|TestRapport|rdlink|bonjour|unauth|found|connect' | head -10",
            timeout=12)
        if logs.strip():
            print("  rapportd REACTED:", logs.strip(), flush=True)
        else:
            print("  No rapportd reaction", flush=True)
        proc.terminate()
        time.sleep(1)

    print("\n[7] Inspect what TXT record keys rapportd uses when advertising:", flush=True)
    # Try to resolve any service rapportd might be running
    result = run_cmd("dns-sd -Z _rdlink._tcp . 2>&1", timeout=10)
    print(result or "(none)", flush=True)
    result = run_cmd("dns-sd -Z _companion-link._tcp . 2>&1", timeout=10)
    print(result or "(none)", flush=True)

    print("\n=== DONE ===", flush=True)

if __name__ == '__main__':
    main()
