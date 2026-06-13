#!/usr/bin/env python3
"""
Test if rapportd can browse _rdlink._tcp over regular IP (not just AWDL).
Sets _prefIPEnabled=YES + _prefNoInfra=NO + _prefIgnoreRemoteDisplayChecks=YES,
restarts rapportd, advertises a fake iPhone service, listens for incoming connections.
"""
import subprocess, socket, time, sys, os

RAPPORT_DOMAIN = "com.apple.rapportd"

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def get_pid():
    out = run("pgrep rapportd | head -1")
    try:
        return int(out.strip())
    except:
        return None

print("=== _prefIPEnabled Infrastructure Browsing Test ===", flush=True)

# Set preferences
prefs = {
    "_prefIPEnabled": "YES",
    "_prefNoInfra": "NO",
    "_prefIgnoreRemoteDisplayChecks": "YES",
}
for key, val in prefs.items():
    run(f"defaults write {RAPPORT_DOMAIN} {key} -bool {val}")
    print(f"Set {key} = {val}", flush=True)

print("Current prefs:", flush=True)
print(run(f"defaults read {RAPPORT_DOMAIN} 2>/dev/null"), flush=True)

# Restart rapportd
print("\nRestarting rapportd...", flush=True)
run("killall -HUP rapportd 2>/dev/null || true")
time.sleep(4)

new_pid = get_pid()
print(f"New rapportd PID: {new_pid}", flush=True)

# Verify prefs survived restart
for key in prefs:
    val = run(f"defaults read {RAPPORT_DOMAIN} {key} 2>/dev/null")
    print(f"  {key} after restart: {val}", flush=True)

# Enable debug logging
run("sudo log config --subsystem com.apple.rapport --mode level:debug 2>/dev/null || true")

# Start TCP listener
print("\nStarting TCP listener on port 9998...", flush=True)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', 9998))
server.listen(5)
server.settimeout(18)

# Advertise fake iPhone
print("Advertising _rdlink._tcp on port 9998...", flush=True)
adv = subprocess.Popen(
    ["dns-sd", "-R", "TestiPhone16Pro", "_rdlink._tcp", "local", "9998",
     "rpFl=98304", "rpHI=TestHI", "rpHN=TestHN", "rpHA=bypass_test",
     "rpMd=iPhone16,2", "rpVr=1.0"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)

connected = False
try:
    print("Waiting for connection from rapportd (18s)...", flush=True)
    conn, addr = server.accept()
    connected = True
    print(f"\n[!!!] CONNECTION from {addr[0]}:{addr[1]}", flush=True)
    data = conn.recv(4096)
    if data:
        print(f"Data (hex): {data[:64].hex()}", flush=True)
        print(f"Data (text): {data[:64]}", flush=True)
    conn.close()
except socket.timeout:
    print("No connection in 18s - rapportd did not browse over infrastructure", flush=True)
finally:
    adv.terminate()
    adv.wait()
    server.close()

# Get logs
print("\n=== rapportd logs during test ===", flush=True)
logs = run(
    "log show --predicate 'process == \"rapportd\"' --last 30s 2>/dev/null | "
    "grep -vE '(WiFiManagerClient|Logging)' | head -60",
    timeout=35
)
print(logs or "(no logs)", flush=True)

# Cleanup
print("\nCleaning up prefs...", flush=True)
for key in prefs:
    run(f"defaults delete {RAPPORT_DOMAIN} {key} 2>/dev/null || true")

if connected:
    print("\n[!!!] CONFIRMED: rapportd connected over IP with bypass pref!", flush=True)
else:
    print("\nNo connection - rapportd did not browse over infrastructure IP.", flush=True)
