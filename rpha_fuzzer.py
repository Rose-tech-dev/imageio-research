#!/usr/bin/env python3
"""
rapportd rpHA (auth tag) TXT Record Fuzzer
Targets the resolveIdentityForSignature:data:typeFlags:error: code path
which processes rpHA from ANY device advertising _rdlink._tcp with rpfl=98304.

The rpHA is a signature/auth tag that rapportd tries to verify against
known device identities. The parsing happens BEFORE any authentication check.

Apple Bug Bounty research - authorized testing only.
"""
import subprocess
import time
import os
import base64
import sys

def get_rapportd_pid():
    try:
        out = subprocess.check_output(['pgrep', 'rapportd'], text=True).strip()
        return int(out.split()[0]) if out else None
    except Exception:
        return None

def check_crash_reports():
    reports = []
    dirs = [
        os.path.expanduser('~/Library/Logs/DiagnosticReports'),
        '/Library/Logs/DiagnosticReports',
    ]
    for d in dirs:
        if os.path.exists(d):
            for f in os.listdir(d):
                if 'rapportd' in f.lower():
                    reports.append(os.path.join(d, f))
    return reports

def advertise_rdlink(name, port, rpfl, rphi, rphn, rpha, duration=8):
    """Advertise _rdlink._tcp with specific TXT record values"""
    cmd = ['dns-sd', '-R', name, '_rdlink._tcp', 'local', str(port)]
    if rpfl is not None:
        cmd.append('rpFl=%s' % rpfl)
    if rphi is not None:
        cmd.append('rpHI=%s' % rphi)
    if rphn is not None:
        cmd.append('rpHN=%s' % rphn)
    if rpha is not None:
        cmd.append('rpHA=%s' % rpha)
    # Also add rpMd (model), rpVr (version) to look more like a real iPhone
    cmd.append('rpMd=iPhone')
    cmd.append('rpVr=1.0')

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    proc.wait()
    return proc.returncode

def get_rapportd_mem(pid):
    """Get rapportd's memory usage"""
    try:
        out = subprocess.check_output(
            ['ps', '-o', 'rss=', '-p', str(pid)], text=True).strip()
        return int(out) if out else 0
    except Exception:
        return 0

def main():
    pid = get_rapportd_pid()
    if not pid:
        print('ERROR: rapportd not running!', flush=True)
        sys.exit(1)

    print('=== rapportd rpHA FUZZER ===', flush=True)
    print('rapportd PID: %d' % pid, flush=True)
    print('Initial memory: %d KB' % get_rapportd_mem(pid), flush=True)

    initial_crashes = set(check_crash_reports())
    print('Initial crash reports: %d' % len(initial_crashes), flush=True)

    # Generate test cases
    test_cases = [
        # (description, rpfl, rphi, rphn, rpha)

        # Baseline: well-formed values
        ('Baseline empty rpha', '98304', 'TestDevice', 'TestHost', ''),

        # Test 1: Maximum length rpHA (255 bytes base64 = ~191 bytes binary)
        # This tests length validation in the signature parser
        ('Max length rpHA', '98304', 'TestDevice', 'TestHost', 'A' * 255),

        # Test 2: Malformed base64 (non-base64 chars)
        ('Invalid base64 rpHA', '98304', 'TestDevice', 'TestHost', '!@#$%^&*()' * 25),

        # Test 3: Valid base64 but wrong length for ECDSA signature
        # ECDSA P-256 signature = 64 bytes; P-521 = 132 bytes
        # Try 1 byte, 65 bytes (65 = 64+1, off-by-one territory)
        ('1-byte rpHA', '98304', 'TestDevice', 'TestHost', base64.b64encode(b'\x00').decode()),
        ('65-byte rpHA', '98304', 'TestDevice', 'TestHost', base64.b64encode(b'\xFF' * 65).decode()),
        ('63-byte rpHA', '98304', 'TestDevice', 'TestHost', base64.b64encode(b'\xAA' * 63).decode()),

        # Test 4: DER-encoded sequence with wrong tag
        # ECDSA signature in DER: 0x30 (SEQUENCE) + length + ...
        ('DER SEQUENCE wrong length', '98304', 'TestDevice', 'TestHost',
         base64.b64encode(bytes([0x30, 0x82, 0x01, 0x00]) + b'\x00' * 20).decode()),

        # Test 5: All zeros
        ('All zeros rpHA', '98304', 'TestDevice', 'TestHost', base64.b64encode(b'\x00' * 64).decode()),

        # Test 6: Max size rpHI to stress the "data" parameter
        ('Max rpHI', '98304', 'A' * 240, 'TestHost', base64.b64encode(b'\xAA' * 32).decode()),

        # Test 7: Null bytes in TXT value
        ('Null bytes rpHA', '98304', 'TestDevice', 'TestHost',
         base64.b64encode(b'\x00' * 32).decode()),

        # Test 8: Binary garbage that looks like a valid protobuf
        ('Proto-like rpHA', '98304', 'TestDevice', 'TestHost',
         base64.b64encode(bytes([0x0a, 0x20]) + b'\x41' * 32).decode()),

        # Test 9: Very large rpFl flags
        ('Large rpFl', '4294967295', 'TestDevice', 'TestHost',
         base64.b64encode(b'\xAA' * 32).decode()),

        # Test 10: Multiple keys (try rpAD, rpBA too)
        ('All TXT keys', '98304', 'TestDevice', 'TestHost',
         base64.b64encode(b'\xBB' * 32).decode()),
    ]

    results = []
    for desc, rpfl, rphi, rphn, rpha in test_cases:
        if not get_rapportd_pid():
            print('\n[!] rapportd CRASHED! (no PID found)', flush=True)
            results.append((desc, 'CRASHED'))
            # Wait for restart
            time.sleep(3)
            pid = get_rapportd_pid()
            if pid:
                print('[+] rapportd restarted as PID %d' % pid, flush=True)
            continue

        mem_before = get_rapportd_mem(pid)
        print('\n[*] Test: %s' % desc, flush=True)
        print('    rpfl=%s rphi=%s rpha=%s' % (rpfl, rphi[:20] + '...' if len(rphi) > 20 else rphi, rpha[:30] + '...' if len(rpha) > 30 else rpha), flush=True)

        advertise_rdlink('ProbeDevice', 9999, rpfl, rphi, rphn, rpha, duration=6)

        time.sleep(1)  # Brief pause between tests

        mem_after = get_rapportd_mem(pid)
        mem_delta = mem_after - mem_before

        new_crashes = set(check_crash_reports()) - initial_crashes

        status = 'OK'
        if mem_delta > 500:  # 500 KB growth
            status = 'LEAK? (+%d KB)' % mem_delta
        if new_crashes:
            status = 'CRASH: %s' % list(new_crashes)
        if not get_rapportd_pid():
            status = 'CRASHED'

        print('    mem: %d → %d KB (delta: %+d), status: %s' % (mem_before, mem_after, mem_delta, status), flush=True)
        results.append((desc, status))

    print('\n=== SUMMARY ===', flush=True)
    for desc, status in results:
        print('%-45s %s' % (desc, status), flush=True)

    final_crashes = set(check_crash_reports()) - initial_crashes
    if final_crashes:
        print('\n[!!] NEW CRASH REPORTS:', flush=True)
        for cr in final_crashes:
            print('  %s' % cr, flush=True)
    else:
        print('\nNo crash reports generated.', flush=True)

if __name__ == '__main__':
    main()
