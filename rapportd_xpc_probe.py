#!/usr/bin/env python3
"""
Probe the com.apple.RemoteDisplay XPC service registered by rapportd.
Also checks launchctl dumpstate for rapportd's registered mach services.
"""
import subprocess, os, sys, time

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)

print("=== rapportd Mach Services (launchctl dumpstate) ===")
dumpstate = run("launchctl dumpstate 2>/dev/null", timeout=20)
lines = dumpstate.split('\n')

# Find rapportd section
rapport_section = []
in_section = False
depth = 0
for line in lines:
    if 'com.apple.rapportd' in line and not in_section:
        in_section = True
        depth = 0
    if in_section:
        rapport_section.append(line)
        depth += line.count('{') - line.count('}')
        if depth <= 0 and len(rapport_section) > 2:
            break

if rapport_section:
    print('\n'.join(rapport_section[:80]))
else:
    print("(rapportd section not found in dumpstate)")

print()
print("=== Services containing 'RemoteDisplay' or 'rapport' ===")
for i, line in enumerate(lines):
    if 'RemoteDisplay' in line or ('rapport' in line.lower() and 'com.apple' in line):
        # Print context
        start = max(0, i-1)
        end = min(len(lines), i+3)
        for j in range(start, end):
            print(f"  [{j}] {lines[j]}")

print()
print("=== Check for com.apple.RemoteDisplay in bootstrap ==="
      "\n(trying launchctl print-disabled)")
for ctx in ['system', f'gui/{os.getuid()}']:
    out = run(f"launchctl print-disabled {ctx} 2>/dev/null", timeout=10)
    if 'RemoteDisplay' in out or 'rapport' in out.lower():
        for line in out.split('\n'):
            if 'RemoteDisplay' in line or 'rapport' in line.lower():
                print(f"  [{ctx}] {line.strip()}")
    else:
        print(f"  [{ctx}]: No RemoteDisplay/rapport found")

print()
print("=== MIG/XPC service lookup via notifyd/lsof ===")
rapport_pid = run("pgrep rapportd | head -1").strip()
if rapport_pid:
    lsof_out = run(f"lsof -p {rapport_pid} 2>/dev/null | grep -v txt | grep -v mem", timeout=10)
    print(f"rapportd PID {rapport_pid} open files:")
    for line in lsof_out.split('\n')[:30]:
        print(f"  {line}")

print()
print("=== Attempt connection to com.apple.RemoteDisplay XPC ===")
# Use python's ctypes to call xpc functions directly
try:
    import ctypes
    xpc = ctypes.CDLL("/usr/lib/libxpc.dylib", use_errno=True)

    # xpc_connection_create_mach_service(name, targetq, flags)
    xpc.xpc_connection_create_mach_service.restype = ctypes.c_void_p
    xpc.xpc_connection_create_mach_service.argtypes = [
        ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint64
    ]

    conn = xpc.xpc_connection_create_mach_service(
        b"com.apple.RemoteDisplay", None, 0
    )

    if conn:
        print(f"  XPC connection object created: 0x{conn:x}")

        # Set up event handler (simplified - just resume and send)
        xpc.xpc_connection_set_event_handler.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        xpc.xpc_connection_resume.argtypes = [ctypes.c_void_p]
        xpc.xpc_connection_resume(conn)

        # Create a dictionary message
        xpc.xpc_dictionary_create.restype = ctypes.c_void_p
        xpc.xpc_dictionary_create.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        ]
        msg = xpc.xpc_dictionary_create(None, None, 0)

        if msg:
            xpc.xpc_dictionary_set_string.argtypes = [
                ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p
            ]
            xpc.xpc_dictionary_set_string(msg, b"type", b"probe")

            xpc.xpc_connection_send_message_with_reply_sync.restype = ctypes.c_void_p
            xpc.xpc_connection_send_message_with_reply_sync.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p
            ]

            print("  Sending probe message (sync)...")
            reply = xpc.xpc_connection_send_message_with_reply_sync(conn, msg)

            if reply:
                xpc.xpc_copy_description.restype = ctypes.c_char_p
                xpc.xpc_copy_description.argtypes = [ctypes.c_void_p]
                desc = xpc.xpc_copy_description(reply)
                if desc:
                    print(f"  Reply: {desc.decode('utf-8', errors='replace')}")
                else:
                    print("  Reply received but no description")
            else:
                print("  No reply (None returned)")
        else:
            print("  Could not create XPC message dict")
    else:
        print("  Connection returned NULL - service not registered or not accessible")

except Exception as e:
    print(f"  XPC probe error: {e}")

print()
print("=== Also try com.apple.rapport.matching ===")
try:
    conn2 = xpc.xpc_connection_create_mach_service(
        b"com.apple.rapport.matching", None, 0
    )
    if conn2:
        print(f"  com.apple.rapport.matching connection: 0x{conn2:x}")
        xpc.xpc_connection_resume(conn2)
        msg2 = xpc.xpc_dictionary_create(None, None, 0)
        reply2 = xpc.xpc_connection_send_message_with_reply_sync(conn2, msg2)
        if reply2:
            desc2 = xpc.xpc_copy_description(reply2)
            print(f"  Reply: {desc2.decode('utf-8', errors='replace') if desc2 else '(no desc)'}")
        else:
            print("  No reply")
    else:
        print("  NULL - not accessible")
except Exception as e:
    print(f"  Error: {e}")
