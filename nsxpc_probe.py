#!/usr/bin/env python3
"""Swift/NSXPCConnection probe for rapportd services."""
import subprocess, os, tempfile, sys

SWIFT_CODE = r"""
import Foundation

print("Testing NSXPCConnection to rapportd services...")

let services = [
    "com.apple.RemoteDisplay",
    "com.apple.rapport",
    "com.apple.rapport.private-discovery",
    "com.apple.rapport.StatusUpdates",
    "com.apple.AutoUnlock.System.AuthenticationHintsProvider",
]

for name in services {
    print("\nService: \(name)")
    let conn = NSXPCConnection(machServiceName: name, options: NSXPCConnection.Options(rawValue: 0))
    var status = "no-handler-called (connection may have stayed open)"
    let sema = DispatchSemaphore(value: 0)
    conn.invalidationHandler = {
        status = "invalidated (service refused or absent)"
        sema.signal()
    }
    conn.interruptionHandler = {
        status = "interrupted (service exists, connection broken)"
        sema.signal()
    }
    conn.resume()

    let timeout = DispatchTime.now() + .seconds(3)
    if sema.wait(timeout: timeout) == .timedOut {
        status = "TIMEOUT - connection stayed active for 3s (service is ACCESSIBLE)"
    }
    conn.invalidate()
    print("  Result: \(status)")
}

print("\nDone.")
"""

with tempfile.NamedTemporaryFile(suffix='.swift', mode='w', delete=False, dir='/tmp') as f:
    f.write(SWIFT_CODE)
    path = f.name

out_path = path.replace('.swift', '_bin')
print(f"Compiling Swift NSXPCConnection probe: {path}")
r = subprocess.run(['swiftc', path, '-o', out_path], capture_output=True, text=True)
if r.returncode != 0:
    print(f"Compile failed:\n{r.stderr}")
    try: os.unlink(path)
    except: pass
    sys.exit(1)

print("Running...")
result = subprocess.run([out_path], capture_output=True, text=True, timeout=30)
print(result.stdout or result.stderr or "(no output)")

try: os.unlink(path)
except: pass
try: os.unlink(out_path)
except: pass
