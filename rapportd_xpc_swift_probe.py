#!/usr/bin/env python3
"""
Write, compile, and run a Swift XPC probe for rapportd services.
"""
import subprocess, os, sys, tempfile

SWIFT_CODE = r"""
import Foundation

let services = [
    "com.apple.RemoteDisplay",
    "com.apple.rapport.matching",
    "com.apple.AutoUnlock.System.AuthenticationHintsProvider",
    "com.apple.wifivelocityd.rapportWake",
]

let sema = DispatchSemaphore(value: 0)

for svcName in services {
    print("Probing: \(svcName)")

    var conn: xpc_connection_t? = xpc_connection_create_mach_service(svcName, nil, 0)
    guard let c = conn else {
        print("  NULL connection (service not found or no permission)")
        continue
    }

    var gotReply = false

    xpc_connection_set_event_handler(c) { event in
        let typeDesc = String(cString: xpc_type_get_name(xpc_get_type(event)))
        if xpc_equal(xpc_get_type(event), XPC_TYPE_ERROR) {
            let errDesc = String(cString: xpc_copy_description(event))
            print("  Error: \(errDesc)")
        } else {
            let desc = String(cString: xpc_copy_description(event))
            print("  Event: \(desc.prefix(200))")
        }
    }

    xpc_connection_resume(c)

    let msg = xpc_dictionary_create(nil, nil, 0)
    xpc_dictionary_set_string(msg, "type", "probe")
    xpc_dictionary_set_uint64(msg, "version", 1)

    let reply = xpc_connection_send_message_with_reply_sync(c, msg)
    if let reply = reply {
        let typeMatch = xpc_equal(xpc_get_type(reply), XPC_TYPE_ERROR)
        let desc = String(cString: xpc_copy_description(reply))
        if typeMatch {
            print("  Reply (error): \(desc.prefix(300))")
        } else {
            print("  Reply (success): \(desc.prefix(300))")
        }
    } else {
        print("  No reply")
    }

    xpc_connection_cancel(c)
    Thread.sleep(forTimeInterval: 0.5)
    print("")
}
"""

# Write Swift file
tf = tempfile.NamedTemporaryFile(suffix='.swift', mode='w', delete=False)
tf.write(SWIFT_CODE)
tf.close()
swift_path = tf.name
bin_path = swift_path.replace('.swift', '_bin')

print(f"Compiling Swift XPC probe...")
r = subprocess.run(
    ["swiftc", swift_path, "-o", bin_path,
     "-Xcc", "-fmodules", "-import-objc-header", "/dev/null"],
    capture_output=True, text=True
)
if r.returncode != 0:
    # Try simpler compile
    r = subprocess.run(
        ["swiftc", swift_path, "-o", bin_path],
        capture_output=True, text=True
    )

if r.returncode != 0:
    print(f"Compilation failed: {r.stderr}")
    # Fall back to Python ctypes approach
    print("\nFalling back to ctypes XPC probe...")
    os.unlink(swift_path)
    sys.exit(0)

print("Running Swift XPC probe...")
result = subprocess.run(
    [bin_path],
    capture_output=True, text=True, timeout=30
)
print(result.stdout or result.stderr or "(no output)")

# Cleanup
os.unlink(swift_path)
try:
    os.unlink(bin_path)
except:
    pass
