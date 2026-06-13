// rapportd RemoteDisplay XPC Method Probe
// Target: com.apple.RemoteDisplay and com.apple.RemoteDisplay.Dedicated
//
// From binary analysis, remoteDisplay* methods are the actual XPC interface methods.
// Probing whether rapportd enforces entitlements AFTER accepting the connection.
//
// Compile: swiftc rapportd_remotedisplay_probe.swift -o rapportd_rd_probe

import Foundation

// ---- Protocol definitions based on binary reverse engineering ----
// From rapportd binary strings:
//   remoteDisplayChangeDedicatedDevice:
//   remoteDisplayChangeDiscoverySessionStateForDevice:reason:
//   remoteDisplayPersonSelected:forDedicatedPairing:
//   remoteDisplayDedicatedDeviceConfirmationWithCompletion:
// Type encodings from binary:
//   v24@0:8@"RPRemoteDisplayDevice"16       -> (void)(RPRemoteDisplayDevice*device)
//   v28@0:8@"RPRemoteDisplayDevice"16I24    -> (void)(RPRemoteDisplayDevice*device, UInt32 val)
//   v28@0:8@"RPRemoteDisplayPerson"16c24    -> (void)(RPRemoteDisplayPerson*person, Bool flag)
//   v48@0:8@"NSNumber"16@"RPRemoteDisplayDevice"24@"NSNumber"32@?<v@?@"NSError">40
//     -> (void)(NSNumber*, RPRemoteDisplayDevice*, NSNumber*, callback(NSError?))

// Server-side protocol (what rapportd exports, what clients CALL):
@objc protocol RPRemoteDisplayDaemonXPC: NSObjectProtocol {
    // Change dedicated mirror device (dedicate one specific iPhone for mirroring)
    @objc optional func remoteDisplayChangeDedicatedDevice(_ device: AnyObject?)

    // Change discovery session state for a specific device
    @objc optional func remoteDisplayChangeDiscoverySessionStateForDevice(
        _ device: AnyObject?,
        reason: UInt32
    )

    // Person selected for dedicated pairing
    @objc optional func remoteDisplayPersonSelected(
        _ person: AnyObject?,
        forDedicatedPairing: Bool
    )

    // Confirmation request with completion (called when user tries to confirm device)
    @objc optional func remoteDisplayDedicatedDeviceConfirmationWithCompletion(
        _ completion: @escaping (NSNumber, AnyObject?, NSNumber?, NSError?) -> Void
    )
}

// Client-side protocol (what clients export, what rapportd CALLS BACK):
@objc protocol RPRemoteDisplayClientXPC: NSObjectProtocol {
    @objc optional func remoteDisplayNotifyDiscoverySessionState(
        _ state: UInt64,
        forDevice device: AnyObject?,
        startReason: UInt64
    )
    @objc optional func remoteDisplayDedicatedDeviceChanged(_ device: AnyObject?)
}

// ---- PROBE FUNCTION ----

func probe(service: String, label: String, action: @escaping (RPRemoteDisplayDaemonXPC, DispatchSemaphore) -> Void) {
    print("\n=== [\(service)] \(label) ===")

    let conn = NSXPCConnection(machServiceName: service, options: [])
    let iface = NSXPCInterface(with: RPRemoteDisplayDaemonXPC.self)
    conn.remoteObjectInterface = iface

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED (connection rejected)" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if result == "(pending)" { result = "INTERRUPTED (rapportd closed connection)" }
        sema.signal()
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        let e = err as NSError
        result = "ERROR HANDLER: \(e.localizedDescription) [code=\(e.code) domain=\(e.domain)]"
        sema.signal()
    } as? RPRemoteDisplayDaemonXPC

    if let p = proxy {
        print("  Proxy: \(type(of: proxy as AnyObject))")
        action(p, sema)
    } else {
        print("  Failed to get typed proxy")
        result = "NO TYPED PROXY"
        sema.signal()
    }

    let deadline = DispatchTime.now() + .seconds(6)
    if sema.wait(timeout: deadline) == .timedOut {
        result = "TIMEOUT (6s) - message sent, connection stayed open, NO ENTITLEMENT CHECK"
    }
    print("  RESULT: \(result)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.5)
}

// ---- MAIN ----

print("=== rapportd RemoteDisplay XPC Method Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())\n")

let services = ["com.apple.RemoteDisplay", "com.apple.RemoteDisplay.Dedicated"]

for svc in services {
    // Test 1: remoteDisplayChangeDedicatedDevice: with nil
    probe(service: svc, label: "remoteDisplayChangeDedicatedDevice:(nil)") { p, sema in
        p.remoteDisplayChangeDedicatedDevice?(nil)
        // This is a void method with no reply, so we won't get a callback
        // Wait a bit then check if connection is still alive
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            sema.signal()
        }
    }

    // Test 2: remoteDisplayChangeDiscoverySessionStateForDevice:reason: with nil, 0
    probe(service: svc, label: "remoteDisplayChangeDiscoverySessionStateForDevice:(nil) reason:0") { p, sema in
        p.remoteDisplayChangeDiscoverySessionStateForDevice?(nil, reason: 0)
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { sema.signal() }
    }

    // Test 3: remoteDisplayDedicatedDeviceConfirmationWithCompletion:
    // This one has a reply block - it's the most interesting
    probe(service: svc, label: "remoteDisplayDedicatedDeviceConfirmationWithCompletion:") { p, sema in
        p.remoteDisplayDedicatedDeviceConfirmationWithCompletion? { code, device, extra, err in
            print("  CALLBACK RECEIVED: code=\(code) device=\(String(describing: device)) err=\(String(describing: err))")
            sema.signal()
        }
    }
}

print("\n=== Done ===")
