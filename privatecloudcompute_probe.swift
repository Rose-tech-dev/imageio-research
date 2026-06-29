// Private Cloud Compute XPC Probe (macOS 26+)
//
// privatecloudcomputed is a new macOS 26 daemon that proxies Apple Intelligence
// requests to Apple's Private Cloud Compute servers.  It handles:
//   - Routing AI requests from on-device models to server-side models
//   - Attestation verification of PCC nodes
//   - OHTTP relay configuration for privacy-preserving requests
//
// A bypass here could allow an unprivileged process to:
//   - Inject or monitor AI requests before encryption
//   - Access request/response content (user prompts, AI replies)
//   - Manipulate attestation / bypass PCC trust checks
//   - Access relay configuration and server endpoints
//
// Methodology: TIMEOUT = bypass, INTERRUPTED = correctly protected.

import Foundation
import ObjectiveC

@objc protocol PCCRequestXPC: NSObjectProtocol {
    @objc optional func submitRequest(_ request: NSDictionary?,
                                      reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func requestStatus(_ requestID: NSString?,
                                      reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func getConfiguration(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func getAttestationStatus(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func availableModels(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

@objc protocol PCCTransparencyXPC: NSObjectProtocol {
    @objc optional func fetchTransparencyLog(_ reply: @escaping (NSData?, Error?) -> Void)
    @objc optional func verifyAttestation(_ data: NSData?,
                                           reply: @escaping (Bool, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

@objc protocol PCCRelayXPC: NSObjectProtocol {
    @objc optional func relayConfiguration(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

// ── Helper ────────────────────────────────────────────────────────────────────

func probe(service: String, proto: Protocol, label: String, waitSecs: Int = 6) -> Bool {
    print("\n╔══ \(label) ══╗")
    print("  service: \(service)")

    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var state = "pending"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if state == "pending" { state = "INVALIDATED — not running (macOS 26+ only?)" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if state == "pending" { state = "INTERRUPTED — entitlement enforced (correct)" }
        sema.signal()
    }
    conn.resume()
    Thread.sleep(forTimeInterval: 0.5)

    if state != "pending" {
        _ = sema.wait(timeout: .now() + 1)
        print("  RESULT: \(state)")
        conn.invalidate()
        return false
    }

    print("  Connection alive — dispatching probe calls...")
    let px = conn.remoteObjectProxyWithErrorHandler { e in
        let code = (e as NSError).code
        if code != 4099 { print("  [xpc-err] \(e.localizedDescription)") }
        if state == "pending" { state = "XPC-ERROR (RPC channel reached daemon)" }
        sema.signal()
    } as AnyObject

    if let p = px as? PCCRequestXPC {
        p.ping? { v, e in
            print("  [ping] REPLY: \(v ?? false)  ← BYPASS CONFIRMED WITH DATA")
            if state == "pending" { state = "PING REPLIED" }
            sema.signal()
        }
        p.getConfiguration? { r, e in
            if let r = r { print("  [config] DATA: \(r)  ← PCC CONFIG LEAK") }
        }
    }

    if sema.wait(timeout: .now() + .seconds(waitSecs)) == .timedOut {
        state = "TIMEOUT (\(waitSecs)s) *** ACCEPTED — NO ENTITLEMENT CHECK *** ← BYPASS"
    }

    print("  RESULT: \(state)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.5)
    return state.contains("TIMEOUT") || state.contains("BYPASS") || state.contains("REPLY")
}

// ── Main ──────────────────────────────────────────────────────────────────────

print("""
=== Private Cloud Compute XPC Probe (macOS 26+) ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

privatecloudcomputed routes Apple Intelligence requests to Apple's
PCC servers.  Any bypass = access to AI request content before encryption.
INVALIDATED = service not running (macOS 15.x or PCC not available).
""")

// Load PCC framework if present
for fw in [
    "/System/Library/PrivateFrameworks/PrivateCloudCompute.framework/PrivateCloudCompute",
    "/System/Library/PrivateFrameworks/PrivateCloudComputeTransparency.framework/PrivateCloudComputeTransparency",
] {
    if dlopen(fw, RTLD_NOW | RTLD_GLOBAL) != nil {
        print("[dlopen] \(fw.components(separatedBy: "/").last!)")
    }
}

for name in ["_PCCRequestProtocol", "_PCCDaemonProtocol",
             "_PCCTransparencyProtocol", "_PCCRelayProtocol"] {
    let s = objc_getProtocol(name) != nil ? "FOUND" : "not found"
    print("  proto \(name): \(s)")
}
print("")

var bypasses: [String] = []

// Main PCC daemon
if probe(service: "com.apple.privatecloudcomputed",
         proto: PCCRequestXPC.self,
         label: "privatecloudcomputed") {
    bypasses.append("com.apple.privatecloudcomputed")
}

// PCC request handler
if probe(service: "com.apple.privatecloudcompute.requesthandler",
         proto: PCCRequestXPC.self,
         label: "privatecloudcompute.requesthandler") {
    bypasses.append("com.apple.privatecloudcompute.requesthandler")
}

// Transparency / attestation log
if probe(service: "com.apple.privatecloudcompute.transparency",
         proto: PCCTransparencyXPC.self,
         label: "privatecloudcompute.transparency") {
    bypasses.append("com.apple.privatecloudcompute.transparency")
}

// OHTTP relay config
if probe(service: "com.apple.privatecloudcompute.ohttp-relay",
         proto: PCCRelayXPC.self,
         label: "privatecloudcompute.ohttp-relay") {
    bypasses.append("com.apple.privatecloudcompute.ohttp-relay")
}

// Writing tools via PCC
if probe(service: "com.apple.privatecloudcompute.writingtools",
         proto: PCCRequestXPC.self,
         label: "privatecloudcompute.writingtools") {
    bypasses.append("com.apple.privatecloudcompute.writingtools")
}

// Intelligence platform proxy
if probe(service: "com.apple.intelligenceplatformd",
         proto: PCCRequestXPC.self,
         label: "intelligenceplatformd") {
    bypasses.append("com.apple.intelligenceplatformd")
}

print("""

╔══ Summary ══╗
Bypasses: \(bypasses.count)  |  INVALIDATED = service not present on this OS version
""")
for b in bypasses { print("  *** BYPASS: \(b)") }
