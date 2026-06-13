// intelligenceplatformd XPC Probe
// Target: com.apple.intelligenceplatformd (PID 3869 on macOS 15.7.7)
//
// intelligenceplatformd is Apple Intelligence's platform orchestrator daemon.
// It routes requests between on-device models and Private Cloud Compute.
// This probe tests whether it enforces entitlement checks on its XPC interface.
//
// Methodology: same as rapportd. TIMEOUT = method accepted without rejection.

import Foundation

// Guessed protocol — derived from IntelligencePlatform.framework + strings in dyld cache.
// Method names follow Apple's intelligence service naming patterns.
@objc protocol IntelligencePlatformXPC: NSObjectProtocol {
    // Request management
    @objc optional func submitRequest(_ request: NSDictionary?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func cancelRequest(_ requestID: NSString?,
                                       reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getRequestStatus(_ requestID: NSString?,
                                          reply: ((NSDictionary?, NSError?) -> Void)?)
    // Capability / model queries
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getAvailableModels(_ reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func queryModelCapability(_ modelID: NSString?,
                                              reply: ((NSDictionary?, NSError?) -> Void)?)
    // Context / session management
    @objc optional func createSession(_ options: NSDictionary?,
                                       reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func endSession(_ sessionID: NSString?,
                                    reply: ((Bool, NSError?) -> Void)?)
    // Platform status
    @objc optional func getServiceStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    // PCC routing
    @objc optional func routeRequestToPCC(_ request: NSDictionary?,
                                           reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getCloudCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
}

// All candidate Mach service names for intelligenceplatformd.
// The launchd label "com.apple.intelligenceplatformd" is almost always the Mach
// service name, but some Apple daemons register sub-services.
let PLATFORM_CANDIDATES = [
    "com.apple.intelligenceplatformd",
    "com.apple.intelligence.platform",
    "com.apple.intelligence.platformd",
    "com.apple.IntelligencePlatform",
    "com.apple.intelligence.xpc",
    "com.apple.intelligenceplatformd.xpc",
    "com.apple.IntelligencePlatform.service",
    "com.apple.intelligenceplatform.service",
    "com.apple.intelligence.service",
    "com.apple.intelligenced",
    "com.apple.intelligence.orchestrator",
    "com.apple.intelligence.daemon",
]

func probeIntelligencePlatform(_ serviceName: String) {
    print("\n--- Probing: \(serviceName) ---")
    let conn = NSXPCConnection(machServiceName: serviceName, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: IntelligencePlatformXPC.self)

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if result == "(pending)" { result = "INTERRUPTED" }
        sema.signal()
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        result = "ERROR: \(err.localizedDescription)"
        sema.signal()
    } as? IntelligencePlatformXPC

    guard let p = proxy else {
        print("  RESULT: No proxy")
        conn.invalidate()
        return
    }

    // Test 1: ping
    p.ping? { _, _ in
        if result == "(pending)" { result = "REPLY: ping accepted" }
        sema.signal()
    }

    let w = sema.wait(timeout: .now() + 4)
    if w == .timedOut { result = "TIMEOUT (4s) *** ACCEPTED — NO ENTITLEMENT CHECK AT CONNECT ***" }
    print("  ping: \(result)")

    if result.contains("TIMEOUT") || result.contains("REPLY") {
        print("  ** SERVICE LIVE — probing deeper **")

        // Test 2: getCapabilities
        let s2 = DispatchSemaphore(value: 0)
        var r2 = "(pending)"
        conn.interruptionHandler = { r2 = "INTERRUPTED"; s2.signal() }
        p.getCapabilities? { resp, _ in
            r2 = "REPLY: getCapabilities returned \(resp?.count ?? 0) keys"
            s2.signal()
        }
        if s2.wait(timeout: .now() + 6) == .timedOut { r2 = "TIMEOUT (6s) — accepted" }
        print("  getCapabilities: \(r2)")

        // Test 3: submitRequest with nil (crash test)
        let s3 = DispatchSemaphore(value: 0)
        var r3 = "(pending)"
        p.submitRequest?(nil) { _, _ in
            r3 = "REPLY: submitRequest(nil) accepted"
            s3.signal()
        }
        if s3.wait(timeout: .now() + 5) == .timedOut { r3 = "TIMEOUT (5s)" }
        print("  submitRequest(nil): \(r3)")

        // Test 4: routeRequestToPCC (most valuable — PCC access)
        let s4 = DispatchSemaphore(value: 0)
        var r4 = "(pending)"
        let pccReq: NSDictionary = [
            "query": "What is the capital of France?",
            "type": "text",
            "targetModel": "pcc",
            "clientBundleID": "com.apple.Safari",
        ]
        p.routeRequestToPCC?(pccReq) { _, _ in
            r4 = "REPLY: routeRequestToPCC accepted from unprivileged caller"
            s4.signal()
        }
        if s4.wait(timeout: .now() + 10) == .timedOut { r4 = "TIMEOUT (10s)" }
        print("  routeRequestToPCC: \(r4)")

        // Test 5: getCloudCapabilities (reveals PCC endpoint info)
        let s5 = DispatchSemaphore(value: 0)
        var r5 = "(pending)"
        p.getCloudCapabilities? { resp, _ in
            r5 = "REPLY: getCloudCapabilities returned \(resp?.count ?? 0) keys — DATA LEAKED"
            s5.signal()
        }
        if s5.wait(timeout: .now() + 6) == .timedOut { r5 = "TIMEOUT (6s)" }
        print("  getCloudCapabilities: \(r5)")
    }

    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.5)
}

print("=== intelligenceplatformd XPC Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("Testing \(PLATFORM_CANDIDATES.count) candidate service names...\n")

for name in PLATFORM_CANDIDATES {
    probeIntelligencePlatform(name)
}

print("\n=== PROBE COMPLETE ===")
print("TIMEOUT or REPLY = service accepted call from unprivileged process (UID 501, no entitlements)")
