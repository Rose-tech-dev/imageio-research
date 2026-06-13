// Writing Tools XPC Service Probe
// Target: com.apple.WritingTools (or com.apple.privatecloudcompute.writingtools)
//
// Methodology: same as rapportd probe.
//   - Connect as unprivileged process (UID 501, no special entitlements)
//   - Call methods on the XPC interface
//   - TIMEOUT (no interruption/invalidation within N seconds) = method accepted
//   - INTERRUPTED = server rejected call (correct behavior)
//   - INVALIDATED = connection rejected at connect time (correct behavior)
//
// We test every known Writing Tools XPC service name variant.
// This file is updated as we discover actual method names from binary analysis.
//
// Tested: macOS 15.x, Apple Silicon

import Foundation

// ── Known / guessed XPC protocol for Writing Tools ─────────────────────────
// Method names derived from ObjC selector dumps + Apple developer docs for
// the public WritingTools API (UIWritingToolsCoordinator, NSWritingToolsCoordinator).
// The daemon methods are the server-side implementations of these calls.

@objc protocol WTXPCServiceProtocol: NSObjectProtocol {
    // Public API entry points (from WritingTools.framework headers)
    @objc optional func requestTextSuggestion(_ text: String,
                                              context: NSDictionary?,
                                              reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func processText(_ text: String,
                                    options: NSDictionary?,
                                    reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func rewriteText(_ text: String,
                                    style: Int,
                                    reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func summarizeText(_ text: String,
                                      reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func proofreadText(_ text: String,
                                      reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    // Generic method that might exist as a catch-all
    @objc optional func handleRequest(_ request: NSDictionary?,
                                      reply: ((NSDictionary?, NSError?) -> Void)?)
}

// ── Candidate Mach service names ────────────────────────────────────────────
// These are guesses derived from Apple's naming conventions.
// The discovery workflow will confirm the actual name.
let SERVICE_CANDIDATES = [
    "com.apple.WritingTools",
    "com.apple.WritingTools.xpc",
    "com.apple.writingtools",
    "com.apple.WritingToolsService",
    "com.apple.intelligence.writingtools",
    "com.apple.private.WritingTools",
    "com.apple.AIRuntime.WritingTools",
    "com.apple.siri.WritingTools",
    "com.apple.NLX.WritingTools",
    "com.apple.intelligenced",
    "com.apple.appleintelligenced",
    "com.apple.AIRuntime",
]

// ── Probe one Mach service ───────────────────────────────────────────────────
func probeService(_ serviceName: String) {
    print("\n--- Probing: \(serviceName) ---")
    let conn = NSXPCConnection(machServiceName: serviceName, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: WTXPCServiceProtocol.self)

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED (service unknown or requires entitlement at connect)" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if result == "(pending)" { result = "INTERRUPTED (method rejected)" }
        sema.signal()
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        result = "ERROR: \(err.localizedDescription)"
        sema.signal()
    } as? WTXPCServiceProtocol

    guard let p = proxy else {
        print("  RESULT: No proxy obtained")
        conn.invalidate()
        return
    }

    // Test 1: ping (most benign, likely to exist)
    print("  Calling ping...")
    p.ping? { _, _ in
        if result == "(pending)" { result = "ping: REPLY RECEIVED (service exists, no entitlement gate)" }
        sema.signal()
    }

    let waitResult = sema.wait(timeout: .now() + 4)
    if waitResult == .timedOut {
        result = "TIMEOUT (4s) *** SERVICE ACCEPTED PING — NO ENTITLEMENT CHECK ***"
    }
    print("  RESULT: \(result)")

    if result.contains("TIMEOUT") || result.contains("REPLY") {
        // Service exists! Try more invasive calls
        print("  ** Service active — attempting text processing calls **")
        let sema2 = DispatchSemaphore(value: 0)
        var result2 = "(pending)"

        conn.interruptionHandler = {
            result2 = "INTERRUPTED"
            sema2.signal()
        }

        // Test 2: summarize with a long string (memory/resource exhaustion potential)
        let longText = String(repeating: "The quick brown fox jumps over the lazy dog. ", count: 500)
        p.summarizeText?(longText) { _, _ in
            result2 = "REPLY: summarizeText accepted 22,500 char input"
            sema2.signal()
        }

        if sema2.wait(timeout: .now() + 10) == .timedOut {
            result2 = "TIMEOUT (10s) — summarizeText(22500 chars) accepted without rejection"
        }
        print("  summarizeText result: \(result2)")

        // Test 3: rewrite with suspicious style index (out-of-range)
        let sema3 = DispatchSemaphore(value: 0)
        var result3 = "(pending)"
        p.rewriteText?("Test text for rewriting.", style: 999999) { _, _ in
            result3 = "REPLY: rewriteText accepted style=999999 (out-of-range)"
            sema3.signal()
        }
        if sema3.wait(timeout: .now() + 5) == .timedOut {
            result3 = "TIMEOUT (5s) — rewriteText(style=999999) accepted"
        }
        print("  rewriteText(style=999999) result: \(result3)")

        // Test 4: handleRequest with null dictionary
        let sema4 = DispatchSemaphore(value: 0)
        var result4 = "(pending)"
        p.handleRequest?(nil) { _, _ in
            result4 = "REPLY: handleRequest(nil) accepted"
            sema4.signal()
        }
        if sema4.wait(timeout: .now() + 4) == .timedOut {
            result4 = "TIMEOUT (4s) — handleRequest(nil) accepted"
        }
        print("  handleRequest(nil) result: \(result4)")
    }

    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.5)
}

// ── MAIN ────────────────────────────────────────────────────────────────────
print("=== Writing Tools XPC Service Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
print("Testing \(SERVICE_CANDIDATES.count) candidate service names...\n")

for name in SERVICE_CANDIDATES {
    probeService(name)
}

print("\n=== PROBE COMPLETE ===")
print("Any TIMEOUT result = service accepted call from unprivileged process.")
print("Check: log show --predicate 'process contains \"writing\" OR process contains \"intelligence\"' --last 2m")
