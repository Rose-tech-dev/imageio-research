// Gen 5: ospredictiond real protocol invocation
//
// Goal: invoke REAL methods on ospredictiond (uid 0) with type-matched arguments.
// If any handler has memory unsafety (NPE, overflow, type confusion), we find it here.
//
// Method names confirmed from /usr/libexec/ospredictiond binary (nm + strings):
//   currentBatteryLevelWithContext:
//   recommendedWaitTimeWithHandler:
//   adjustedChargingDecision:withPluginDate:withPluginBatteryLevel:forDate:forStatus:
//   recordChargingEvent:withReply:
//
// Strategy:
//   Round 1 — nil arguments       → triggers NPE / assert if no null guard
//   Round 2 — NSData payloads     → tests binary parser for overflow
//   Round 3 — NSDictionary inputs → tests key/type dispatch
//   Round 4 — boundary values     → NSNumber extremes, empty NSData, huge NSData

import Foundation

// ── Protocol declarations with best-guess signatures ──────────────────────────
// Type encodings from otool -oV determine real types; these are our best guess
// until we extract them from the binary below.

@objc protocol OSIntelligenceBatteryXPC: NSObjectProtocol {
    // Primary candidates
    @objc optional func currentBatteryLevelWithContext(
        _ context: NSDictionary?,
        reply: ((NSNumber?, NSError?) -> Void)?)

    @objc optional func recommendedWaitTimeWithHandler(
        _ reply: ((NSNumber?, NSError?) -> Void)?)

    @objc optional func recordChargingEvent(
        _ event: NSDictionary?,
        withReply reply: ((Bool, NSError?) -> Void)?)

    // Variant signatures (in case types differ from guess)
    @objc optional func currentBatteryLevelWithContext(
        _ context: NSData?,
        reply: ((NSNumber?, NSError?) -> Void)?)

    @objc optional func recordChargingEvent(
        _ event: NSData?,
        withReply reply: ((Bool, NSError?) -> Void)?)
}

@objc protocol OSIntelligenceChargingXPC: NSObjectProtocol {
    @objc optional func adjustedChargingDecision(
        _ decision: NSDictionary?,
        withPluginDate date: NSDate?,
        withPluginBatteryLevel level: NSNumber?,
        forDate targetDate: NSDate?,
        forStatus status: NSNumber?,
        reply: ((NSDictionary?, NSError?) -> Void)?)

    @objc optional func recordChargingEvent(
        _ event: NSDictionary?,
        withReply reply: ((Bool, NSError?) -> Void)?)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func openConnection(service: String, proto: Protocol) -> (NSXPCConnection, AnyObject)? {
    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)
    var alive = true
    conn.invalidationHandler = { alive = false }
    conn.interruptionHandler = { alive = false }
    conn.resume()
    let proxy = conn.remoteObjectProxyWithErrorHandler { _ in } as AnyObject
    Thread.sleep(forTimeInterval: 0.3)
    guard alive else { conn.invalidate(); return nil }
    return (conn, proxy)
}

func wait(_ sema: DispatchSemaphore, timeout: Int = 5) -> Bool {
    return sema.wait(timeout: .now() + .seconds(timeout)) == .success
}

// ── Test payloads ─────────────────────────────────────────────────────────────

let smallData  = NSData(bytes: [0x41, 0x41, 0x41, 0x41] as [UInt8], length: 4)
let largeData  = NSData(bytes: Array(repeating: UInt8(0x41), count: 65536), length: 65536)
let hugeData   = NSData(bytes: Array(repeating: UInt8(0xFF), count: 1_048_576), length: 1_048_576)
let emptyData  = NSData()

let testDict: NSDictionary = [
    "level":     NSNumber(value: 85),
    "timestamp": NSDate(),
    "source":    "com.apple.OSIntelligence.battery",
    "data":      smallData,
]

let malformedDict: NSDictionary = [
    "level":     NSNumber(value: Int64.max),   // boundary
    "timestamp": NSNumber(value: -1),          // negative date
    "count":     NSNumber(value: UInt64.max),  // overflow candidate
    "nested":    testDict,
]

// ── BATTERY service probes ────────────────────────────────────────────────────

print("""
=== Gen 5: ospredictiond Real Protocol Invocation ===
UID: \(getuid())  PID: \(ProcessInfo.processInfo.processIdentifier)
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)
Goal: invoke real root-daemon methods with typed arguments.
""")

// Connection to battery service
if let (battConn, battProxy) = openConnection(
    service: "com.apple.OSIntelligence.battery",
    proto: OSIntelligenceBatteryXPC.self) {

    let p = battProxy as? OSIntelligenceBatteryXPC
    print("\n── com.apple.OSIntelligence.battery (root daemon) ──")

    // R1: recommendedWaitTimeWithHandler (no args — simplest call)
    print("\n[R1] recommendedWaitTimeWithHandler (nil args)")
    let s1 = DispatchSemaphore(value: 0)
    p?.recommendedWaitTimeWithHandler? { result, err in
        if let r = result {
            print("  REPLY: \(r)  ← root daemon responded with data!")
        } else if let e = err {
            print("  ERROR: \(e.localizedDescription)")
        } else {
            print("  REPLY: nil/nil")
        }
        s1.signal()
    }
    if !wait(s1, timeout: 6) { print("  TIMEOUT — accepted, no reply (root daemon processing)") }

    // R2: currentBatteryLevelWithContext — nil context
    print("\n[R2] currentBatteryLevelWithContext(nil)")
    let s2 = DispatchSemaphore(value: 0)
    p?.currentBatteryLevelWithContext(nil) { result, err in
        if let r = result { print("  REPLY: \(r)  ← data from root!") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil") }
        s2.signal()
    }
    if !wait(s2, timeout: 6) { print("  TIMEOUT — accepted") }

    // R3: currentBatteryLevelWithContext — NSDictionary context
    print("\n[R3] currentBatteryLevelWithContext(testDict)")
    let s3 = DispatchSemaphore(value: 0)
    p?.currentBatteryLevelWithContext(testDict) { result, err in
        if let r = result { print("  REPLY: \(r)  ← root daemon processed dict!") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil") }
        s3.signal()
    }
    if !wait(s3, timeout: 6) { print("  TIMEOUT — accepted") }

    // R4: currentBatteryLevelWithContext — malformed/boundary dict
    print("\n[R4] currentBatteryLevelWithContext(malformedDict — boundary values)")
    let s4 = DispatchSemaphore(value: 0)
    p?.currentBatteryLevelWithContext(malformedDict) { result, err in
        if let r = result { print("  REPLY: \(r)") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil") }
        s4.signal()
    }
    if !wait(s4, timeout: 6) { print("  TIMEOUT — accepted") }

    // R5: recordChargingEvent — nil
    print("\n[R5] recordChargingEvent(nil)")
    let s5 = DispatchSemaphore(value: 0)
    p?.recordChargingEvent(nil) { ok, err in
        if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: ok=\(ok)") }
        s5.signal()
    }
    if !wait(s5, timeout: 6) { print("  TIMEOUT — accepted") }

    // R6: recordChargingEvent — structured dict
    print("\n[R6] recordChargingEvent(testDict)")
    let s6 = DispatchSemaphore(value: 0)
    p?.recordChargingEvent(testDict) { ok, err in
        if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: ok=\(ok)  ← root daemon recorded our event!") }
        s6.signal()
    }
    if !wait(s6, timeout: 6) { print("  TIMEOUT — accepted") }

    // R7: recordChargingEvent — large NSData (overflow probe)
    print("\n[R7] recordChargingEvent(NSData 65KB — overflow probe)")
    let dataDict: NSDictionary = ["payload": largeData, "type": NSNumber(value: 0xDEADBEEF)]
    let s7 = DispatchSemaphore(value: 0)
    p?.recordChargingEvent(dataDict) { ok, err in
        if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: ok=\(ok)") }
        s7.signal()
    }
    if !wait(s7, timeout: 6) { print("  TIMEOUT — accepted") }

    battConn.invalidate()
    Thread.sleep(forTimeInterval: 1.0)
}

// ── CHARGING service probes ───────────────────────────────────────────────────

if let (chgConn, chgProxy) = openConnection(
    service: "com.apple.OSIntelligence.charging",
    proto: OSIntelligenceChargingXPC.self) {

    let p = chgProxy as? OSIntelligenceChargingXPC
    print("\n── com.apple.OSIntelligence.charging (root daemon) ──")

    // C1: adjustedChargingDecision — all nil args
    print("\n[C1] adjustedChargingDecision(all nil)")
    let c1 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision(
        nil, withPluginDate: nil,
        withPluginBatteryLevel: nil,
        forDate: nil,
        forStatus: nil) { result, err in
        if let r = result { print("  REPLY: \(r)  ← root daemon responded!") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil") }
        c1.signal()
    }
    if !wait(c1, timeout: 6) { print("  TIMEOUT — accepted") }

    // C2: adjustedChargingDecision — typed args
    print("\n[C2] adjustedChargingDecision(typed args)")
    let c2 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision(
        testDict,
        withPluginDate: NSDate(),
        withPluginBatteryLevel: NSNumber(value: 85),
        forDate: NSDate(timeIntervalSinceNow: 3600),
        forStatus: NSNumber(value: 1)) { result, err in
        if let r = result { print("  REPLY: \(r)  ← root daemon processed!") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil") }
        c2.signal()
    }
    if !wait(c2, timeout: 6) { print("  TIMEOUT — accepted") }

    // C3: boundary value — Int64.max for level/status
    print("\n[C3] adjustedChargingDecision(Int64.max boundary values)")
    let c3 = DispatchSemaphore(value: 0)
    p?.adjustedChargingDecision(
        malformedDict,
        withPluginDate: NSDate(timeIntervalSince1970: TimeInterval(Int64.max)),
        withPluginBatteryLevel: NSNumber(value: Int64.max),
        forDate: NSDate(timeIntervalSince1970: -1),
        forStatus: NSNumber(value: UInt64.max)) { result, err in
        if let r = result { print("  REPLY: \(r)") }
        else if let e = err { print("  ERROR: \(e.localizedDescription)") }
        else { print("  REPLY: nil/nil — boundary values accepted silently") }
        c3.signal()
    }
    if !wait(c3, timeout: 6) { print("  TIMEOUT — accepted with boundary values") }

    chgConn.invalidate()
}

print("""

=== Gen 5 Complete ===
Any REPLY above = root daemon executed our method call.
Any TIMEOUT     = connection live, daemon processing (reply not returned to our interface).
Any crash in ospredictiond = check DiagnosticReports below.
""")
