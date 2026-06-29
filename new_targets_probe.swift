// New macOS 26 Target Probe — Gen 1
//
// Uses confirmed MachService names from plist dumps.
// Targets (all new macOS 26 AI daemons):
//
//   com.apple.callintelligenced.service  — callintelligenced (UserName: mobile)
//     Handles: call summaries, voicemail transcription, call recordings
//
//   com.apple.coreduetd.knowledge        — coreduetd
//     Handles: user activity knowledge graph (app usage, location, habits)
//
//   com.apple.coreduetd.people           — coreduetd
//     Handles: people/contacts interaction graph
//
//   com.apple.biome.access.system        — biomed (UserName: _biome)
//     Handles: ALL Biome event streams (Siri history, app usage, etc.)
//
//   com.apple.biome.compute.source       — biomed
//     Handles: Biome compute event source
//
//   com.apple.intelligentroutingd.xpc.media — intelligentroutingd
//     Handles: AI routing for media (Photos, Music, Video)
//
//   com.apple.proactive.SuggestionRequest.ps_facetime_interaction_model — coreduetd
//     Handles: FaceTime call pattern analysis
//
//   com.apple.proactive.SuggestionRequest.cd_calendar_interaction_suggestions — coreduetd
//     Handles: Calendar interaction suggestion data

import Foundation
import ObjectiveC

// ── Generic probe protocol ─────────────────────────────────────────────────
@objc protocol GenericXPC: NSObjectProtocol {
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
    @objc optional func status(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func getStatus(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func fetchData(_ reply: @escaping (NSDictionary?, Error?) -> Void)
}

// ── CallIntelligence-specific protocol ────────────────────────────────────
@objc protocol CallIntelligenceXPC: NSObjectProtocol {
    @objc optional func fetchCallSummary(_ callID: NSString?,
                                          reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func allCallSummaries(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func transcriptForCall(_ callID: NSString?,
                                           reply: @escaping (NSString?, Error?) -> Void)
    @objc optional func voicemailTranscription(_ vmID: NSString?,
                                                reply: @escaping (NSString?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
    @objc optional func status(_ reply: @escaping (NSDictionary?, Error?) -> Void)
}

// ── Biome-specific protocol ───────────────────────────────────────────────
@objc protocol BiomeXPC: NSObjectProtocol {
    @objc optional func allEventsWithReply(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func eventsForAppBundleID(_ bundleID: NSString?,
                                              reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func recentEventsWithReply(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func queryEvents(_ query: NSDictionary?,
                                     reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

// ── CoreDuet knowledge protocol ───────────────────────────────────────────
@objc protocol CoreDuetKnowledgeXPC: NSObjectProtocol {
    @objc optional func queryKnowledge(_ query: NSDictionary?,
                                        reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func allInteractions(_ reply: @escaping (NSArray?, Error?) -> Void)
    @objc optional func peopleGraph(_ reply: @escaping (NSDictionary?, Error?) -> Void)
    @objc optional func ping(_ reply: @escaping (Bool, Error?) -> Void)
}

// ── Probe helper ──────────────────────────────────────────────────────────

func probe(service: String, proto: Protocol, label: String, waitSecs: Int = 6) -> Bool {
    print("\n╔══ \(label) ══╗")
    print("  service: \(service)")

    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var state = "pending"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if state == "pending" { state = "INVALIDATED — service name wrong or not running" }
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
        if state == "pending" { state = "XPC-ERROR (RPC channel live, method rejected)" }
        sema.signal()
    } as AnyObject

    if let p = px as? GenericXPC {
        p.ping? { v, e in
            if let e = e { print("  [ping] ERROR: \(e)") }
            else { print("  [ping] REPLY: \(v)  ← BYPASS + METHOD EXECUTED") }
            if state == "pending" { state = "PING REPLIED" }
            sema.signal()
        }
    }

    if sema.wait(timeout: .now() + .seconds(waitSecs)) == .timedOut {
        state = "TIMEOUT (\(waitSecs)s) *** ACCEPTED — NO ENTITLEMENT CHECK *** ← BYPASS"
    }

    print("  RESULT: \(state)")
    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.5)
    return state.contains("TIMEOUT") || state.contains("BYPASS") || state.contains("REPLY")
}

// ── Framework loading ──────────────────────────────────────────────────────

print("""
=== macOS 26 New Daemon XPC Bypass Probe ===
PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

Targets: callintelligenced, coreduetd, biomed, intelligentroutingd
All service names confirmed from plist dumps.
""")

for fw in [
    "/System/Library/PrivateFrameworks/CallIntelligence.framework/CallIntelligence",
    "/System/Library/PrivateFrameworks/BiomeStreams.framework/BiomeStreams",
    "/System/Library/PrivateFrameworks/CoreDuet.framework/CoreDuet",
    "/System/Library/PrivateFrameworks/CoreDuetDaemonProtocol.framework/CoreDuetDaemonProtocol",
] {
    let name = fw.components(separatedBy: "/").last!
    if dlopen(fw, RTLD_NOW | RTLD_GLOBAL) != nil {
        print("[dlopen] \(name) loaded")
    } else {
        print("[dlopen] \(name) — not found")
    }
}

// Check real ObjC protocol objects from frameworks
for n in ["_CICallSummaryXPCProtocol", "_CIServiceProtocol",
          "_CDKnowledgeClientProtocol", "_CDPeopleClientProtocol",
          "_BiomeAccessProtocol", "_BiomeComputeProtocol"] {
    let s = objc_getProtocol(n) != nil ? "FOUND ← use for real interface" : "not found"
    print("  proto \(n): \(s)")
}
print("")

var bypasses: [String] = []

// ── callintelligenced — call summaries + voicemail transcription ───────────
if probe(service: "com.apple.callintelligenced.service",
         proto: CallIntelligenceXPC.self,
         label: "callintelligenced (call AI)") {
    bypasses.append("com.apple.callintelligenced.service")
}

// ── coreduetd — user activity knowledge graph ─────────────────────────────
if probe(service: "com.apple.coreduetd.knowledge",
         proto: CoreDuetKnowledgeXPC.self,
         label: "coreduetd.knowledge (activity graph)") {
    bypasses.append("com.apple.coreduetd.knowledge")
}

// ── coreduetd — people/contacts interaction model ─────────────────────────
if probe(service: "com.apple.coreduetd.people",
         proto: CoreDuetKnowledgeXPC.self,
         label: "coreduetd.people (contacts graph)") {
    bypasses.append("com.apple.coreduetd.people")
}

// ── biomed — Biome user activity event store (ALL user data) ──────────────
if probe(service: "com.apple.biome.access.system",
         proto: BiomeXPC.self,
         label: "biome.access.system (ALL user activity)") {
    bypasses.append("com.apple.biome.access.system")
}

// ── biomed — Biome compute event source ───────────────────────────────────
if probe(service: "com.apple.biome.compute.source",
         proto: BiomeXPC.self,
         label: "biome.compute.source") {
    bypasses.append("com.apple.biome.compute.source")
}

// ── intelligentroutingd — media AI routing ────────────────────────────────
if probe(service: "com.apple.intelligentroutingd.xpc.media",
         proto: GenericXPC.self,
         label: "intelligentroutingd (media AI routing)") {
    bypasses.append("com.apple.intelligentroutingd.xpc.media")
}

// ── coreduetd — FaceTime interaction pattern model ────────────────────────
if probe(service: "com.apple.proactive.SuggestionRequest.ps_facetime_interaction_model",
         proto: CoreDuetKnowledgeXPC.self,
         label: "proactive.SuggestionRequest.ps_facetime_interaction_model") {
    bypasses.append("com.apple.proactive.SuggestionRequest.ps_facetime_interaction_model")
}

// ── coreduetd — Calendar interaction suggestions ──────────────────────────
if probe(service: "com.apple.proactive.SuggestionRequest.cd_calendar_interaction_suggestions",
         proto: CoreDuetKnowledgeXPC.self,
         label: "proactive.SuggestionRequest.cd_calendar_interaction_suggestions") {
    bypasses.append("com.apple.proactive.SuggestionRequest.cd_calendar_interaction_suggestions")
}

// ── coreduetd — unstructured reminder suggestions ─────────────────────────
if probe(service: "com.apple.proactive.SuggestionRequest.ps_unstructured_reminder_interaction_suggestions",
         proto: CoreDuetKnowledgeXPC.self,
         label: "proactive.SuggestionRequest.ps_unstructured_reminder_interaction_suggestions") {
    bypasses.append("com.apple.proactive.SuggestionRequest.ps_unstructured_reminder_interaction_suggestions")
}

print("""

╔══ Summary ══╗
Bypasses: \(bypasses.count) / 9 services tested
""")
for b in bypasses {
    print("  *** BYPASS: \(b)")
}
if bypasses.isEmpty {
    print("  No bypasses — all services either rejected connections or not running.")
}
print("""

TIMEOUT = connection accepted, no entitlement check (bypass)
INTERRUPTED = entitlement enforced (correctly protected)
INVALIDATED = service not running / name wrong
XPC-ERROR = connection live, method dispatch reached daemon
""")
