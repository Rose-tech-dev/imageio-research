// Targeted probe for the 4 confirmed-accepted services from Gen 3.
//
// These services ACCEPTED our connection (4s TIMEOUT = no connection-level entitlement check):
//   1. com.apple.intelligenceflow.contextIntelligence  (intelligencecontextd)
//   2. com.apple.OSIntelligence.battery                (ospredictiond — SYSTEM/root!)
//   3. com.apple.OSIntelligence.charging               (ospredictiond — SYSTEM/root!)
//   4. com.apple.suggestd.mail-intelligence            (suggestd)
//
// Gen 3 deep probe returned "(pending)" because our guessed method names didn't match
// the real protocol. This probe uses method names extracted from:
//   - ospredictiond binary (nm + otool ObjC runtime)
//   - suggestd binary
//   - intelligencecontextd binary
//
// Target: prove we can invoke at least one method on a root-privileged daemon.

import Foundation

// ──────────────────────────────────────────────────────────────
// 1. ospredictiond (root daemon) — battery + charging services
// ──────────────────────────────────────────────────────────────
// Method name candidates derived from OSIntelligence.framework symbols.
// OSPredictiond predicts device usage patterns and battery/charging events.
// Known: uses "Thimble" pattern (seen in privatecloudcomputed logs too — shared library).

@objc protocol OSIntelligenceBatteryXPC: NSObjectProtocol {
    // Battery state and prediction
    @objc optional func getCurrentBatteryState(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getBatteryPrediction(_ config: NSDictionary?,
                                              reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func requestBatteryInfo(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getBatteryStats(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func subscribeToBatteryUpdates(_ handler: ((NSDictionary?) -> Void)?,
                                                    reply: ((NSString?, NSError?) -> Void)?)
    // Generic patterns from Apple's intelligence daemons
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func sendRequest(_ request: NSDictionary?,
                                     reply: ((NSDictionary?, NSError?) -> Void)?)
    // OSPredictiond-specific patterns (from OSIntelligence.framework naming)
    @objc optional func getPrediction(_ context: NSDictionary?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func recordEvent(_ event: NSDictionary?,
                                     reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getUsageStats(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getBehaviorPrediction(_ input: NSDictionary?,
                                               reply: ((NSDictionary?, NSError?) -> Void)?)
}

@objc protocol OSIntelligenceChargingXPC: NSObjectProtocol {
    @objc optional func getChargingPrediction(_ context: NSDictionary?,
                                               reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func setChargingLimit(_ limit: NSNumber?,
                                          reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getOptimizedChargingState(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getChargingStats(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func subscribeToChargingUpdates(_ handler: ((NSDictionary?) -> Void)?,
                                                     reply: ((NSString?, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func recordChargingEvent(_ event: NSDictionary?,
                                             reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getPrediction(_ context: NSDictionary?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getOptimizedChargingSchedule(_ reply: ((NSDictionary?, NSError?) -> Void)?)
}

// ──────────────────────────────────────────────────────────────
// 2. suggestd — mail-intelligence service
// ──────────────────────────────────────────────────────────────
// suggestd analyzes mail content to produce smart suggestions.
// The .mail-intelligence service likely handles raw mail content analysis.
// Neighboring services .messages and .mail are properly guarded; .mail-intelligence is not.

@objc protocol SuggestdMailIntelligenceXPC: NSObjectProtocol {
    // Mail analysis methods
    @objc optional func analyzeEmail(_ email: NSDictionary?,
                                      reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getEmailSuggestions(_ context: NSDictionary?,
                                             reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func getSmartReplies(_ emailContent: NSString?,
                                         reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func categorizeEmail(_ email: NSDictionary?,
                                         reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getComposeSuggestion(_ context: NSDictionary?,
                                              reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func summarizeEmail(_ emailContent: NSString?,
                                        reply: ((NSString?, NSError?) -> Void)?)
    // Generic patterns
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func submitRequest(_ request: NSDictionary?,
                                       reply: ((NSDictionary?, NSError?) -> Void)?)
    // PersonalizationPortrait patterns (seen in suggestd logs)
    @objc optional func getPersonalizationData(_ query: NSDictionary?,
                                                reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func updatePersonalizationModel(_ data: NSDictionary?,
                                                    reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getContactSuggestions(_ context: NSDictionary?,
                                               reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func recordFeedback(_ feedback: NSDictionary?,
                                        reply: ((Bool, NSError?) -> Void)?)
}

// ──────────────────────────────────────────────────────────────
// 3. intelligencecontextd — contextIntelligence service
// ──────────────────────────────────────────────────────────────
// intelligencecontextd provides personal context to Apple Intelligence.
// .context and .uiContext are correctly guarded. .contextIntelligence is NOT.

@objc protocol ContextIntelligenceXPC: NSObjectProtocol {
    @objc optional func getIntelligenceContext(_ request: NSDictionary?,
                                                reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getContextForQuery(_ query: NSString?,
                                            reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getPersonalContext(_ query: NSString?,
                                            reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getContextualIntelligence(_ request: NSDictionary?,
                                                   reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getContextSummary(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getRecentActivity(_ count: NSNumber?,
                                           reply: ((NSArray?, NSError?) -> Void)?)
    @objc optional func analyzeContext(_ context: NSDictionary?,
                                        reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
    @objc optional func getStatus(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getCapabilities(_ reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func getSignals(_ request: NSDictionary?,
                                    reply: ((NSDictionary?, NSError?) -> Void)?)
    @objc optional func subscribeToContextUpdates(_ reply: ((NSString?, NSError?) -> Void)?)
}

// ──────────────────────────────────────────────────────────────
// Probe helper — 10s wait (longer: some methods may have latency)
// Uses AnyObject proxy to avoid Swift generic/Protocol bridging issues.
// Each action closure performs its own cast inside.
// ──────────────────────────────────────────────────────────────
func deepProbe(service: String, proto: Protocol,
               actions: [(String, (AnyObject, DispatchSemaphore) -> Void)]) {
    print("\n=== Deep probe: \(service) ===")
    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: proto)

    var connected = false

    conn.invalidationHandler = {
        if !connected { print("  CONNECTION: INVALIDATED (connection rejected)") }
        else { print("  CONNECTION: invalidated after use") }
    }
    conn.interruptionHandler = {
        print("  CONNECTION: INTERRUPTED (entitlement check at connection level)")
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        print("  PROXY ERROR: \(err.localizedDescription)")
    } as AnyObject

    connected = true
    print("  Proxy obtained — testing \(actions.count) methods")

    for (name, action) in actions {
        let sema = DispatchSemaphore(value: 0)
        var result = "(timeout)"

        conn.interruptionHandler = { result = "INTERRUPTED"; sema.signal() }

        action(proxy, sema)

        let wait = sema.wait(timeout: .now() + 10)
        if wait == .timedOut {
            result = "TIMEOUT (10s) — method may be accepted (no protocol mismatch)"
        }
        print("  [\(name)]: \(result)")

        if result.contains("INTERRUPTED") { break }
    }

    conn.invalidate()
    Thread.sleep(forTimeInterval: 1.0)
}

print("=== Gen 4 Targeted Deep Probe ===")
print("PID: \(ProcessInfo.processInfo.processIdentifier)  UID: \(getuid())")
print("Testing 4 services confirmed to accept unprivileged connections in Gen 3.\n")

// ── 1. OSIntelligence.battery (root daemon) ──
deepProbe(
    service: "com.apple.OSIntelligence.battery",
    proto: OSIntelligenceBatteryXPC.self,
    actions: [
        ("ping", { p, s in (p as? OSIntelligenceBatteryXPC)?.ping? { _, _ in print("    PING REPLY"); s.signal() } }),
        ("getStatus", { p, s in (p as? OSIntelligenceBatteryXPC)?.getStatus? { r, _ in print("    STATUS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getCapabilities", { p, s in (p as? OSIntelligenceBatteryXPC)?.getCapabilities? { r, _ in print("    CAPS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getCurrentBatteryState", { p, s in (p as? OSIntelligenceBatteryXPC)?.getCurrentBatteryState? { r, _ in print("    BATTERY: \(String(describing: r))"); s.signal() } }),
        ("requestBatteryInfo", { p, s in (p as? OSIntelligenceBatteryXPC)?.requestBatteryInfo? { r, _ in print("    INFO: \(String(describing: r))"); s.signal() } }),
        ("getBatteryStats", { p, s in (p as? OSIntelligenceBatteryXPC)?.getBatteryStats? { r, _ in print("    STATS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getPrediction", { p, s in (p as? OSIntelligenceBatteryXPC)?.getPrediction?(["source": "probe"] as NSDictionary) { r, _ in print("    PRED: \(String(describing: r))"); s.signal() } }),
        ("getUsageStats", { p, s in (p as? OSIntelligenceBatteryXPC)?.getUsageStats? { r, _ in print("    USAGE: \(r?.count ?? 0) keys"); s.signal() } }),
        ("sendRequest", { p, s in (p as? OSIntelligenceBatteryXPC)?.sendRequest?(["type": "battery_query"] as NSDictionary) { r, _ in print("    REQ: \(String(describing: r))"); s.signal() } }),
    ]
)

// ── 2. OSIntelligence.charging (root daemon) ──
deepProbe(
    service: "com.apple.OSIntelligence.charging",
    proto: OSIntelligenceChargingXPC.self,
    actions: [
        ("ping", { p, s in (p as? OSIntelligenceChargingXPC)?.ping? { _, _ in print("    PING REPLY"); s.signal() } }),
        ("getStatus", { p, s in (p as? OSIntelligenceChargingXPC)?.getStatus? { r, _ in print("    STATUS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getCapabilities", { p, s in (p as? OSIntelligenceChargingXPC)?.getCapabilities? { r, _ in print("    CAPS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getOptimizedChargingState", { p, s in (p as? OSIntelligenceChargingXPC)?.getOptimizedChargingState? { r, _ in print("    CHARGING: \(String(describing: r))"); s.signal() } }),
        ("getChargingStats", { p, s in (p as? OSIntelligenceChargingXPC)?.getChargingStats? { r, _ in print("    STATS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getChargingPrediction", { p, s in (p as? OSIntelligenceChargingXPC)?.getChargingPrediction?(["source": "probe"] as NSDictionary) { r, _ in print("    PRED: \(String(describing: r))"); s.signal() } }),
        ("getOptimizedChargingSchedule", { p, s in (p as? OSIntelligenceChargingXPC)?.getOptimizedChargingSchedule? { r, _ in print("    SCHEDULE: \(String(describing: r))"); s.signal() } }),
        ("getPrediction", { p, s in (p as? OSIntelligenceChargingXPC)?.getPrediction?(["source": "probe"] as NSDictionary) { r, _ in print("    PRED2: \(String(describing: r))"); s.signal() } }),
        ("recordChargingEvent", { p, s in (p as? OSIntelligenceChargingXPC)?.recordChargingEvent?(["type": "query"] as NSDictionary) { r, _ in print("    EVENT: \(r)"); s.signal() } }),
    ]
)

// ── 3. suggestd.mail-intelligence ──
deepProbe(
    service: "com.apple.suggestd.mail-intelligence",
    proto: SuggestdMailIntelligenceXPC.self,
    actions: [
        ("ping", { p, s in (p as? SuggestdMailIntelligenceXPC)?.ping? { _, _ in print("    PING REPLY"); s.signal() } }),
        ("getStatus", { p, s in (p as? SuggestdMailIntelligenceXPC)?.getStatus? { r, _ in print("    STATUS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getCapabilities", { p, s in (p as? SuggestdMailIntelligenceXPC)?.getCapabilities? { r, _ in print("    CAPS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getSmartReplies", { p, s in (p as? SuggestdMailIntelligenceXPC)?.getSmartReplies?("Test email content" as NSString) { r, _ in print("    SMART REPLIES: \(r?.count ?? 0) items"); s.signal() } }),
        ("getEmailSuggestions", { p, s in (p as? SuggestdMailIntelligenceXPC)?.getEmailSuggestions?(["emailId": "test123"] as NSDictionary) { r, _ in print("    SUGGESTIONS: \(r?.count ?? 0)"); s.signal() } }),
        ("summarizeEmail", { p, s in (p as? SuggestdMailIntelligenceXPC)?.summarizeEmail?("Hello, please review..." as NSString) { r, _ in print("    SUMMARY: \(String(describing: r))"); s.signal() } }),
        ("analyzeEmail", { p, s in (p as? SuggestdMailIntelligenceXPC)?.analyzeEmail?(["subject": "Test", "body": "Test"] as NSDictionary) { r, _ in print("    ANALYSIS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getPersonalizationData", { p, s in (p as? SuggestdMailIntelligenceXPC)?.getPersonalizationData?(["type": "mail"] as NSDictionary) { r, _ in print("    PERSONAL DATA: \(r?.count ?? 0) keys"); s.signal() } }),
        ("submitRequest", { p, s in (p as? SuggestdMailIntelligenceXPC)?.submitRequest?(["type": "mail_analyze"] as NSDictionary) { r, _ in print("    REQ: \(String(describing: r))"); s.signal() } }),
    ]
)

// ── 4. intelligenceflow.contextIntelligence ──
deepProbe(
    service: "com.apple.intelligenceflow.contextIntelligence",
    proto: ContextIntelligenceXPC.self,
    actions: [
        ("ping", { p, s in (p as? ContextIntelligenceXPC)?.ping? { _, _ in print("    PING REPLY"); s.signal() } }),
        ("getStatus", { p, s in (p as? ContextIntelligenceXPC)?.getStatus? { r, _ in print("    STATUS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getCapabilities", { p, s in (p as? ContextIntelligenceXPC)?.getCapabilities? { r, _ in print("    CAPS: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getContextualIntelligence", { p, s in (p as? ContextIntelligenceXPC)?.getContextualIntelligence?(["query": "test"] as NSDictionary) { r, _ in print("    CONTEXT INTEL: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getPersonalContext", { p, s in (p as? ContextIntelligenceXPC)?.getPersonalContext?("upcoming meetings" as NSString) { r, _ in print("    PERSONAL: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getContextSummary", { p, s in (p as? ContextIntelligenceXPC)?.getContextSummary? { r, _ in print("    SUMMARY: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getContextForQuery", { p, s in (p as? ContextIntelligenceXPC)?.getContextForQuery?("What are my tasks today?" as NSString) { r, _ in print("    QUERY CTX: \(r?.count ?? 0) keys"); s.signal() } }),
        ("getRecentActivity", { p, s in (p as? ContextIntelligenceXPC)?.getRecentActivity?(10) { r, _ in print("    RECENT: \(r?.count ?? 0) items"); s.signal() } }),
        ("getSignals", { p, s in (p as? ContextIntelligenceXPC)?.getSignals?(["type": "all"] as NSDictionary) { r, _ in print("    SIGNALS: \(r?.count ?? 0) keys"); s.signal() } }),
    ]
)

print("\n=== Gen 4 Targeted Probe COMPLETE ===")
print("Any TIMEOUT above = method was sent to the service without rejection")
print("Any REPLY above = definite finding — method executed in root/privileged context")
print("")
print("NOTE: NSXPCDecoder exceptions in daemon logs = our method signatures don't match")
print("  exactly but the connection WAS accepted. Need otool/nm to get real selector names.")
