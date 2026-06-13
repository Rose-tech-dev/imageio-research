import Foundation

let extras = [
    "com.apple.rapport.people",
    "com.apple.rapport.matching",
    "com.apple.rapport.private-discovery",
    "com.apple.rapport",
    "com.apple.RemoteDisplay",
]

for name in extras {
    print("Service: \(name)")
    let conn = NSXPCConnection(machServiceName: name, options: NSXPCConnection.Options(rawValue: 0))
    var status = "TIMEOUT (stayed open = ACCESSIBLE)"
    let sema = DispatchSemaphore(value: 0)
    conn.invalidationHandler = { status = "INVALIDATED (rejected)"; sema.signal() }
    conn.interruptionHandler = { status = "INTERRUPTED (service broke connection)"; sema.signal() }
    conn.resume()
    if sema.wait(timeout: .now() + .seconds(4)) == .timedOut {
        status = "TIMEOUT (4s) = NO ENTITLEMENT CHECK AT CONNECT"
    }
    conn.invalidate()
    print("  -> \(status)\n")
}
