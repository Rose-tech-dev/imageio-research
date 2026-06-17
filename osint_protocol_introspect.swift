// ObjC runtime introspection of OSIntelligence.framework
// Goal: discover the exact XPC protocol names and method type encodings
// used by ospredictiond's battery and charging services.
//
// OSIntelligence.framework is in the dyld shared cache — we load it
// via dlopen/NSBundle and then walk the ObjC protocol list.

import Foundation
import ObjectiveC

// ── Load OSIntelligence.framework ────────────────────────────────────────────

let fwPaths = [
    "/System/Library/PrivateFrameworks/OSIntelligence.framework/OSIntelligence",
    "/System/Library/PrivateFrameworks/OSIntelligence.framework/Versions/A/OSIntelligence",
]

var loaded = false
for path in fwPaths {
    if dlopen(path, RTLD_NOW | RTLD_GLOBAL) != nil {
        print("Loaded: \(path)")
        loaded = true
        break
    }
}

if !loaded {
    // Try loading via NSBundle (picks up from dyld cache automatically)
    let fwURL = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/OSIntelligence.framework")
    if let bundle = Bundle(url: fwURL), bundle.load() {
        print("Loaded via NSBundle: \(fwURL.path)")
        loaded = true
    }
}

if !loaded {
    print("WARNING: Could not explicitly load OSIntelligence.framework — protocols may still be available via dyld cache")
}

// ── Decode ObjC type encoding to readable signature ───────────────────────────

func decodeType(_ enc: String) -> String {
    var result = ""
    var i = enc.startIndex
    while i < enc.endIndex {
        let ch = enc[i]
        switch ch {
        case "v": result += "void"
        case "B": result += "BOOL"
        case "i": result += "int"
        case "I": result += "unsigned int"
        case "l": result += "long"
        case "L": result += "unsigned long"
        case "q": result += "long long"
        case "Q": result += "unsigned long long"
        case "f": result += "float"
        case "d": result += "double"
        case "c": result += "char"
        case "C": result += "unsigned char"
        case "s": result += "short"
        case "@":
            let next = enc.index(after: i)
            if next < enc.endIndex && enc[next] == "\"" {
                // @"ClassName"
                let nameStart = enc.index(after: next)
                if let nameEnd = enc[nameStart...].firstIndex(of: "\"") {
                    result += String(enc[nameStart..<nameEnd]) + " *"
                    i = nameEnd
                } else {
                    result += "id"
                }
            } else if next < enc.endIndex && enc[next] == "?" {
                result += "id (block?)"
                i = next
            } else {
                result += "id"
            }
        case "^": result += "void *"
        case ":": result += "SEL"
        case "#": result += "Class"
        case "?": result += "?"
        case "{":
            if let end = enc[i...].firstIndex(of: "}") {
                result += "struct { ... }"
                i = end
            } else {
                result += "{"
            }
        case "(":
            if let end = enc[i...].firstIndex(of: ")") {
                result += "union { ... }"
                i = end
            } else {
                result += "("
            }
        case "[":
            result += "array[]"
        case "r": result += "const "
        case "n": result += "in "
        case "N": result += "inout "
        case "o": result += "out "
        case "O": result += "bycopy "
        case "R": result += "byref "
        case "V": result += "oneway "
        default:
            if ch.isNumber { i = enc.index(after: i); continue }
            result += String(ch)
        }
        i = enc.index(after: i)
    }
    return result
}

func dumpProtocol(_ proto: Protocol) {
    let name = String(cString: protocol_getName(proto))
    print("\n@protocol \(name)")

    var count: UInt32 = 0

    // Required instance methods
    let reqMethods = protocol_copyMethodDescriptionList(proto, true, true, &count)
    if let methods = reqMethods {
        for j in 0..<Int(count) {
            let desc = methods[j]
            let sel = NSStringFromSelector(desc.name!)
            let types = desc.types.map { String(cString: $0) } ?? ""
            print("  - (?) \(sel);  // types: \(types)")
        }
        free(reqMethods)
    }

    // Optional instance methods
    count = 0
    let optMethods = protocol_copyMethodDescriptionList(proto, false, true, &count)
    if let methods = optMethods {
        for j in 0..<Int(count) {
            let desc = methods[j]
            let sel = NSStringFromSelector(desc.name!)
            let types = desc.types.map { String(cString: $0) } ?? ""
            print("  @optional - (?) \(sel);  // types: \(types)")
        }
        free(optMethods)
    }

    print("@end")
}

// ── Walk all registered protocols ────────────────────────────────────────────

print("\n=== All registered protocols (first 300 names) ===\n")

var protoCount: UInt32 = 0
let allProtocols = objc_copyProtocolList(&protoCount)
print("Total protocols registered: \(protoCount)")

// Print all names first so we can see everything
var found = 0
if let protos = allProtocols {
    for i in 0..<Int(protoCount) {
        let name = String(cString: protocol_getName(protos[i]))
        print("  \(name)")
    }
}

print("\n=== Full dump of matching protocols ===\n")

if let protos = allProtocols {
    for i in 0..<Int(protoCount) {
        let proto = protos[i]
        let name = String(cString: protocol_getName(proto))
        let lower = name.lowercased()
        if lower.contains("battery") || lower.contains("charging") ||
           lower.contains("osintelligence") || lower.contains("osprediction") ||
           lower.contains("inactivity") || lower.contains("prediction") ||
           lower.contains("osint") || lower.contains("mitigation") ||
           lower.contains("powerui") || lower.contains("smartcharge") {
            dumpProtocol(proto)
            found += 1
        }
    }
}
print("Matching protocols found: \(found)")

// ── Also try explicit protocol lookups by guessed names ───────────────────────

print("\n=== Explicit protocol lookups ===")
let candidateNames = [
    "OSIntelligenceBatteryService",
    "OSIntelligenceChargingService",
    "OSIntelligenceBatteryXPC",
    "OSIntelligenceChargingXPC",
    "OSIntelligenceBattery",
    "OSIntelligenceCharging",
    "OSIntelligenceService",
    "_OSBatteryService",
    "_OSChargingService",
    "OSPredictionBatteryService",
    "OSPredictionChargingService",
]

for name in candidateNames {
    if let proto = objc_getProtocol(name) {
        print("FOUND: \(name)")
        dumpProtocol(proto)
    } else {
        print("not found: \(name)")
    }
}

// Class enumeration removed — objc_copyClassList over the dyld cache is too heavy
// and causes SIGKILL on GitHub Actions runners. Protocol enumeration above is sufficient.
