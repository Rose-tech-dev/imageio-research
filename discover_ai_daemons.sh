#!/bin/bash
# Discover Apple Intelligence / Writing Tools / Priority Notifications daemons
# on macOS 15.x. Enumerates: running processes, Mach service names, XPC plists,
# entitlements, and exported ObjC selectors.
#
# Run on macOS 15 runner (GitHub Actions macos-15).
# Output: everything needed to write a targeted XPC probe.

set -euo pipefail

echo "=== APPLE INTELLIGENCE DAEMON DISCOVERY ==="
echo "macOS: $(sw_vers -productVersion)  Build: $(sw_vers -buildVersion)"
echo "Arch: $(uname -m)  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ── Daemon name patterns to search for ──────────────────────────────────────
PATTERNS=(
    "WritingTools"
    "writingtools"
    "intelligence"
    "Intelligence"
    "AIRuntime"
    "airuntime"
    "ImagePlayground"
    "imageplayground"
    "Genmoji"
    "genmoji"
    "notificationintelligence"
    "NotificationIntelligence"
    "siriinference"
    "SiriInference"
    "assistantd"
    "appleintelligenced"
    "AppleIntelligence"
    "NarrativeUI"
    "narrativeui"
    "AdaptiveInference"
    "adaptiveinference"
    "FoundationModels"
    "foundationmodels"
    "privatecloudcompute"
    "PrivateCloudCompute"
    "pcc"
    "coreml"
    "CoreML"
    "NLTagger"
    "naturallanguage"
    "SiriKit"
    "sirikit"
)

echo "=== 1. RUNNING PROCESSES MATCHING AI PATTERNS ==="
ps aux | head -1
for pat in "${PATTERNS[@]}"; do
    ps aux | grep -i "$pat" | grep -v "grep" | grep -v "discover_ai" && true
done
echo ""

echo "=== 2. LAUNCHD PLISTS — ALL APPLE INTELLIGENCE SERVICES ==="
PLIST_DIRS=(
    "/System/Library/LaunchDaemons"
    "/System/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "/Library/LaunchAgents"
)
for dir in "${PLIST_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for pat in "${PATTERNS[@]}"; do
            find "$dir" -name "*.plist" -iname "*${pat}*" 2>/dev/null | while read f; do
                echo "FOUND PLIST: $f"
                plutil -p "$f" 2>/dev/null | head -40 || true
                echo "---"
            done
        done
    fi
done
echo ""

echo "=== 3. ALL LAUNCHD PLISTS CONTAINING 'WritingTools' OR 'intelligence' (grep) ==="
grep -rl "WritingTools\|WritingTool\|AIRuntime\|intelligence\|Intelligence\|Genmoji\|ImagePlayground\|PrivateCloudCompute\|appleintelligence" \
    /System/Library/LaunchDaemons/ /System/Library/LaunchAgents/ 2>/dev/null | head -30 || echo "(none found)"
echo ""

echo "=== 4. BINARIES IN KNOWN AI/ML FRAMEWORK LOCATIONS ==="
AI_DIRS=(
    "/System/Library/PrivateFrameworks/NaturalLanguage.framework"
    "/System/Library/PrivateFrameworks/WritingTools.framework"
    "/System/Library/PrivateFrameworks/AIRuntime.framework"
    "/System/Library/PrivateFrameworks/Intelligence.framework"
    "/System/Library/PrivateFrameworks/AppleIntelligence.framework"
    "/System/Library/PrivateFrameworks/ImagePlayground.framework"
    "/System/Library/PrivateFrameworks/Genmoji.framework"
    "/System/Library/PrivateFrameworks/NotificationIntelligence.framework"
    "/System/Library/PrivateFrameworks/SiriInference.framework"
    "/System/Library/PrivateFrameworks/FoundationModels.framework"
    "/System/Library/PrivateFrameworks/CoreML.framework"
    "/System/Library/PrivateFrameworks/PrivateCloudCompute.framework"
    "/System/Library/Frameworks/WritingTools.framework"
    "/System/Library/Frameworks/NaturalLanguage.framework"
    "/usr/libexec"
)
for dir in "${AI_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "EXISTS: $dir"
        ls -la "$dir/" 2>/dev/null | head -20 || true
        echo "---"
    else
        echo "NOT PRESENT: $dir"
    fi
done
echo ""

echo "=== 5. FIND ALL BINARIES WITH 'intelligence' OR 'writingtools' IN PATH ==="
find /System/Library /usr/libexec /usr/lib \
    \( -iname "*intelligence*" -o -iname "*writingtools*" -o -iname "*airuntime*" \
       -o -iname "*genmoji*" -o -iname "*imageplayground*" -o -iname "*pccservice*" \
       -o -iname "*appleintelligenced*" -o -iname "*siriinference*" \
       -o -iname "*foundationmodels*" \) \
    -type f 2>/dev/null | head -50
echo ""

echo "=== 6. MACH SERVICE NAMES REGISTERED ON THIS SYSTEM ==="
# launchctl list to see loaded agents/daemons
echo "-- All loaded daemons with 'intelligence' or 'writing' or 'genmoji' --"
launchctl list 2>/dev/null | grep -iE "intelligence|writingtools|genmoji|imageplay|airuntime|pccservice|appleintelligence|siriinfer|foundationmodel" | head -40 || echo "(none matched)"
echo ""
echo "-- All launchctl list (first 200 lines) --"
launchctl list 2>/dev/null | head -200
echo ""

echo "=== 7. STRINGS SEARCH — MACH SERVICE NAMES IN CANDIDATE BINARIES ==="
# Look for com.apple.* Mach service names embedded in any AI daemon
SEARCH_DIRS=(
    "/System/Library/PrivateFrameworks"
    "/usr/libexec"
)
for sdir in "${SEARCH_DIRS[@]}"; do
    find "$sdir" -type f -name "*intelligence*" -o -name "*writingtools*" \
        -o -name "*genmoji*" -o -name "*imageplayground*" 2>/dev/null | while read bin; do
        echo "STRINGS in $bin:"
        strings "$bin" 2>/dev/null | grep -E "^com\.apple\.[a-z]" | head -30 || true
        echo "---"
    done
done
echo ""

echo "=== 8. ENTITLEMENTS OF AI DAEMONS ==="
for dir in "${AI_DIRS[@]}"; do
    find "$dir" -type f 2>/dev/null | while read bin; do
        ents=$(codesign -d --entitlements - "$bin" 2>/dev/null | strings | grep -v "^<?xml\|^<!DOCTYPE\|^<plist\|^<dict\|^</dict\|^</plist\|^<key\|^<string\|^<true\|^<false" | head -5)
        if [ -n "$ents" ]; then
            echo "ENTITLEMENTS: $bin"
            codesign -d --entitlements - "$bin" 2>/dev/null | strings | grep "com.apple" | head -20
            echo "---"
        fi
    done 2>/dev/null || true
done
echo ""

echo "=== 9. OBJC SELECTORS IN WRITING TOOLS / AI FRAMEWORKS ==="
OBJC_TARGETS=()
for dir in "${AI_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        find "$dir" -type f \( -name "*.dylib" -o -name "WritingTools" -o -name "AIRuntime" \
            -o -name "Intelligence" -o -name "Genmoji" -o -name "ImagePlayground" \
            -o -name "NotificationIntelligence" -o -name "SiriInference" \
            -o -name "FoundationModels" \) 2>/dev/null | while read f; do
            echo "SELECTORS in $f:"
            nm "$f" 2>/dev/null | grep " T -\[" | grep -iE "xpc|remote|proxy|service|request|session|connection" | head -30 || true
            strings "$f" 2>/dev/null | grep -E "^[a-z][a-zA-Z]+:[a-z]" | grep -iE "xpc|remote|service|proxy|session|request" | head -20 || true
            echo "---"
        done
    fi
done
echo ""

echo "=== 10. BOOT ARGUMENTS / FEATURE FLAGS RELATED TO APPLE INTELLIGENCE ==="
nvram -x -p 2>/dev/null | grep -iE "intelligence|writing|genmoji|airuntime" | head -20 || echo "(nvram: none)"
defaults read /Library/Preferences/com.apple.AppleIntelligence 2>/dev/null || echo "(pref: AppleIntelligence not found)"
defaults read /Library/Preferences/com.apple.WritingTools 2>/dev/null || echo "(pref: WritingTools not found)"
echo ""

echo "=== 11. /usr/libexec — NEW DAEMONS NOT IN PREVIOUS SURVEYS ==="
ls -la /usr/libexec/ | grep -iE "intelligence|writing|genmoji|imageplay|pcc|airuntime|siriinfer|foundationmodel|appleintelligence" | head -20
echo ""
echo "-- All /usr/libexec sorted by name --"
ls /usr/libexec/ | sort | head -100
echo ""

echo "=== DISCOVERY COMPLETE ==="
