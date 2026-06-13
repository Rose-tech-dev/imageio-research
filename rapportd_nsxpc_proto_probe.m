// rapportd NSXPCProxy protocol probe
// Discovers what protocol com.apple.RemoteDisplay exports by:
// 1. Connecting and attempting to get remoteObjectProxy
// 2. Sending structured messages matching likely method signatures
// 3. Probing what happens when a well-formed but unauthorized selector arrives
//
// Compile: clang -o rapportd_nsxpc_proto_probe rapportd_nsxpc_proto_probe.m -framework Foundation
// The key question: does rapportd drop connection only because our message is malformed,
// OR because we lack an entitlement? A properly-formed NSXPCProxy message will tell us.

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

// NSXPCProxy internal message format:
// The message sent over XPC is an NSXPCCoder-encoded dict. We can't easily
// replicate that. Instead, use NSXPCConnection's own proxy mechanism:
// set remoteObjectInterface to a dummy protocol and call a method.
// rapportd will either:
//  a) Accept it (execute the selector) = entitlement not checked
//  b) Return an error "connection interrupted" = entitlement checked on message
//  c) Return "connection invalid" = hard reject

@protocol RPRemoteDisplayServerGuess <NSObject>
// Guessing common method names from binary analysis
- (void)startRemoteDisplaySession:(id)session withReply:(void(^)(BOOL success, NSError *error))reply;
- (void)stopRemoteDisplaySession:(id)session withReply:(void(^)(BOOL success))reply;
- (void)getRemoteDisplayStatus:(void(^)(id status))reply;
- (void)registerClient:(id)client withReply:(void(^)(BOOL))reply;
@end

@protocol RPAutoUnlockGuess <NSObject>
- (void)getAuthenticationHint:(void(^)(id hint, NSError *error))reply;
- (void)requestAuthentication:(id)request withReply:(void(^)(id result))reply;
@end

@protocol RPRapportStatusGuess <NSObject>
- (void)getStatus:(void(^)(id status))reply;
- (void)subscribeToUpdates:(id)observer withReply:(void(^)(BOOL))reply;
@end

static void probe_nsxpc_with_protocol(const char *service_name,
                                       Protocol *proto,
                                       const char *method_name,
                                       SEL selector) {
    printf("\n=== Service: %s ===\n", service_name);
    printf("    Protocol: %s\n", protocol_getName(proto));
    printf("    Method:   %s\n", method_name);
    fflush(stdout);

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:
        [NSString stringWithUTF8String:service_name]
        options:0];

    if (!conn) {
        printf("    RESULT: Failed to create connection\n");
        return;
    }

    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:proto];
    conn.remoteObjectInterface = iface;

    __block NSString *result = @"(no result)";
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    conn.invalidationHandler = ^{
        result = @"INVALIDATED - connection rejected";
        dispatch_semaphore_signal(sema);
    };
    conn.interruptionHandler = ^{
        result = @"INTERRUPTED - service crashed or cancelled";
        dispatch_semaphore_signal(sema);
    };

    [conn resume];

    // Get a proxy and call the method with an error handler
    __block BOOL got_error_handler = NO;
    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        result = [NSString stringWithFormat:@"ERROR HANDLER: %@ (code=%ld domain=%@)",
                  err.localizedDescription, (long)err.code, err.domain];
        got_error_handler = YES;
        dispatch_semaphore_signal(sema);
    }];

    printf("    Got proxy: %p\n", (__bridge void*)proxy);
    fflush(stdout);

    // Try to call a method - this will send a properly-formatted NSXPCProxy message
    // The method call is the key: if rapportd checks entitlements here, we get an error
    @try {
        if ([proxy respondsToSelector:selector]) {
            printf("    Proxy responds to selector - calling...\n");
            fflush(stdout);
        } else {
            printf("    Proxy does NOT respond to selector (expected for typed proxy)\n");
            fflush(stdout);
        }

        // Force the message send - NSXPCProxy will encode it regardless
        // Use performSelector: to avoid compile-time type checking
        // But NSXPCProxy encodes the real protocol methods, so we need proper method signatures
    } @catch (NSException *e) {
        result = [NSString stringWithFormat:@"EXCEPTION: %@", e.reason];
        dispatch_semaphore_signal(sema);
    }

    // Wait for a response (may time out if rapportd accepts silently)
    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, deadline) != 0) {
        result = @"TIMEOUT (5s) - connection stayed open, no error";
    }

    printf("    RESULT: %s\n", [result UTF8String]);
    fflush(stdout);

    [conn invalidate];
    sleep(1);
}

// Try sending a properly-formatted NSXPCProxy message for getStatus
static void probe_status_call(void) {
    printf("\n=== NSXPC Status Call Probe (com.apple.rapport.StatusUpdates) ===\n");
    fflush(stdout);

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:
        @"com.apple.rapport.StatusUpdates"
        options:0];

    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RPRapportStatusGuess)];
    conn.remoteObjectInterface = iface;

    __block NSString *result = @"(pending)";
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    conn.invalidationHandler = ^{
        result = @"INVALIDATED";
        dispatch_semaphore_signal(sema);
    };
    conn.interruptionHandler = ^{
        result = @"INTERRUPTED";
        dispatch_semaphore_signal(sema);
    };

    [conn resume];

    id<RPRapportStatusGuess> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        result = [NSString stringWithFormat:@"ERROR: %@ [%ld]", err.localizedDescription, (long)err.code];
        dispatch_semaphore_signal(sema);
    }];

    // Send a real NSXPCProxy message
    [proxy getStatus:^(id status) {
        result = [NSString stringWithFormat:@"SUCCESS: status=%@", status];
        dispatch_semaphore_signal(sema);
    }];

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, deadline) != 0) {
        result = @"TIMEOUT (5s) - message sent, no reply";
    }

    printf("  Result: %s\n", [result UTF8String]);
    fflush(stdout);
    [conn invalidate];
}

// Low-level XPC: send a message that looks like an NSXPCProxy message
// NSXPCProxy encoding format (from reversing): uses XPC type 3 with specific structure
static void probe_raw_nsxpc_format(const char *service_name) {
    printf("\n=== Raw NSXPCProxy Format Probe: %s ===\n", service_name);
    fflush(stdout);

    // The NSXPCProxy message is sent as a Foundation-serialized XPC dict.
    // The key "f" = function/method name, "a" = arguments, "r" = reply ID
    // We can construct this using xpc_dictionary_create but the encoding
    // is more complex (uses NSXPCCoder, not raw XPC types).
    // Instead, let's use the NSXPCConnection synchronous call approach.

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:
        [NSString stringWithUTF8String:service_name]
        options:0];

    // Set NO remote interface (will cause different encoding)
    // conn.remoteObjectInterface is nil

    __block NSString *result = @"(pending)";
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    conn.invalidationHandler = ^{
        result = @"INVALIDATED (no interface set)";
        dispatch_semaphore_signal(sema);
    };
    conn.interruptionHandler = ^{
        result = @"INTERRUPTED (no interface set)";
        dispatch_semaphore_signal(sema);
    };

    [conn resume];

    // Try synchronousRemoteObjectProxy - different code path
    NSError *syncError = nil;
    id syncProxy = nil;
    @try {
        syncProxy = [conn synchronousRemoteObjectProxyWithErrorHandler:^(NSError *err) {
            result = [NSString stringWithFormat:@"SYNC ERROR: %@", err.localizedDescription];
            dispatch_semaphore_signal(sema);
        }];
    } @catch (NSException *e) {
        result = [NSString stringWithFormat:@"SYNC EXCEPTION: %@", e.reason];
        dispatch_semaphore_signal(sema);
    }

    printf("  Sync proxy: %p\n", (__bridge void*)syncProxy);
    fflush(stdout);

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, deadline) != 0) {
        result = @"TIMEOUT (3s) with sync proxy";
    }

    printf("  Result: %s\n", [result UTF8String]);
    fflush(stdout);
    [conn invalidate];
    sleep(1);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        printf("=== rapportd NSXPCProxy Protocol Probe ===\n");
        printf("PID: %d  UID: %d\n", getpid(), getuid());
        fflush(stdout);

        // Probe 1: RPRapportStatusGuess on StatusUpdates
        probe_status_call();

        // Probe 2: Raw sync proxy tests
        probe_raw_nsxpc_format("com.apple.RemoteDisplay");
        probe_raw_nsxpc_format("com.apple.rapport");
        probe_raw_nsxpc_format("com.apple.AutoUnlock.System.AuthenticationHintsProvider");

        printf("\n=== Done ===\n");
        fflush(stdout);
    }
    return 0;
}
