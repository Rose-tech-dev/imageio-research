// rapportd NSXPCProxy Protocol Probe v2
// Key discoveries from binary analysis:
//   - RPRemoteDisplayXPCDaemonInterface = class rapportd defines as daemon XPC handler
//   - RPRemoteDisplayXPCClientInterface = class for client callbacks
//   - diagnosticCommand:params: = a method rapportd handles on com.apple.RemoteDisplay
//   - com.apple.RemoteDisplay.Dedicated = an additional undiscovered XPC service
//   - entitlement check happens AFTER connection (not at connect time)
//
// This probe:
//   1. Sends a properly-structured NSXPCProxy message for diagnosticCommand:params:
//   2. Probes com.apple.RemoteDisplay.Dedicated (new service)
//   3. Tests what rapportd logs when it receives the proper message format
//
// Compile: clang -o rapportd_nsxpc_proto_probe rapportd_nsxpc_proto_probe.m -framework Foundation
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

// ---- PROTOCOL DEFINITIONS (guessed from rapportd binary analysis) ----

// RPRemoteDisplayDaemon exposes these on com.apple.RemoteDisplay:
// From binary: -[RPRemoteDisplayDaemon diagnosticCommand:params:]
// From binary: -[RPRemoteDisplayDaemon daemonInfoChanged:]
// The XPC-facing interface is 'RPRemoteDisplayXPCDaemonInterface'
@protocol RPRemoteDisplayXPCDaemonGuess <NSObject>
@optional
- (void)diagnosticCommand:(NSString *)command
                   params:(NSDictionary *)params
                withReply:(void(^)(NSDictionary *result))reply;
- (void)getDaemonInfo:(void(^)(NSDictionary *info))reply;
- (void)getSessionState:(void(^)(NSInteger state))reply;
- (void)startMirroringForDevice:(id)device withReply:(void(^)(BOOL success, NSError *error))reply;
- (void)stopMirroringWithReply:(void(^)(BOOL success))reply;
- (void)registerForUpdates:(id)observer withReply:(void(^)(BOOL))reply;
@end

// Client exports this back to rapportd (callbacks)
@protocol RPRemoteDisplayXPCClientGuess <NSObject>
@optional
- (void)sessionStateChanged:(NSInteger)state;
- (void)deviceFound:(id)device;
- (void)deviceLost:(id)device;
@end

// ---- PROBE FUNCTIONS ----

static void probe_with_method(const char *service,
                               const char *method_desc,
                               void(^test_block)(id proxy, dispatch_semaphore_t sema, NSString **result)) {
    printf("\n=== [%s] method: %s ===\n", service, method_desc);
    fflush(stdout);

    NSXPCConnection *conn = [[NSXPCConnection alloc] initWithMachServiceName:
        [NSString stringWithUTF8String:service]
        options:0];

    NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:
        @protocol(RPRemoteDisplayXPCDaemonGuess)];

    // Also set up what we export as the client
    NSXPCInterface *client_iface = [NSXPCInterface interfaceWithProtocol:
        @protocol(RPRemoteDisplayXPCClientGuess)];

    conn.remoteObjectInterface = iface;

    __block NSString *result = @"(pending)";
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    conn.invalidationHandler = ^{
        if ([result isEqualToString:@"(pending)"])
            result = @"INVALIDATED (connection rejected)";
        dispatch_semaphore_signal(sema);
    };
    conn.interruptionHandler = ^{
        if ([result isEqualToString:@"(pending)"])
            result = @"INTERRUPTED (rapportd closed connection)";
        dispatch_semaphore_signal(sema);
    };
    [conn resume];

    id proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *err) {
        result = [NSString stringWithFormat:@"ERROR HANDLER: %@ (code=%ld domain=%@)",
                  err.localizedDescription, (long)err.code, err.domain];
        dispatch_semaphore_signal(sema);
    }];

    printf("  Proxy: %p  (class: %s)\n", (__bridge void*)proxy, object_getClassName(proxy));
    fflush(stdout);

    // Run the test block which sends the actual message
    test_block(proxy, sema, &result);

    dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 6LL * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, deadline) != 0) {
        result = @"TIMEOUT (6s) - message sent, connection stayed open, no reply";
    }

    printf("  RESULT: %s\n\n", [result UTF8String]);
    fflush(stdout);
    [conn invalidate];
    sleep(1);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        printf("=== rapportd NSXPCProxy Protocol Probe v2 ===\n");
        printf("PID: %d  UID: %d\n\n", getpid(), getuid());
        fflush(stdout);

        // Test 1: diagnosticCommand:params: on com.apple.RemoteDisplay
        probe_with_method("com.apple.RemoteDisplay", "diagnosticCommand:params:", ^(id proxy, dispatch_semaphore_t sema, NSString **result) {
            id<RPRemoteDisplayXPCDaemonGuess> p = (id<RPRemoteDisplayXPCDaemonGuess>)proxy;
            [p diagnosticCommand:@"status"
                          params:@{@"verbose": @YES}
                       withReply:^(NSDictionary *r) {
                *result = [NSString stringWithFormat:@"SUCCESS: got reply=%@", r];
                dispatch_semaphore_signal(sema);
            }];
        });

        // Test 2: getDaemonInfo on com.apple.RemoteDisplay
        probe_with_method("com.apple.RemoteDisplay", "getDaemonInfo:", ^(id proxy, dispatch_semaphore_t sema, NSString **result) {
            id<RPRemoteDisplayXPCDaemonGuess> p = (id<RPRemoteDisplayXPCDaemonGuess>)proxy;
            [p getDaemonInfo:^(NSDictionary *info) {
                *result = [NSString stringWithFormat:@"SUCCESS: info=%@", info];
                dispatch_semaphore_signal(sema);
            }];
        });

        // Test 3: getSessionState on com.apple.RemoteDisplay
        probe_with_method("com.apple.RemoteDisplay", "getSessionState:", ^(id proxy, dispatch_semaphore_t sema, NSString **result) {
            id<RPRemoteDisplayXPCDaemonGuess> p = (id<RPRemoteDisplayXPCDaemonGuess>)proxy;
            [p getSessionState:^(NSInteger state) {
                *result = [NSString stringWithFormat:@"SUCCESS: sessionState=%ld", (long)state];
                dispatch_semaphore_signal(sema);
            }];
        });

        // Test 4: com.apple.RemoteDisplay.Dedicated (new service discovered in strings)
        probe_with_method("com.apple.RemoteDisplay.Dedicated", "diagnosticCommand:params:", ^(id proxy, dispatch_semaphore_t sema, NSString **result) {
            id<RPRemoteDisplayXPCDaemonGuess> p = (id<RPRemoteDisplayXPCDaemonGuess>)proxy;
            [p diagnosticCommand:@"status"
                          params:@{}
                       withReply:^(NSDictionary *r) {
                *result = [NSString stringWithFormat:@"SUCCESS (Dedicated): %@", r];
                dispatch_semaphore_signal(sema);
            }];
        });

        // Test 5: com.apple.rapport (general service)
        probe_with_method("com.apple.rapport", "diagnosticCommand:params:", ^(id proxy, dispatch_semaphore_t sema, NSString **result) {
            id<RPRemoteDisplayXPCDaemonGuess> p = (id<RPRemoteDisplayXPCDaemonGuess>)proxy;
            [p diagnosticCommand:@"diagnostics"
                          params:@{}
                       withReply:^(NSDictionary *r) {
                *result = [NSString stringWithFormat:@"SUCCESS (rapport): %@", r];
                dispatch_semaphore_signal(sema);
            }];
        });

        printf("\n=== Done ===\n");
        fflush(stdout);
    }
    return 0;
}
