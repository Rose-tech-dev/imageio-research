// Objective-C XPC probe for rapportd services
// Compile: clang -o xpc_probe xpc_probe.m -framework Foundation
// Tests whether unprivileged process can reach rapportd's XPC services

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <string.h>

static void probe_service(const char *name) {
    printf("\n=== Probing: %s ===\n", name);
    fflush(stdout);

    xpc_connection_t conn = xpc_connection_create_mach_service(name, NULL, 0);
    if (!conn) {
        printf("  NULL connection (not found or not accessible)\n");
        fflush(stdout);
        return;
    }
    printf("  Connection object created: %p\n", (void*)conn);
    fflush(stdout);

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block int signal_count = 0;

    xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_ERROR) {
            const char *desc = xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION);
            printf("  [ERROR] %s\n", desc ? desc : "(no description)");
        } else {
            char *desc = xpc_copy_description(event);
            printf("  [EVENT] %s\n", desc ? desc : "(no description)");
            if (desc) free(desc);
        }
        fflush(stdout);
        if (signal_count == 0) {
            signal_count++;
            dispatch_semaphore_signal(sema);
        }
    });

    xpc_connection_resume(conn);
    printf("  Connection resumed. Sending probe...\n");
    fflush(stdout);

    // Create and send a probe dictionary
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "type", "probe");
    xpc_dictionary_set_uint64(msg, "version", 1);
    xpc_connection_send_message(conn, msg);
    xpc_release(msg);

    // Wait up to 3 seconds for a response
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 3LL * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(sema, timeout) != 0) {
        printf("  [TIMEOUT] No response in 3s\n");
        fflush(stdout);
    }

    xpc_connection_cancel(conn);
    xpc_release(conn);
    sleep(1);
}

int main(int argc, char *argv[]) {
    printf("=== rapportd XPC Service Probe (Objective-C) ===\n");
    printf("Running as UID %d (PID %d)\n", getuid(), getpid());
    fflush(stdout);

    // Key services to test
    probe_service("com.apple.RemoteDisplay");
    probe_service("com.apple.rapport");
    probe_service("com.apple.rapport.private-discovery");
    probe_service("com.apple.rapport.StatusUpdates");
    probe_service("com.apple.rapport.people");
    probe_service("com.apple.rapport.matching");
    probe_service("com.apple.AutoUnlock.System.AuthenticationHintsProvider");

    printf("\n=== Done ===\n");
    fflush(stdout);
    return 0;
}
