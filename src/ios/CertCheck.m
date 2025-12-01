#import "CertCheck.h"
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <mach/task.h>
#import <mach/mach_init.h>

@implementation CertCheck

#pragma mark - Cordova Plugin Init

- (void)pluginInitialize {
    NSLog(@"[CertCheck] iOS plugin loaded");
}

#pragma mark - Cordova Command: startFridaMonitor

- (void)startFridaMonitor:(CDVInvokedUrlCommand*)command {
    NSLog(@"[CertCheck] startFridaMonitor called from JS");

    [self startFridaMonitorInternal];

    CDVPluginResult* result =
        [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                           messageAsString:@"FRIDA_MONITOR_STARTED"];

    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

#pragma mark - Start Monitoring (loop)

- (void)startFridaMonitorInternal {
    static BOOL monitoring = NO;
    if (monitoring) {
        NSLog(@"[CertCheck] Monitor already running");
        return;
    }

    monitoring = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSLog(@"[CertCheck] Background frida monitoring started");

        while (true) {
            if ([self detectInjectedLibraries] ||
                [self detectFrida] ||
                [self isDebugged]) {

                NSLog(@"[CertCheck] Frida / debugger detected — exiting app");
                [self killApp];
                return;
            }

            [NSThread sleepForTimeInterval:3.0];
        }
    });
}

#pragma mark - Anti-Frida: Detect dylib injection

- (BOOL)detectInjectedLibraries {
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;

        NSString *lib = [NSString stringWithUTF8String:imageName];

        if ([lib containsString:@"frida"] ||
            [lib containsString:@"gadget"] ||
            [lib containsString:@"cycript"] ||
            [lib containsString:@"substrate"] ||
            [lib containsString:@"sslkill"] ) {

            NSLog(@"[CertCheck] Suspicious dylib detected: %@", lib);
            return YES;
        }
    }

    return NO;
}

#pragma mark - Anti-Frida: Detect runtime usage

- (BOOL)detectFrida {
    // Common Frida thread names start with "gum-"
    thread_act_array_t threads;
    mach_msg_type_number_t threadCount = 0;

    task_threads(mach_task_self(), &threads, &threadCount);

    for (int i = 0; i < threadCount; i++) {
        thread_t thread = threads[i];

        char name[256];
        pthread_t pthread = pthread_from_mach_thread_np(thread);
        if (pthread) {
            pthread_getname_np(pthread, name, sizeof(name));

            NSString *threadName = [NSString stringWithUTF8String:name];

            if ([threadName containsString:@"gum"] ||
                [threadName containsString:@"frida"]) {

                NSLog(@"[CertCheck] Suspicious thread detected: %@", threadName);
                return YES;
            }
        }
    }

    return NO;
}

#pragma mark - Anti-Debugging

- (BOOL)isDebugged {
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &size, NULL, 0) == -1) {
        return NO;
    }

    if ((info.kp_proc.p_flag & P_TRACED) != 0) {
        NSLog(@"[CertCheck] Debugger detected");
        return YES;
    }
    return NO;
}

#pragma mark - Kill App

- (void)killApp {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSLog(@"[CertCheck] App terminated due to security detection");
        exit(0);
    });
}

@end
