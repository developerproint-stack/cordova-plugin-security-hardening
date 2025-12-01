#import "CertCheck.h"
#import <sys/sysctl.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>

@implementation CertCheck

- (void)pluginInitialize {
    // Start background anti-frida check
    [self startFridaMonitor];
}

- (void)startFridaMonitor {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        while (true) {
            if ([self detectFrida] || [self isDebugged] || [self detectInjectedLibraries]) {
                [self killApp];
                break;
            }
            [NSThread sleepForTimeInterval:3.0];
        }
    });
}

#pragma mark - Anti Frida

- (BOOL)detectInjectedLibraries {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        NSString *lib = [NSString stringWithUTF8String:name];

        if ([lib containsString:@"frida"] ||
            [lib containsString:@"gadget"] ||
            [lib containsString:@"cycript"] ||
            [lib containsString:@"sslkill"] ||
            [lib containsString:@"substrate"]) {

            return YES;
        }
    }
    return NO;
}

- (BOOL)detectFrida {
    // Basic thread name detection (Frida gadget threads contain "gum-" prefix)
    NSArray *threads = [NSThread callStackReturnAddresses];
    for (id t in threads) {
        NSString *desc = [NSString stringWithFormat:@"%@", t];
        if ([desc containsString:@"frida"] || [desc containsString:@"gum"]) {
            return YES;
        }
    }
    return NO;
}

#pragma mark - Anti Debugger

- (BOOL)isDebugged {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);

    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();

    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

#pragma mark - Kill App

- (void)killApp {
    dispatch_async(dispatch_get_main_queue(), ^{
        exit(0);
    });
}

@end
