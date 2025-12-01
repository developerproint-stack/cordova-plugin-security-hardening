#import <Cordova/CDVPlugin.h>

@interface CertCheck : CDVPlugin

// Cordova-exposed command
- (void)startFridaMonitor:(CDVInvokedUrlCommand*)command;

// Internal helper
- (void)startFridaMonitorInternal;

@end
