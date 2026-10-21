// DeviceTLS.h — the STARTTLS/TLS bridge (ObjC wrapper around Secure Transport,
// whose constants are not Swift-visible). Used by DeviceConsole (lockdown
// control-channel STARTTLS + TLS-from-start service sockets).
#import <Foundation/Foundation.h>
#import <Security/SecIdentity.h>
#import <Security/SecureTransport.h>

@interface DeviceTLS : NSObject
// Performs the TLS handshake on an ALREADY-connected fd (plaintext STARTTLS
// or TLS-from-start — same call). Returns an SSLContextRef (void*) on
// success, nil + *errOut on failure. Identity = HostCertificate+HostPrivateKey
// (the pymobiledevice3 ssl_file pair). Server auth is accepted (pairing-model
// trust — the device presents its own cert).
+ (void *)upgradeFD:(int)fd cert:(NSData *)cert key:(NSData *)key errOut:(NSString **)errOut;
// through the established TLS: returns bytes read (0 = clean retry/empty), <0 = EOF/err
+ (int)tlsRead:(void *)ctx buf:(uint8_t *)buf len:(int)len;
+ (int)tlsWrite:(void *)ctx bytes:(const uint8_t *)buf len:(int)len;
@end