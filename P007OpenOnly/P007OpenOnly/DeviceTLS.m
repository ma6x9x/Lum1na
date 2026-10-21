// DeviceTLS.m — Secure Transport STARTTLS bridge (see .h).
#import "DeviceTLS.h"

static OSStatus dRead(SSLConnectionRef ctx, void *data, size_t *len) {
    int fd = (int)(intptr_t)ctx;
    size_t total = 0;
    while (total < *len) {
        ssize_t n = read(fd, (char *)data + total, *len - total);
        if (n > 0) { total += (size_t)n; continue; }
        if (n == 0) { *len = total; return errSSLClosedGraceful; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (total) break;
            *len = total; return errSSLWouldBlock;
        }
        *len = total; return errSSLClosedAbort;
    }
    *len = total; return noErr;
}
static OSStatus dWrite(SSLConnectionRef ctx, const void *data, size_t *len) {
    int fd = (int)(intptr_t)ctx;
    size_t total = 0;
    while (total < *len) {
        ssize_t n = write(fd, (const char *)data + total, *len - total);
        if (n > 0) { total += (size_t)n; continue; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (total) break;
            *len = total; return errSSLWouldBlock;
        }
        *len = total; return errSSLClosedAbort;
    }
    *len = total; return noErr;
}

@implementation DeviceTLS

+ (NSData *)pemToDer:(NSData *)data tag:(NSString *)tag {
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) return data;
    NSString *begin = [NSString stringWithFormat:@"-----BEGIN %@-----", tag];
    NSString *end = [NSString stringWithFormat:@"-----END %@-----", tag];
    NSRange b = [s rangeOfString:begin], e = [s rangeOfString:end];
    if (b.location == NSNotFound || e.location == NSNotFound || e.location <= NSMaxRange(b))
        return data;
    NSString *b64 = [[s substringWithRange:NSMakeRange(NSMaxRange(b), e.location - NSMaxRange(b))]
        stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    b64 = [b64 stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    b64 = [b64 stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSData *der = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    return der ?: data;
}

+ (void *)upgradeFD:(int)fd cert:(NSData *)certData key:(NSData *)keyData errOut:(NSString **)errOut {
    if (errOut) *errOut = nil;
#define TFAIL(m) do { if (errOut) *errOut = m; return nil; } while (0)
    // PEM → DER
    NSData *cert = certData, *key = keyData;
    if ([certData length] > 27) cert = [self pemToDer:certData tag:@"CERTIFICATE"];
    if ([keyData length] > 11) key = [self pemToDer:keyData tag:@"PRIVATE KEY"];
    if ([certData length] > 27) {
        NSString *h = [[NSString alloc] initWithData:[certData subdataWithRange:NSMakeRange(0, 20)] encoding:NSUTF8StringEncoding];
        if ([h hasPrefix:@"-----BEGIN CERTIFICATE"]) cert = [self pemToDer:certData tag:@"CERTIFICATE"];
    }
    if ([keyData length] > 11) {
        NSString *h = [[NSString alloc] initWithData:[keyData subdataWithRange:NSMakeRange(0, 10)] encoding:NSUTF8StringEncoding];
        if ([h hasPrefix:@"-----BEGIN"]) key = [self pemToDer:keyData tag:@"PRIVATE KEY"];
    }
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)cert);
    if (!certRef) TFAIL(@"sec: bad certificate DER");
    NSDictionary *attrs = @{ (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                             (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate };
    CFErrorRef e = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)key, (__bridge CFDictionaryRef)attrs, &e);
    if (!keyRef) TFAIL(@"sec: bad private key");
#if TARGET_OS_IPHONE
    SecIdentityRef identity = NULL;
    OSStatus st = SecIdentityCreateWithCertificate(kCFAllocatorDefault, certRef, keyRef, &identity);
    if (st != errSecSuccess || !identity) TFAIL(@"sec: identity create failed");
#else
    SecIdentityRef identity = NULL;
    OSStatus st2 = SecIdentityCreateWithCertificate(kCFAllocatorDefault, certRef, &identity);
    (void)keyRef;
    if (st2 != errSecSuccess || !identity) TFAIL(@"sec: identity create failed");
#endif

    SSLContextRef ctx = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    SSLSetConnection(ctx, (SSLConnectionRef)(intptr_t)fd);
    SSLSetIOFuncs(ctx, &dRead, &dWrite);
    SSLSetCertificate(ctx, (__bridge CFArrayRef)@[(__bridge id)identity]);
    SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
    OSStatus res = errSSLWouldBlock;
    while (res == errSSLWouldBlock) {
        res = SSLHandshake(ctx);
        if (res == errSSLPeerAuthCompleted) { continue; }
    }
    if (res != noErr) {
        do { if (errOut) *errOut = [NSString stringWithFormat:@"handshake err=%d", (int)res]; return nil; } while (0);
    }
    return (void *)ctx;
}

+ (int)tlsRead:(void *)ctx buf:(uint8_t *)buf len:(int)len {
    size_t processed = 0;
    OSStatus st = SSLRead((SSLContextRef)ctx, buf, (size_t)len, &processed);
    if (st == noErr || st == errSSLWouldBlock) return (int)processed; // 0 = retry
    return -1;
}

+ (int)tlsWrite:(void *)ctx bytes:(const uint8_t *)buf len:(int)len {
    size_t processed = 0;
    OSStatus st = SSLWrite((SSLContextRef)ctx, buf, (size_t)len, &processed);
    if (st == noErr || st == errSSLWouldBlock) return (int)processed;
    return -1;
}


@end