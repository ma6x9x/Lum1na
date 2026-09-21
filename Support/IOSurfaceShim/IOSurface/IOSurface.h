// Glue shim: some iPhoneOS 18.x SDKs ship IOSurface.framework without umbrella IOSurface.h.
// Keep Exploit/*.m imports unchanged — point HEADER_SEARCH_PATHS here instead.
#import <IOSurface/IOSurfaceRef.h>
