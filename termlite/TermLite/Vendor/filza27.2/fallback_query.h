//
//  fallback_query.h
//  FileQuest
//
//  A second container-query primitive used only when worse_query fails.
//  The technique is derived from the access path used by Veilpath
//  (https://github.com/everettjf/veilpath), which in turn builds on
//  forcequitOS/bad_query. This file is part of a GPL-3.0 derivative of
//  worse_query and is distributed under the same license.
//

#ifndef fallback_query_h
#define fallback_query_h

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

/// Anchor the Container Manager query at the system mobilegestaltcache group,
/// set a traversal part domain, and consume the resulting extension. This is
/// intentionally a fallback: worse_query remains the primary engine.
int64_t fallback_query(NSString *target, bool alt_flags);

#endif /* fallback_query_h */
