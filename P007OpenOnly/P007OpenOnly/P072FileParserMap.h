//
//  P072FileParserMap.h
//  In-app file-parser chain slot — v1 census + v2 CVE-2026-86950 glyph-OOB
//  oracle (synthetic 30-em extreme-coord TrueType, AA-rasterizer sweep).
//  v2 craft validated on macOS 15.6 pre-fix CG (loads, maps, renders).
//  Not a full ACE payload; PDF-ingest vehicle = p072 v3.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface P072FileParserMap : NSObject
+ (NSString *)tap NS_SWIFT_NAME(tap());
@end

NS_ASSUME_NONNULL_END
