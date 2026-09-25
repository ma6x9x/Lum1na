- (void)recordCandidate:(uint64_t)va kind:(NSString *)kind source:(NSString *)source {
    if (va < 0xffff000000000000ULL) return;
    NSMutableArray *leaks = _d[@"leaks"];
    if (![leaks isKindOfClass:[NSMutableArray class]]) {
        leaks = [leaks mutableCopy] ?: [NSMutableArray array];
        _d[@"leaks"] = leaks;
    }
    // v2: dedupe — an identical (va, kind, source) already on the board is
    // a re-poll of the same primitive, not a new leak. (This is why the
    // aio84530 tap produced 66 identical rows.)
    NSString *vaStr = [NSString stringWithFormat:@"0x%llx", va];
    for (NSDictionary *e in leaks) {
        if ([e isKindOfClass:[NSDictionary class]] &&
            [vaStr isEqualToString:e[@"va"]] &&
            [kind isEqualToString:e[@"kind"]] &&
            [source isEqualToString:e[@"source"]]) {
            return;
        }
    }
    [leaks addObject:@{
        @"va": vaStr,
        @"kind": kind ?: @"unknown",
        @"source": source ?: @"?",
        @"time": LabLocalMilitaryNow() ?: @""
    }];
    if (leaks.count > 64) {
        [leaks removeObjectsInRange:NSMakeRange(0, leaks.count - 64)];
    }
    [self persist];
}
