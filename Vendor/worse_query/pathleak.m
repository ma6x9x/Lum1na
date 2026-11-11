//
//  pathleak.m
//  worse_query
//
//  Created by Taj C on 9/2/26.
//

/*
     pathleak - The dumbest arbitrary path enumeration.
     Copyright (C) 2026 Taj C (forcequit)

     This program is free software: you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published by
     the Free Software Foundation, either version 3 of the License, or
     (at your option) any later version.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#import <Foundation/Foundation.h>
#include <string.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>

// This is just a rewrite of bad_query_list to return an NSString array and run faster
// The way this works is literally just brute-forcing inodes and doing fsgetpath until it gets a matching path, lol.
// Which is still, obviously, dramatically faster than brute-forcing UUIDs.

// It might be possible to derive a sane inode value automagically by just creating a file, doing stat() on it, getting *that* file's inode, then using that for the max_inode count.

NSArray<NSString *> *pathleak(NSString *path, uint64_t max_inode) {
    // Sanity checks
    if (path.length == 0 || max_inode < 1) return nil;
    NSString *dir = path;
    while (dir.length > 1 && [dir hasSuffix: @"/"]) { // Trim trailing slash (if present)
        dir = [dir substringToIndex: dir.length - 1];
    }

    // Set everything up
    struct statfs sfs;
    if (statfs(dir.fileSystemRepresentation, &sfs) != 0) return nil;
    fsid_t fsid = sfs.f_fsid;


    // fsgetpath is a syscall per inode. Splitting the range across the
    // performance cores cuts the wall-clock time substantially on A-series
    // devices; each worker owns its own bucket so no locking is required.
    NSUInteger workerCount = MIN((NSUInteger)8,
        MAX((NSUInteger)2, NSProcessInfo.processInfo.processorCount));
    NSMutableArray<NSMutableArray<NSString *> *> *buckets =
        [NSMutableArray arrayWithCapacity:workerCount];
    for (NSUInteger index = 0; index < workerCount; index++)
        [buckets addObject:[NSMutableArray array]];

    uint64_t chunkSize = (max_inode + workerCount - 1) / workerCount;
    dispatch_apply(workerCount,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t index) {
        uint64_t start = 1 + chunkSize * (uint64_t)index;
        uint64_t end = MIN(max_inode, start + chunkSize - 1);
        if (start > max_inode) return;
        NSMutableArray<NSString *> *bucket = buckets[index];
        char prefix[PATH_MAX];
        if (![dir getFileSystemRepresentation:prefix maxLength:sizeof(prefix)]) return;
        size_t prefix_length = strlen(prefix);
        if (prefix_length == 1 && prefix[0] == '/') prefix_length = 0;
        char buffer[PATH_MAX];
        for (uint64_t inode = start; inode <= end; inode++) {
            ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
            if (n <= 0) continue;

            if (strncmp(buffer, prefix, prefix_length) != 0) continue;
            if (buffer[prefix_length] != '/') continue;
            if (strchr(buffer + prefix_length + 1, '/')) continue;

            NSString *string = [[NSString alloc] initWithBytes:buffer
                length:strlen(buffer) encoding:NSUTF8StringEncoding];
            if (string) [bucket addObject:string];
        }
    });

    NSMutableArray<NSString *> *result = [NSMutableArray array];
    for (NSArray<NSString *> *bucket in buckets) [result addObjectsFromArray:bucket];
    return result;
}

NSArray<NSString *> *pathleak_roots(NSArray<NSString *> *roots,
                                    NSUInteger maxDepth,
                                    uint64_t max_inode) {
    if (roots.count == 0 || max_inode < 1) return nil;

    NSString *anchor = roots.firstObject;
    struct statfs sfs;
    if (statfs(anchor.fileSystemRepresentation, &sfs) != 0) return nil;
    fsid_t fsid = sfs.f_fsid;

    NSUInteger workerCount = MIN((NSUInteger)8,
        MAX((NSUInteger)2, NSProcessInfo.processInfo.processorCount));
    NSMutableArray<NSMutableArray<NSString *> *> *buckets =
        [NSMutableArray arrayWithCapacity:workerCount];
    for (NSUInteger index = 0; index < workerCount; index++)
        [buckets addObject:[NSMutableArray array]];

    uint64_t chunkSize = (max_inode + workerCount - 1) / workerCount;
    dispatch_apply(workerCount,
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^(size_t index) {
        uint64_t start = 1 + chunkSize * (uint64_t)index;
        uint64_t end = MIN(max_inode, start + chunkSize - 1);
        if (start > max_inode) return;

        NSUInteger rootCount = roots.count;
        char **prefixes = calloc(rootCount, sizeof(char *));
        size_t *lengths = calloc(rootCount, sizeof(size_t));
        if (!prefixes || !lengths) {
            free(prefixes); free(lengths); return;
        }
        for (NSUInteger rootIndex = 0; rootIndex < rootCount; rootIndex++) {
            NSString *root = roots[rootIndex];
            char value[PATH_MAX];
            if (![root getFileSystemRepresentation:value maxLength:sizeof(value)])
                continue;
            prefixes[rootIndex] = strdup(value);
            lengths[rootIndex] = strlen(value);
        }

        NSMutableArray<NSString *> *bucket = buckets[index];
        char buffer[PATH_MAX];
        for (uint64_t inode = start; inode <= end; inode++) {
            ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
            if (n <= 0) continue;

            for (NSUInteger rootIndex = 0; rootIndex < rootCount; rootIndex++) {
                char *prefix = prefixes[rootIndex];
                size_t length = lengths[rootIndex];
                if (!prefix || length == 0) continue;
                if (strncmp(buffer, prefix, length) != 0) continue;
                if (buffer[length] != '/') continue;
                const char *remainder = buffer + length + 1;
                NSUInteger depth = 0;
                for (const char *cursor = remainder; *cursor; cursor++)
                    if (*cursor == '/') depth++;
                if (depth > maxDepth) continue;
                NSString *string = [[NSString alloc] initWithBytes:buffer
                    length:strlen(buffer) encoding:NSUTF8StringEncoding];
                if (string) [bucket addObject:string];
                break;
            }
        }

        for (NSUInteger rootIndex = 0; rootIndex < rootCount; rootIndex++)
            free(prefixes[rootIndex]);
        free(prefixes);
        free(lengths);
    });

    NSMutableArray<NSString *> *result = [NSMutableArray array];
    for (NSArray<NSString *> *bucket in buckets) [result addObjectsFromArray:bucket];
    return result;
}
