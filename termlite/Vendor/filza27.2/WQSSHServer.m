//
//  WQSSHServer.m
//  FilzaSlop
//
//  In-process SSH server built on libssh (weakly linked; the public build
//  does not ship libssh). Authentication is intentionally simple:
//  mobile/alpine and root/alpine. Each session runs the same in-process shell
//  engine used by Filza's terminal, starting in the worse_query hub.
//

#import "WQSSHServer.h"
#import "WQTerminal.h"
#import "WQFilzaIntegration.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <string.h>
#import <sys/socket.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <unistd.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

static ssh_bind gSSHBind;
static ssh_key gSSHHostKey;
static pthread_t gSSHListenerThread;
static BOOL gSSHRunning;
static NSInteger gSSHPort = 2222;
static NSString *gSSHLastError;
static NSObject *gSSHLock;

static void WQSSHLog(NSString *message)
{
    NSLog(@"[WQSSH] %@", message);
}

static BOOL WQSSHLibraryAvailable(void)
{
    return dlsym(RTLD_DEFAULT, "ssh_bind_new") != NULL &&
           dlsym(RTLD_DEFAULT, "ssh_handle_key_exchange") != NULL;
}

#pragma mark - Session shell

static const char *WQSSHAuthorizedPassword(const char *user)
{
    if (!user) return NULL;
    if (strcmp(user, "mobile") == 0 || strcmp(user, "root") == 0)
        return "alpine";
    return NULL;
}

static void *WQSSHClientThread(void *argument)
{
    ssh_session session = (ssh_session)argument;
    @autoreleasepool {
        if (!session) return NULL;
        if (ssh_handle_key_exchange(session) != SSH_OK) {
            WQSSHLog([NSString stringWithFormat:@"key exchange failed: %s",
                ssh_get_error(session)]);
            ssh_disconnect(session);
            ssh_free(session);
            return NULL;
        }

        ssh_channel channel = NULL;
        char authenticatedUser[64] = {0};
        BOOL authenticated = NO;

        while (gSSHRunning) {
            ssh_message message = ssh_message_get(session);
            if (!message) break;
            int type = ssh_message_type(message);
            int subtype = ssh_message_subtype(message);

            if (type == SSH_REQUEST_AUTH && !authenticated) {
                if (subtype == SSH_AUTH_METHOD_PASSWORD) {
                    const char *user = ssh_message_auth_user(message);
                    const char *password = ssh_message_auth_password(message);
                    const char *expected = WQSSHAuthorizedPassword(user);
                    if (expected && password && strcmp(password, expected) == 0) {
                        ssh_message_auth_reply_success(message, 0);
                        authenticated = YES;
                        strncpy(authenticatedUser, user,
                                sizeof(authenticatedUser) - 1);
                        WQSSHLog([NSString stringWithFormat:@"login user=%s", user]);
                        ssh_message_free(message);
                        continue;
                    }
                }
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(message);
            } else if (authenticated && type == SSH_REQUEST_CHANNEL_OPEN &&
                       subtype == SSH_CHANNEL_SESSION) {
                channel = ssh_message_channel_request_open_reply_accept(message);
            } else if (authenticated && type == SSH_REQUEST_CHANNEL && channel) {
                if (subtype == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(message);
                } else if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    break;
                } else {
                    ssh_message_reply_default(message);
                }
            } else {
                ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }

        if (!authenticated || !channel) {
            ssh_disconnect(session);
            ssh_free(session);
            return NULL;
        }

        setenv("USER", authenticatedUser, 1);
        setenv("LOGNAME", authenticatedUser, 1);
        setenv("HOME", NSHomeDirectory().UTF8String, 1);
        setenv("SHELL", "fish", 1);

        int pid = -1;
        int master = WQTerminalSpawnShell(&pid, WQVirtualRootFolder());
        if (master < 0) {
            const char *failure = "Unable to start the in-process shell.\r\n";
            ssh_channel_write(channel, failure, (uint32_t)strlen(failure));
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            return NULL;
        }
        fcntl(master, F_SETFL, O_NONBLOCK);

        char buffer[4096];
        while (gSSHRunning && ssh_channel_is_open(channel)) {
            int incoming = ssh_channel_read_nonblocking(channel, buffer,
                                                        sizeof(buffer), 0);
            if (incoming > 0) {
                ssize_t written = 0;
                while (written < incoming) {
                    ssize_t step = write(master, buffer + written,
                                         (size_t)(incoming - written));
                    if (step <= 0) break;
                    written += step;
                }
            } else if (incoming == SSH_ERROR) {
                // Client may have half-closed stdin after piping a command.
                // Keep pumping shell output until the shell exits.
            }

            ssize_t outgoing = read(master, buffer, sizeof(buffer));
            if (outgoing > 0) {
                int offset = 0;
                while (offset < outgoing) {
                    int sent = ssh_channel_write(channel, buffer + offset,
                                                 (uint32_t)(outgoing - offset));
                    if (sent <= 0) break;
                    offset += sent;
                }
            } else if (outgoing < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }
            usleep(5000);
        }

        close(master);
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
    }
    return NULL;
}

#pragma mark - Listener

static void *WQSSHListener(void *argument)
{
    @autoreleasepool {
        while (gSSHRunning) {
            ssh_session session = ssh_new();
            if (!session) break;
            if (ssh_bind_accept(gSSHBind, session) != SSH_OK) {
                ssh_free(session);
                if (!gSSHRunning) break;
                usleep(20000);
                continue;
            }
            pthread_t thread;
            if (pthread_create(&thread, NULL, WQSSHClientThread, session) == 0) {
                pthread_detach(thread);
            } else {
                ssh_disconnect(session);
                ssh_free(session);
            }
        }
    }
    return NULL;
}

static BOOL WQSSHTryPort(NSInteger port, NSString **error)
{
    gSSHBind = ssh_bind_new();
    if (!gSSHBind) {
        if (error) *error = @"ssh_bind_new failed";
        return NO;
    }
    unsigned int bindPort = (unsigned int)port;
    ssh_bind_options_set(gSSHBind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(gSSHBind, SSH_BIND_OPTIONS_BINDPORT, &bindPort);
    if (gSSHHostKey)
        ssh_bind_options_set(gSSHBind, SSH_BIND_OPTIONS_IMPORT_KEY, gSSHHostKey);
    if (ssh_bind_listen(gSSHBind) != SSH_OK) {
        if (error) *error = [NSString stringWithFormat:@"listen failed: %s",
            ssh_get_error(gSSHBind)];
        ssh_bind_free(gSSHBind);
        gSSHBind = NULL;
        return NO;
    }
    gSSHPort = port;
    return YES;
}

BOOL WQSSHServerStart(NSString **error)
{
    @synchronized (gSSHLock ?: (gSSHLock = [NSObject new])) {
        if (gSSHRunning) return YES;
        if (!WQSSHLibraryAvailable()) {
            if (error) *error = @"libssh is not bundled in this build";
            return NO;
        }
        ssh_init();
        if (!gSSHHostKey) {
            if (ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &gSSHHostKey) != SSH_OK) {
                if (error) *error = @"failed to generate SSH host key";
                ssh_finalize();
                return NO;
            }
        }
        gSSHRunning = YES;
        BOOL bound = NO;
        NSString *lastError = nil;
        NSInteger requested = WQSSHServerPort();
        for (NSInteger port = requested; port < requested + 8; port++) {
            if (WQSSHTryPort(port, &lastError)) { bound = YES; break; }
        }
        if (!bound) {
            gSSHRunning = NO;
            ssh_finalize();
            if (error) *error = lastError ?: @"unable to bind SSH port";
            WQSSHLog([NSString stringWithFormat:@"start failed: %@", lastError]);
            return NO;
        }
        if (pthread_create(&gSSHListenerThread, NULL, WQSSHListener, NULL) != 0) {
            gSSHRunning = NO;
            ssh_bind_free(gSSHBind);
            gSSHBind = NULL;
            if (error) *error = @"failed to create SSH listener thread";
            return NO;
        }
        pthread_detach(gSSHListenerThread);
        gSSHLastError = nil;
        WQSSHLog([NSString stringWithFormat:@"started port=%ld url=%@",
            (long)gSSHPort, WQSSHServerURL()]);
        return YES;
    }
}

void WQSSHServerStop(void)
{
    @synchronized (gSSHLock ?: (gSSHLock = [NSObject new])) {
        if (!gSSHRunning && !gSSHBind) return;
        gSSHRunning = NO;
        if (gSSHBind) {
            ssh_bind_free(gSSHBind);
            gSSHBind = NULL;
        }
        if (gSSHHostKey) {
            ssh_key_free(gSSHHostKey);
            gSSHHostKey = NULL;
        }
        ssh_finalize();
        WQSSHLog(@"stopped");
    }
}

BOOL WQSSHServerIsRunning(void)
{
    return gSSHRunning;
}

NSInteger WQSSHServerPort(void)
{
    id value = [NSUserDefaults.standardUserDefaults objectForKey:@"WQSSHPort"];
    NSInteger port = [value respondsToSelector:@selector(integerValue)]
        ? [value integerValue] : 2222;
    if (port < 1024 || port > 65535) port = 2222;
    return port;
}

NSString *WQSSHServerURL(void)
{
    struct ifaddrs *interfaces = NULL;
    NSString *ip = nil;
    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *cursor = interfaces; cursor; cursor = cursor->ifa_next) {
            if (!cursor->ifa_addr || cursor->ifa_addr->sa_family != AF_INET) continue;
            NSString *name = [NSString stringWithUTF8String:cursor->ifa_name ?: ""];
            if ([name isEqualToString:@"lo0"]) continue;
            char address[INET_ADDRSTRLEN] = {0};
            struct sockaddr_in *sin = (struct sockaddr_in *)cursor->ifa_addr;
            if (!inet_ntop(AF_INET, &sin->sin_addr, address, sizeof(address))) continue;
            NSString *candidate = [NSString stringWithUTF8String:address];
            if ([name isEqualToString:@"en0"] || [name isEqualToString:@"en1"]) {
                ip = candidate;
                break;
            }
            if (!ip) ip = candidate;
        }
        freeifaddrs(interfaces);
    }
    return [NSString stringWithFormat:@"ssh -p %ld mobile@%@",
        (long)gSSHPort, ip ?: @"127.0.0.1"];
}
