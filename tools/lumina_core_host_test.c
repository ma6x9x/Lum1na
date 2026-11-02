/* Host clang check of Exploit/lumina_core.c. No iOS SDK, no IOKit.
 *
 *   clang -std=c11 -O0 -Wall -Werror -IExploit \
 *     tools/lumina_core_host_test.c Exploit/lumina_core.c -lm \
 *     -o /tmp/lumina_core_host_test && /tmp/lumina_core_host_test
 */
#include "lumina_core.h"
#include <stdio.h>

int main(void) {
    int r = lumina_core_selftest();
    printf("lumina_core %s selftest=%d\n", lumina_core_version(), r);
    return r == 0 ? 0 : 1;
}
