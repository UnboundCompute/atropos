/* Human reference for c_buffer.index.json (the neutral symbol-index export).
 * Each callsite below has a matching record in the .index.json with the
 * per-argument value-node handles a real graph would carry. */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void f(int fd, const char *name) {
    char dst[64], src[128];
    memcpy(dst, src, sizeof dst);   /* buffer-size sink = Arg2; buffer-write = Arg0; src (Arg1) is NOT a sink */
    read(fd, dst, 64);              /* untrusted-input source = Arg1 buffer; fd (Arg0) is NOT a sink */
    char *e = getenv(name);         /* untrusted-input source = ReturnValue; name (Arg0) is NOT a sink */
    scanf("%s", dst);               /* buffer-write sink = Arg1 */
    (void)e;
}
