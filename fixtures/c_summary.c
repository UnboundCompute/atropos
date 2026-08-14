/* Human reference for c_summary.index.json: flow-summary attachments.
 * memcpy/strcpy/strcat: Argument[1] (src) flows to Argument[0] (dest).
 * strdup: Argument[0] flows to the ReturnValue (a fresh copy). */
#include <string.h>
char *h(char *dst, const char *src) {
    memcpy(dst, src, 16);   /* edge: v_src -> v_dst */
    strcpy(dst, src);        /* edge: v2_src -> v2_dst */
    strcat(dst, src);        /* edge: v3_src -> v3_dst */
    return strdup(src);      /* edge: v_sd_in -> v_sd_ret */
}
