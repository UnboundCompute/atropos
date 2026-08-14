/* Human reference for c_ambiguous.index.json.
 * The application defines its own function also named `system`. A name-only
 * model (package: null) matches both the libc symbol and the app symbol, so
 * the binder must report `ambiguous` rather than silently attach. */
extern int system(const char *);   /* libc */
static int system_app(int code);   /* app's own, exported to the index as name "system", module "app" */

void g(const char *cmd, int code) {
    system(cmd);        /* libc system  -> module null */
    system_app(code);   /* app  system  -> module "app" (same spelling in the index) */
}
