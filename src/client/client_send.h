#ifndef CLIENT_SEND_H
#define CLIENT_SEND_H

#include "chunk.h"
#include "config.h"
#include "transport_tcp.h"
#include <signal.h>
#include <stdbool.h>

/* Set ONLY by the client's SIGINT/SIGTERM handler (async-signal-safe: the
 * handler stores 1 and does nothing else).  The send loops poll it via
 * client_abort_pending() and, when set, best-effort send STATUS_ABORT so the
 * receiver can clean up before the client exits. */
extern volatile sig_atomic_t client_abort_requested;
bool client_abort_pending(void);
/* Arm/disarm abort handling around the network phase.  While disarmed, a
 * SIGINT/SIGTERM takes the default action (immediate termination) so local-only
 * modes are not left unresponsive.  Defined in client_cli.c. */
void client_set_abort_armed(bool armed);

/* Both sender entry points BORROW `config` for the duration of the call; they
 * never free it, and the caller retains ownership (freeing it with
 * config_delete() once the call returns). */
int send_files(Config* config);
int send_files_multithreaded(Config** config);
/* rsync's --ignore-errors deletion gate: with no I/O error during the scan the
 * deletion phase always proceeds; with one it is suppressed unless
 * `--ignore-errors` was given.  Exposed so the decision can be unit-tested
 * without a privileged (mode-000) source directory.  See client_send.c. */
bool ignore_errors_allows_delete(const Config* config, bool had_io_error);

/* Phase 6 residual-batch (client-only).  See client_send.c. */
int write_batch_from_source(const Config* config, const char* batch_path);
int apply_batch_to_dest(const Config* config, const char* batch_path, const char* dest_root);

#endif
