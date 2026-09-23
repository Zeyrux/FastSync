#ifndef CLIENT_SEND_INTERNAL_H
#define CLIENT_SEND_INTERNAL_H

/* Declarations shared between the client_send.c transfer orchestration and the
 * reporting (client_report.c), scanner-preparation (client_scan.c) and
 * manifest/list/dry-run (client_manifest.c) translation units that were split
 * out of it.  Nothing here is part of the public client_send.h facade. */

#include "array_list.h"
#include "client_send.h"
#include "config.h"
#include "delete_plan.h"
#include "delta.h"
#include "format.h"
#include "log.h"
#include "scanner.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* One mebibyte in bytes; the unit used by the --stats/--progress lines.
   Always cast to double when dividing so the output stays fractional. */
#define BYTES_PER_MIB (1024ULL * 1024ULL)

/* Compiled scanner inputs that are shared read-only across scanner instances
 * and, in -m mode, across worker threads. `base_filters` owns the compiled
 * command-line + -C rules; the FileListSet allow-set lives in the Config.
 * `hardlinks` owns the --hard-links/-H link-group detection table (NULL when
 * off) and is shared (mutex-guarded) across every scanner/worker of one scan. */
typedef struct {
  ScannerOptions options;
  FilterRuleList* base_filters; /* owned; may be NULL */
  HardLinkTable* hardlinks;     /* owned; may be NULL */
  char* relative_prefix;        /* owned -R prefix; may be NULL */
} PreparedScanner;

/* client_scan.c */
bool prepare_scanner(const Config* config, int num_threads, PreparedScanner* out);
void prepared_scanner_destroy(PreparedScanner* prepared);
bool append_implied_dir_times(const Config* config, ArrayList* dir_entries);
char* delete_scope_root_marker(const Config* config);
const char* delete_plan_walk_root(const Config* config, const ArrayList* synced_dirs);
bool files_from_list_check(const Config* config, ArrayList* missing_dest, int* skipped_out);
bool scan_paths_only(const Config* config, const ScannerOptions* options, ArrayList* manifest,
                     DeletePlanSender* plans, bool* io_error_out,
                     unsigned long long* non_dir_count_out, ArrayList* chunks_out,
                     bool emit_nonreg);

/* client_report.c */
void log_server_rejection(const char* context);
const char* display_bytes(unsigned long long bytes, bool human_readable, char* buffer,
                          size_t buffer_size);
unsigned long long dir_count_for_stats(const Config* config, const ArrayList* dir_entries,
                                       atomic_ullong* counter);
void report_transfer_stats(const Config* config, const TransferStats* stats, time_t start,
                           const ReceiverStats* recv);
void transfer_stats_note_entry(TransferStats* stats, const File* file);
void transfer_stats_note_transferred(TransferStats* stats, const File* file);
bool info_flag_enabled(const Config* config, LogInfoFlag flag);
void print_delete_reports(const Config* config, const ArrayList* paths);
const char* delete_display_path(const Config* config, const char* path);
bool progress_requested(const Config* config);
void client_progress_cleanup(void);
void client_progress_begin(const Config* config);
void client_progress_file(const Config* config, const File* file);
void client_progress_name(const Config* config, const File* file);
/* Emit a transferred entry's ancestor directories (as -i/--out-format change
 * lines or --progress name lines) before the entry's own line. */
void client_change_emit_ancestors(const Config* config, const File* file);
/* Output parity (protocol 2.30.0): probe each not-yet-known ancestor directory's
 * pre-transfer destination state before the entry that first triggers it is
 * sent.  Returns false on a protocol/transport error. */
bool client_change_probe_ancestors(const Config* config, const File* file, int fd);
/* Mark a transferred directory entry as already reported, and flush the
 * itemize lines for changed directories that had no transferred child. */
void client_change_mark_dir(const Config* config, const File* file);
void client_change_emit_pending_dirs(const Config* config, int fd);
void client_progress_uptodate(const Config* config, const File* file);
void client_progress_prepare(const Config* config, const ArrayList* plan_dirs,
                             unsigned long long plan_non_dir_count);
bool receive_stats_record(int fd, ReceiverStats* stats, ArrayList* would_delete);
/* --stderr=client diagnostic channel (client_report.c): install the queueing
 * log sink for a transfer, mark the session live, flush queued diagnostics over
 * the wire at a frame boundary, and tear the sink down. */
void client_messages_install(void);
void client_messages_activate(bool active);
void client_flush_client_messages(int fd);
void client_messages_end(void);

/* client_send.c */
void receive_daemon_motd(Client* client, const Config* config);
Client* connect_transfer_client(const Config* config);
void disconnect_transfer_client(Client* client);
int incremental_check(Client* client, File* file, const Config* config, DeltaSignature** out_sig,
                      unsigned long long* resume_offset);

/* client_manifest.c */
bool dry_run_targets_server(const Config* config);
bool add_chunk_to_manifest(ArrayList* manifest, const Chunk* chunk);
int send_dry_run_manifest(const Config* config);
int send_list_only(const Config* config);
int send_dry_run_remote(Config* config);
int send_delete_manifest(int fd, ArrayList* manifest, ArrayList* protected_prefixes,
                         ArrayList* size_skipped, ArrayList* missing_args, ArrayList* synced_dirs,
                         const FilterRuleList* per_dir_rules);
bool send_delete_manifest_early(Client* client, ArrayList* manifest, ArrayList* protected_prefixes,
                                ArrayList* size_skipped, ArrayList* missing_args,
                                ArrayList* synced_dirs, const FilterRuleList* per_dir_rules);

#endif
