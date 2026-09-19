#ifndef FILE_TYPES_H
#define FILE_TYPES_H

#include "data.h"
#include "format.h"
#include "xattr.h"
#include <stdbool.h>
#include <sys/stat.h>

typedef enum { FILE_TYPE_REGULAR, FILE_TYPE_SYMLINK, FILE_TYPE_DIR } FileType;

typedef struct {
  mode_t mode;
  uid_t uid;
  gid_t gid;
  time_t mtime_sec;
  long mtime_nsec;
  /* Optional access time (-U/--atimes) and creation/birth time (-N/--crtimes),
   * appended for protocol 2.12.0.  The SENDER sets the corresponding *_valid
   * flag only when the preserve option is active (and, for crtime, only when
   * the source platform exposed a birth time via statx STATX_BTIME).  The wire
   * always carries the fields and the flags; a false flag tells the receiver to
   * ignore the value. */
  bool atime_valid;
  time_t atime_sec;
  long atime_nsec;
  bool crtime_valid;
  time_t crtime_sec;
  long crtime_nsec;
} FileMetadata;

typedef struct {
  char* path;
  /* Sender-side override for the path transmitted on the wire (and used for
   * the delete manifest / change output).  NULL means "use `path`".  With
   * -R + --files-from this holds the entry's bare relative destination path,
   * while `path` stays the absolute local source path the client reads from.
   * Never populated on the receiver. */
  char* send_path;
  Data* data;
  FileMetadata* metadata;
  bool skip;
  /* True when this entry is an explicit directory entry (--dirs mode): the
   * receiver creates the directory instead of writing a regular file. */
  bool is_dir;
  /* Receiver-only (P7 Wave D): this is a STATUS_DIR_TIMES entry.  It carries a
   * traversed source directory's metadata for DEFERRED application, but must
   * NEVER create the directory: the scanner captures every traversed directory
   * (including empty ones whose parents no child write created), so creation
   * would resurrect the empty dirs that FastSync deliberately never transfers.
   * file_save_to_disk_full short-circuits such an entry as FILE_SAVE_SKIPPED,
   * and the sink still accumulates the metadata into its DirTimeList. */
  bool dir_time_only;
  /* Receiver-only, --link-dest: when set, install the destination entry as a
   * hard link to this absolute (root-confined) path instead of writing
   * `data`.  The matching code has already verified the link target's content
   * equals the incoming file, and `data` is kept as the cross-filesystem
   * fallback (a local copy) if the hard link cannot be created. */
  char* basis_link;
  /* Receiver-only, --copy-dest: when set (and basis_link is NULL), stream the
   * basis file's bytes into the destination instead of `data`/`data->size`.
   * This lets a basis larger than any whole-file bound materialize without
   * buffering it; the source metadata on `metadata` is applied afterwards. */
  char* basis_copy;
  /* --hard-links (-H), sender + receiver wire state.  link_group is a run-local
   * id shared by every member of one source inode (0 = not part of a group).
   * The FIRST member (link_first == true) carries its data on the wire and is
   * written normally; every sibling (link_first == false) carries NO data and
   * hardlink_target holds the first member's wire path so the receiver can link
   * to (or copy from) the already-installed first member. */
  int link_group;
  bool link_first;
  char* hardlink_target;
  /* Symlink-type entry (-l/--links, or -k/--copy-dirlinks' keep-as-symlink
   * branch).  When true, `symlink_target` holds the (sender-munged, if
   * --munge-links) target string that is carried on the wire; the receiver
   * creates a symlink to (an unmunged) target instead of writing regular-file
   * data.  `data` is empty for a symlink entry.  Sender + receiver state. */
  bool is_symlink;
  char* symlink_target;
  /* Phase 4 special/devices: when `is_special` is true this entry is a device
   * or special node to be RECREATED on the destination (mknod/mkfifo) rather
   * than written from `data`.  The concrete node kind is derived from the
   * metadata mode's S_IFMT bits (receiver-validated), and rdev_major/minor
   * carry the device major/minor numbers for char/block devices.  CROSSES the
   * wire (protocol 2.13.0). */
  bool is_special;
  int32_t rdev_major;
  int32_t rdev_minor;
  /* Phase-4 xattrs (-X/--xattrs, -A/--acls).  Sender: captured from the source
   * file when use_xattrs is set; transmitted in the per-file metadata frame.
   * Receiver: parsed off the wire, attached here, and applied fd-relative on
   * the written file.  NULL/0 == the file carries no xattrs. */
  FileXattrList* xattrs;
  /* Sender-side output-parity state (never serialized): the receiver-reported
   * pre-transfer destination snapshot for this entry, filled by the per-file
   * STATUS_CHECK exchange when report_dest_info is set.  `known` is false when
   * no report was requested/received, in which case -i/--out-format treats the
   * entry conservatively as newly created. */
  OutputDestState dest_state;
  /* Receiver-only wire-stats tally: the number of bytes reconstructed from the
   * basis file (matched delta blocks) for this entry.  0 when the file was sent
   * whole.  Accumulated into ReceiverStats.matched_data by the receiver sink. */
  unsigned long long matched_bytes;
  /* Receiver-only (protocol 2.28.0) wire-stats tally: the literal delta fragment
   * bytes this entry carried (DELTA_INSTR_LITERAL).  0 when the file was sent
   * whole; the sink then falls back to the whole payload size.  Accumulated
   * into ReceiverStats.literal_bytes. */
  unsigned long long literal_bytes;
} File;

/* The path that should be sent on the wire and used for the receiver-side
 * destination layout (see send_path). */
static inline const char* file_wire_path(const File* file) {
  return file && file->send_path ? file->send_path : (file ? file->path : NULL);
}

#endif
