#ifndef FILE_TYPES_H
#define FILE_TYPES_H

#include "data.h"
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
  /* Receiver-only, --link-dest: when set, install the destination entry as a
   * hard link to this absolute (root-confined) path instead of writing
   * `data`.  The matching code has already verified the link target's content
   * equals the incoming file, and `data` is kept as the cross-filesystem
   * fallback (a local copy) if the hard link cannot be created. */
  char* basis_link;
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
} File;

/* The path that should be sent on the wire and used for the receiver-side
 * destination layout (see send_path). */
static inline const char* file_wire_path(const File* file) {
  return file && file->send_path ? file->send_path : (file ? file->path : NULL);
}

#endif
