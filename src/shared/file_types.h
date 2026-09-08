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
} File;

/* The path that should be sent on the wire and used for the receiver-side
 * destination layout (see send_path). */
static inline const char* file_wire_path(const File* file) {
  return file && file->send_path ? file->send_path : (file ? file->path : NULL);
}

#endif
