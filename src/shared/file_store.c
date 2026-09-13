#include <errno.h>
#include <unistd.h>

#include "file_store.h"

static bool write_all(int fd, const void* data, unsigned long long size) {
  const unsigned char* p = data;
  unsigned long long done = 0;
  while (done < size) {
    ssize_t n = write(fd, p + done, (size_t)(size - done));
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return false;
    done += (unsigned long long)n;
  }
  return true;
}

/* A run of NUL bytes at least this long is emitted as a hole (lseek) rather
 * than written, so the resulting file is genuinely sparse on the filesystem. */
#define SPARSE_HOLE_MIN 4096U

/* Sparse-aware writer (--sparse/-S).  Walks `data`; any all-zero run of at
 * least SPARSE_HOLE_MIN bytes is skipped with lseek(SEEK_CUR) so the block is
 * never allocated (a real hole on the destination); every other byte is written
 * normally.  The file is pre-sized with ftruncate by the callers before this
 * runs, so holes are guaranteed and the offset bookkeeping stays correct
 * (each lseek advances the fd offset exactly as a write of that many bytes
 * would).  After the final run, ftruncate(size) guarantees the logical size is
 * exactly `size` even when the tail was a hole.  The full file image is in
 * memory, so no wire change is needed.  Returns false on I/O error. */
bool file_store_write_sparse(int fd, const unsigned char* data, unsigned long long size) {
  unsigned long long i = 0;
  while (i < size) {
    if (data[i] == 0) {
      unsigned long long run_start = i;
      while (i < size && data[i] == 0)
        i++;
      unsigned long long run_len = i - run_start;
      if (run_len >= SPARSE_HOLE_MIN) {
        if (lseek(fd, (off_t)run_len, SEEK_CUR) < 0)
          return false;
      } else if (!write_all(fd, data + run_start, run_len)) {
        return false;
      }
    } else {
      unsigned long long run_start = i;
      while (i < size && data[i] != 0)
        i++;
      if (!write_all(fd, data + run_start, i - run_start))
        return false;
    }
  }
  return ftruncate(fd, (off_t)size) == 0;
}
