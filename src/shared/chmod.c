#include "chmod.h"
#include "file.h"
#include <stddef.h>
#include <string.h>

/* rsync's --chmod parser (parse_chmod + tweak_mode).  A single clause is
 * applied as it is completed, so repeated clauses and repeated --chmod options
 * (joined with commas by the CLI) accumulate exactly like rsync.  The D/F
 * selectors restrict a clause to directories/files; X adds execute only to
 * directories or files that were already executable. */

#define CHMOD_BITS 07777
#define CHMOD_FLAG_X_KEEP (1U << 0)
#define CHMOD_FLAG_DIRS_ONLY (1U << 1)
#define CHMOD_FLAG_FILES_ONLY (1U << 2)

enum chmod_op { CHMOD_OP_ADD = 1, CHMOD_OP_SUB, CHMOD_OP_EQ, CHMOD_OP_SET };
enum chmod_state {
  CHMOD_STATE_ERROR,
  CHMOD_STATE_1ST_HALF,
  CHMOD_STATE_2ND_HALF,
  CHMOD_STATE_OCTAL
};

bool chmod_apply(mode_t mode, const char* spec, mode_t* result) {
  if (!spec || !*spec || !result)
    return false;
  const mode_t nonperm = mode & ~(mode_t)CHMOD_BITS;
  const bool initially_executable = (mode & 0111) != 0;
  mode_t changed = mode;
  int state = CHMOD_STATE_1ST_HALF;
  unsigned where = 0;
  int what = 0, op = 0, topbits = 0, topoct = 0, flags = 0;
  const char* p = spec;
  while (state != CHMOD_STATE_ERROR) {
    if (*p == '\0' || *p == ',') {
      int bits;
      if (!op) {
        state = CHMOD_STATE_ERROR;
        break;
      }
      if (where)
        bits = (int)(where * (unsigned)what);
      else {
        where = 0111;
        bits = (int)((where * (unsigned)what) & ~(unsigned)file_process_umask());
      }
      int mode_and, mode_or;
      switch (op) {
      case CHMOD_OP_ADD:
        mode_and = CHMOD_BITS;
        mode_or = bits + topoct;
        break;
      case CHMOD_OP_SUB:
        mode_and = CHMOD_BITS - bits - topoct;
        mode_or = 0;
        break;
      case CHMOD_OP_EQ:
        mode_and = CHMOD_BITS - (int)(where * 7U) - (topoct ? topbits : 0);
        mode_or = bits + topoct;
        break;
      default:
        mode_and = 0;
        mode_or = bits;
        break;
      }
      bool is_dir = S_ISDIR(nonperm);
      if (!((flags & CHMOD_FLAG_DIRS_ONLY) && !is_dir) &&
          !((flags & CHMOD_FLAG_FILES_ONLY) && is_dir)) {
        changed &= (mode_t)mode_and;
        if ((flags & CHMOD_FLAG_X_KEEP) && !initially_executable && !is_dir)
          changed |= (mode_t)(mode_or & ~0111);
        else
          changed |= (mode_t)mode_or;
      }
      if (*p == '\0')
        break;
      p++;
      state = CHMOD_STATE_1ST_HALF;
      where = 0;
      what = op = topoct = topbits = flags = 0;
      continue;
    }
    switch (state) {
    case CHMOD_STATE_1ST_HALF:
      switch (*p) {
      case 'D':
        if (flags & CHMOD_FLAG_FILES_ONLY) {
          state = CHMOD_STATE_ERROR;
          break;
        }
        flags |= CHMOD_FLAG_DIRS_ONLY;
        break;
      case 'F':
        if (flags & CHMOD_FLAG_DIRS_ONLY) {
          state = CHMOD_STATE_ERROR;
          break;
        }
        flags |= CHMOD_FLAG_FILES_ONLY;
        break;
      case 'u':
        where |= 0100;
        topbits |= 04000;
        break;
      case 'g':
        where |= 0010;
        topbits |= 02000;
        break;
      case 'o':
        where |= 0001;
        break;
      case 'a':
        where |= 0111;
        break;
      case '+':
        op = CHMOD_OP_ADD;
        state = CHMOD_STATE_2ND_HALF;
        break;
      case '-':
        op = CHMOD_OP_SUB;
        state = CHMOD_STATE_2ND_HALF;
        break;
      case '=':
        op = CHMOD_OP_EQ;
        state = CHMOD_STATE_2ND_HALF;
        break;
      default:
        if (*p >= '0' && *p <= '7' && !where) {
          op = CHMOD_OP_SET;
          state = CHMOD_STATE_OCTAL;
          where = 1;
          what = *p - '0';
        } else {
          state = CHMOD_STATE_ERROR;
        }
        break;
      }
      break;
    case CHMOD_STATE_2ND_HALF:
      switch (*p) {
      case 'r':
        what |= 4;
        break;
      case 'w':
        what |= 2;
        break;
      case 'X':
        flags |= CHMOD_FLAG_X_KEEP;
        /* fall through */
      case 'x':
        what |= 1;
        break;
      case 's':
        if (topbits)
          topoct |= topbits;
        else
          topoct = 04000;
        break;
      case 't':
        topoct |= 01000;
        break;
      default:
        state = CHMOD_STATE_ERROR;
        break;
      }
      break;
    default:
      if (*p >= '0' && *p <= '7') {
        what = what * 8 + (*p - '0');
        if (what > CHMOD_BITS)
          state = CHMOD_STATE_ERROR;
      } else {
        state = CHMOD_STATE_ERROR;
      }
      break;
    }
    p++;
  }
  if (state == CHMOD_STATE_ERROR)
    return false;
  *result = (changed & (mode_t)CHMOD_BITS) | nonperm;
  return true;
}
