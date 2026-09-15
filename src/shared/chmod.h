#ifndef CHMOD_H
#define CHMOD_H

#include <stdbool.h>
#include <sys/stat.h>

/* Apply rsync's --chmod syntax to a permission mode, including the D/F/X
 * selectors and the s/t special bits.  `mode` should carry the file type bits
 * (S_IFDIR/S_IFREG) so D/F/X can be evaluated; the type bits are preserved in
 * `result`.  A spec may contain comma-separated clauses, which accumulate. */
bool chmod_apply(mode_t mode, const char* spec, mode_t* result);

#endif
