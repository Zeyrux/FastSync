#include "stop_condition.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Parse a strictly positive decimal integer: only ASCII digits, no leading
 * whitespace, sign or trailing garbage. */
static bool parse_positive_minutes(const char* value, long* out) {
  if (!value || *value == '\0')
    return false;
  if (*value < '0' || *value > '9')
    return false;
  long v = 0;
  for (const char* p = value; *p != '\0'; p++) {
    if (*p < '0' || *p > '9')
      return false;
    int digit = *p - '0';
    if (v > (LONG_MAX - digit) / 10)
      return false;
    v = v * 10 + digit;
  }
  if (v <= 0 || v > INT_MAX)
    return false;
  *out = v;
  return true;
}

bool stop_parse_after_minutes(const char* value, int* out_minutes) {
  if (!out_minutes)
    return false;
  long minutes = 0;
  if (!parse_positive_minutes(value, &minutes))
    return false;
  *out_minutes = (int)minutes;
  return true;
}

/* Two consecutive ASCII digits -> 0..99. */
static bool parse_two_digits(const char* s, int* out) {
  if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9')
    return false;
  *out = (s[0] - '0') * 10 + (s[1] - '0');
  return true;
}

/* True when the current character of the cursor is a decimal digit. */
static bool is_digit(const char* cp) {
  return *cp >= '0' && *cp <= '9';
}

/* rsync 3.4.1's flexible --stop-at date parser (ported from
 * options.c:parse_time).  Returns a time_t, or (time_t)-1 on a malformed value.
 * Accepted forms include Y-M-DTh:m, Y/M/DTh:m, Y-M-D, M-D, D, h:m, :m and
 * "T h:m"; a 1- or 2-digit year and omitted fields are resolved to the next
 * matching point in time in the local timezone.  Seconds are NOT accepted
 * (rsync rejects them too); FastSync keeps its own HH:MM:SS spelling as an
 * extension handled by the caller.  `now` is passed in so tests are
 * deterministic; production passes time(NULL). */
static time_t parse_time_rsync(const char* value, time_t now) {
  const char* cp;
  time_t val;
  struct tm today;
  if (!localtime_r(&now, &today))
    return (time_t)-1;
  struct tm t;
  int in_date, old_mday, n;

  memset(&t, 0, sizeof t);
  t.tm_year = t.tm_mon = t.tm_mday = -1;
  t.tm_hour = t.tm_min = t.tm_isdst = -1;
  cp = value;
  if (*cp == 'T' || *cp == 't' || *cp == ':') {
    in_date = *cp == ':' ? 0 : -1;
    cp++;
  } else
    in_date = 1;
  for (;; cp++) {
    if (!is_digit(cp))
      return (time_t)-1;
    n = 0;
    do {
      n = n * 10 + *cp++ - '0';
    } while (is_digit(cp));
    if (*cp == ':')
      in_date = 0;
    if (in_date > 0) {
      if (t.tm_year != -1)
        return (time_t)-1;
      t.tm_year = t.tm_mon;
      t.tm_mon = t.tm_mday;
      t.tm_mday = n;
      if (!*cp)
        break;
      if (*cp == 'T' || *cp == 't') {
        if (!cp[1])
          break;
        in_date = -1;
      } else if (*cp != '-' && *cp != '/')
        return (time_t)-1;
      continue;
    }
    if (t.tm_hour != -1)
      return (time_t)-1;
    t.tm_hour = t.tm_min;
    t.tm_min = n;
    if (!*cp) {
      if (in_date < 0)
        return (time_t)-1;
      break;
    }
    if (*cp != ':')
      return (time_t)-1;
    in_date = 0;
  }

  in_date = 0;
  if (t.tm_year < 0) {
    t.tm_year = today.tm_year;
    in_date = 1;
  } else if (t.tm_year < 100) {
    while (t.tm_year < today.tm_year)
      t.tm_year += 100;
  } else
    t.tm_year -= 1900;
  if (t.tm_mon < 0) {
    t.tm_mon = today.tm_mon;
    in_date = 2;
  } else
    t.tm_mon--;
  if (t.tm_mday < 0) {
    t.tm_mday = today.tm_mday;
    in_date = 3;
  }

  n = 0;
  if (t.tm_min < 0) {
    t.tm_hour = t.tm_min = 0;
  } else if (t.tm_hour < 0) {
    if (in_date != 3)
      return (time_t)-1;
    in_date = 0;
    t.tm_hour = today.tm_hour;
    n = 60 * 60;
  }

  /* mktime() may roll a too-large tm_mday into the following month; undo that
   * in the "next match" loop below. */
  old_mday = t.tm_mday;
  if (t.tm_hour > 23 || t.tm_min > 59 || t.tm_mon < 0 || t.tm_mon >= 12 || t.tm_mday < 1 ||
      t.tm_mday > 31 || (val = mktime(&t)) == (time_t)-1)
    return (time_t)-1;

  while (in_date && (val <= now || t.tm_mday < old_mday)) {
    switch (in_date) {
    case 3:
      old_mday = ++t.tm_mday;
      break;
    case 2:
      if (t.tm_mday < old_mday)
        t.tm_mday = old_mday; /* the month already got bumped forward */
      else if (++t.tm_mon == 12) {
        t.tm_mon = 0;
        t.tm_year++;
      }
      break;
    case 1:
      if (t.tm_mday < old_mday) {
        /* mon==1 mday==29 got bumped to mon==2 */
        if (t.tm_mon != 2 || old_mday != 29)
          return (time_t)-1;
        t.tm_mon = 1;
        t.tm_mday = 29;
      }
      t.tm_year++;
      break;
    }
    if ((val = mktime(&t)) == (time_t)-1) {
      if (in_date != 3 || t.tm_mday <= 28)
        return (time_t)-1;
      t.tm_mday = old_mday = 1;
      in_date = 2;
    }
  }
  if (n) {
    while (val <= now)
      val += n;
  }
  return val;
}

/* FastSync's HH:MM or HH:MM:SS spelling on the current local day.  rsync's own
 * --stop-at accepts only HH:MM, so this is a strict superset extension. */
static bool parse_clock_time(const char* value, time_t now, time_t* out_deadline) {
  size_t len = strlen(value);
  if (len != 5 && len != 8)
    return false;
  if (value[2] != ':' || (len == 8 && value[5] != ':'))
    return false;
  int hh, mm, ss = 0;
  if (!parse_two_digits(value, &hh) || !parse_two_digits(value + 3, &mm))
    return false;
  if (len == 8 && !parse_two_digits(value + 6, &ss))
    return false;
  if (hh > 23 || mm > 59 || ss > 59)
    return false;

  struct tm today;
  if (!localtime_r(&now, &today))
    return false;
  today.tm_hour = hh;
  today.tm_min = mm;
  today.tm_sec = ss;
  today.tm_isdst = -1;
  time_t deadline = mktime(&today);
  if (deadline == (time_t)-1)
    return false;
  *out_deadline = deadline;
  return true;
}

bool stop_parse_at_time(const char* value, time_t now, time_t* out_deadline) {
  if (!value || !out_deadline)
    return false;

  /* now+N[smhd]: N whole units from the current wall clock. */
  if (strncmp(value, "now+", 4) == 0) {
    const char* p = value + 4;
    /* The count must be a bare non-negative digit run: reject leading
       whitespace ('now+ 5s') and a leading sign ('now++5s'). */
    if (*p < '0' || *p > '9')
      return false;
    errno = 0;
    char* end = NULL;
    long amount = strtol(p, &end, 10);
    if (errno != 0 || end == p || amount < 0)
      return false;
    long unit_seconds;
    switch (*end) {
    case 's':
      unit_seconds = 1;
      break;
    case 'm':
      unit_seconds = 60;
      break;
    case 'h':
      unit_seconds = 3600;
      break;
    case 'd':
      unit_seconds = 86400;
      break;
    default:
      return false;
    }
    if (end[1] != '\0')
      return false;
    if (amount > LONG_MAX / unit_seconds)
      return false;
    long long delta = (long long)amount * unit_seconds;
    /* Guard against signed overflow of now + delta. */
    if ((long long)now > 0 && delta > (long long)LLONG_MAX - (long long)now)
      return false;
    if ((long long)now < 0 && delta < (long long)LLONG_MIN - (long long)now)
      return false;
    *out_deadline = now + (time_t)delta;
    return true;
  }

  /* HH:MM or HH:MM:SS on the current local day (FastSync extension). */
  if (parse_clock_time(value, now, out_deadline))
    return true;

  /* rsync's full/partial date-and-time form (e.g. 2000-12-31T23:59, 12-31,
   * 14:00, :59, 1, 1-30). */
  time_t deadline = parse_time_rsync(value, now);
  if (deadline == (time_t)-1)
    return false;
  *out_deadline = deadline;
  return true;
}

StopCondition stop_condition_make(bool has_after, int after_minutes, bool has_at, time_t at_time,
                                  struct timespec now_mono) {
  StopCondition condition;
  condition.has_monotonic = false;
  condition.monotonic_deadline.tv_sec = 0;
  condition.monotonic_deadline.tv_nsec = 0;
  condition.has_wall = false;
  condition.wall_deadline = 0;
  if (has_after && after_minutes > 0) {
    condition.has_monotonic = true;
    condition.monotonic_deadline.tv_sec = now_mono.tv_sec + (time_t)after_minutes * 60;
    condition.monotonic_deadline.tv_nsec = now_mono.tv_nsec;
  }
  if (has_at) {
    condition.has_wall = true;
    condition.wall_deadline = at_time;
  }
  return condition;
}

bool stop_condition_reached(const StopCondition* condition) {
  if (!condition)
    return false;
  if (condition->has_wall && time(NULL) >= condition->wall_deadline)
    return true;
  if (condition->has_monotonic) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
      return false;
    if (now.tv_sec > condition->monotonic_deadline.tv_sec ||
        (now.tv_sec == condition->monotonic_deadline.tv_sec &&
         now.tv_nsec >= condition->monotonic_deadline.tv_nsec))
      return true;
  }
  return false;
}