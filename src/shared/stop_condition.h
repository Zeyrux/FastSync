#ifndef STOP_CONDITION_H
#define STOP_CONDITION_H

#include <stdbool.h>
#include <time.h>

/* Client-only transfer stop conditions (--stop-after=MINS / --stop-at=TIME).
 * Both are local sender-side deadlines: they are never serialized into the
 * config frame and never bump PROTOCOL_VERSION.  A transfer checks the
 * condition at natural chunk/file boundaries and, once reached, stops
 * elegantly (everything already sent is finalized normally, exit 0).
 *
 * A condition combines an optional CLOCK_MONOTONIC instant (the relative
 * --stop-after duration, immune to wall-clock changes) with an optional
 * wall-clock instant (the absolute --stop-at form).  Either one being reached
 * ends the transfer. */
typedef struct StopCondition {
  bool has_monotonic;
  struct timespec monotonic_deadline;
  bool has_wall;
  time_t wall_deadline;
} StopCondition;

/* Parse --stop-after=MINS: a positive integer count of minutes.  Zero,
 * negative, empty and non-numeric values are rejected.  Returns true when
 * accepted and stores the value in *out_minutes. */
bool stop_parse_after_minutes(const char* value, int* out_minutes);

/* Parse --stop-at=TIME.  Accepted forms are HH:MM, HH:MM:SS and
 * now+N[smhd] (seconds/minutes/hours/days from now).  The absolute forms are
 * resolved against `now` (local wall clock) and written to *out_deadline; a
 * time already in the past yields a deadline <= now ("stop immediately").
 * Returns false on any malformed value. */
bool stop_parse_at_time(const char* value, time_t now, time_t* out_deadline);

/* Build the runtime condition at transfer start.  after_minutes is the
 * relative --stop-after duration (<= 0 disables it); at_time is the absolute
 * --stop-at deadline (only consulted when has_at is true); now_mono is the
 * CLOCK_MONOTONIC reading at start. */
StopCondition stop_condition_make(bool has_after, int after_minutes, bool has_at, time_t at_time,
                                  struct timespec now_mono);

/* True once either deadline has passed (wall clock first, then monotonic). */
bool stop_condition_reached(const StopCondition* condition);

#endif
