#ifndef RECEIVER_H
#define RECEIVER_H

#include "config.h"
#include "file.h"
#include "file_receive.h"

typedef bool (*ReceiverFileSink)(File* file, void* context);

/* Ordered per-file save outcomes for one connection.  One entry is appended
   for every data-bearing file the receiver processes (in the order the files
   were sent) so the sender of a --remove-source-files transfer can be told
   which sources were actually written versus skipped on the receiver. */
typedef struct {
  unsigned char* entries; /* FILE_SAVE_WRITTEN or FILE_SAVE_SKIPPED */
  size_t count;
  size_t capacity;
} ReceiverOutcomes;

typedef bool (*ReceiverSuccessFrame)(int fd, void* context);

typedef struct {
  ReceiverFileSink store_file;
  void* context;
  bool send_error;
  bool send_success;
  /* Emits the end-of-transfer success frame.  When the sender requested
     --remove-source-files this includes one per-file status per processed
     data file followed by the final STATUS_OK; otherwise just STATUS_OK. */
  ReceiverSuccessFrame send_success_frame;
} ReceiverSink;

bool receiver_outcomes_append(ReceiverOutcomes* outcomes, unsigned char code);
void receiver_outcomes_destroy(ReceiverOutcomes* outcomes);
bool receiver_send_final_success(int fd, const Config* config, const ReceiverOutcomes* outcomes);

int receiver_process(Config* config, int file_descriptor, const ReceiverSink* sink);
/* receiver_process with an escape hatch for the commit-style (late) deletion:
   when `pending_manifest` is non-NULL the receiver does NOT delete at
   STATUS_FINISHED itself; instead it stores the owned keep-set manifest there
   (leaving *pending_manifest untouched on early modes/errors) so the caller can
   commit the deletion only after its disk writer has fully drained.  Pass NULL
   to keep the default behaviour (delete before the success frame). */
int receiver_process_pending(Config* config, int file_descriptor, const ReceiverSink* sink,
                             ArrayList** pending_manifest);
int receiver_receive_files(Config* config, int file_descriptor);

#endif
