#ifndef RECEIVER_H
#define RECEIVER_H

#include "config.h"
#include "file.h"

typedef bool (*ReceiverFileSink)(File* file, void* context);

typedef struct {
  ReceiverFileSink store_file;
  void* context;
  bool send_error;
  bool send_success;
} ReceiverSink;

int receiver_process(Config* config, int file_descriptor, const ReceiverSink* sink);
int receiver_receive_files(Config* config, int file_descriptor);

#endif
