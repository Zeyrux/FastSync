#include "array_list.h"
#include "chunk.h"
#include "config.h"
#include "data.h"
#include "file.h"
#include "log.h"
#include "multiprocessing.h"
#include "protocol.h"
#include "queue.h"
#include "transport_tcp.h"
#include "transport_tls.h"
#include "unistd.h"
#include "utils.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int receive_files(Config *config, int fd) {
  Status status;
  if (!receive_status(fd, &status)) return -1;

  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK) {
    if (status == STATUS_CHECK) {
      bool skipped;
      File *file = receive_incremental_check(fd, config, &skipped);
      if (skipped) goto next;
      if (file == NULL && !skipped) return -1;
      if (config->save_to_disk)
        file_save_to_disk(config->receive_root_directory, file);
      file_destroy(file);
    } else if (status == STATUS_CHUNK) {
      Chunk *chunk = receive_chunk_data(fd, config);
      if (chunk == NULL) {
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      for (int i = 0; i < chunk->element_count; i++) {
        if (config->save_to_disk)
          file_save_to_disk(config->receive_root_directory, chunk->items[i]);
      }
      chunk_destroy(chunk);
    } else {
      File *file = file_receive(config, fd);
      if (file == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      if (config->save_to_disk)
        file_save_to_disk(config->receive_root_directory, file);
      file_destroy(file);
    }
  next:
    if (!receive_status(fd, &status)) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }

  if (status == STATUS_MANIFEST) {
    if (receive_manifest(fd, config, &status) != 0) return -1;
  }
  if (status != STATUS_FINISHED) {
    log_message(LOG_LEVEL_ERROR, "Did not receive FINISHED Status");
    send_status(fd, STATUS_ERROR);
    return -1;
  }
  send_status(fd, STATUS_OK);
  return 0;
}

void handler(int file_descriptor) {
  Config *config = config_receive(file_descriptor);
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    close(file_descriptor);
    return;
  }
  if (config->use_multithreading) {
    Queue *q = queue_create(100, file_destroy);
    if (q == NULL) {
      config_delete(config);
      close(file_descriptor);
      return;
    }
    PipelineContextReceiver *context = pipeline_context_receiver_create(
        config, q, file_descriptor);
    if (context == NULL) {
      queue_destroy(q);
      config_delete(config);
      close(file_descriptor);
      return;
    }
    thrd_t receiver, writer;
    if (thrd_create(&receiver, receive_thread, context) != thrd_success ||
        thrd_create(&writer, write_thread, context) != thrd_success) {
      perror("Error creating Threads");
      pipeline_context_receiver_destroy(context);
      close(file_descriptor);
      return;
    }
    thrd_join(receiver, NULL);
    thrd_join(writer, NULL);
    send_status(file_descriptor, STATUS_OK);
    pipeline_context_receiver_destroy(context);
  } else
    receive_files(config, file_descriptor);
  close(file_descriptor);
}

static Server *g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server) {
    server_delete(&g_server);
  }
  _exit(0);
}

int main(int argc, char *argv[]) {
  bool use_tls = false;
  char *tls_cert = NULL;
  char *tls_key = NULL;
  int port = 8080;

  signal(SIGPIPE, SIG_IGN);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--stdio") == 0) {
      io_set_fds(STDIN_FILENO, STDOUT_FILENO);
      handler(STDIN_FILENO);
      return 0;
    } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
      set_log_level(LOG_LEVEL_DEBUG);
    } else if (strcmp(argv[i], "--tls") == 0) {
      use_tls = true;
    } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      tls_cert = argv[++i];
    } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      tls_key = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      port = atoi(argv[++i]);
    }
  }
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);
  g_server = server_create(port);
  if (g_server == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to create server");
    return 1;
  }
  if (use_tls) {
    if (!tls_cert || !tls_key) {
      fprintf(stderr, "Error: --tls requires --cert and --key\n");
      server_delete(&g_server);
      return 1;
    }
    tls_global_init();
    if (!server_create_tls(g_server, tls_cert, tls_key)) {
      log_message(LOG_LEVEL_ERROR, "Failed to set up TLS");
      server_delete(&g_server);
      return 1;
    }
    server_listen_tls(g_server, handler);
  } else {
    server_listen(g_server, handler);
  }
  return 0;
}
