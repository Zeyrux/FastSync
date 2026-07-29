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

int receive_files(Config* config, int fd) {
  Status status;
  if (!receive_status(fd, &status))
    return -1;

  while (status == STATUS_NEXT || status == STATUS_CHUNK || status == STATUS_CHECK ||
         status == STATUS_KEEPALIVE || status == STATUS_ABORT || status == STATUS_CHECK_BATCH) {
    if (status == STATUS_KEEPALIVE) {
      send_status(fd, STATUS_KEEPALIVE);
      goto next;
    }
    if (status == STATUS_ABORT) {
      log_message(LOG_LEVEL_INFO, "Received abort from client, cleaning up");
      return -1;
    }
    if (status == STATUS_CHECK) {
      bool skipped;
      File* file = receive_incremental_check(fd, config, &skipped);
      if (skipped)
        goto next;
      if (file == NULL && !skipped)
        return -1;
      if (config->save_to_disk)
        file_save_to_disk(config->receive_root_directory, file, NULL);
      file_destroy(file);
    } else if (status == STATUS_CHUNK) {
      Chunk* chunk = receive_chunk_data(fd, config);
      if (chunk == NULL) {
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      for (int i = 0; i < chunk->element_count; i++) {
        if (config->save_to_disk)
          file_save_to_disk(config->receive_root_directory, chunk->items[i], NULL);
      }
      chunk_destroy(chunk);
    } else if (status == STATUS_CHECK_BATCH) {
      int count;
      if (!receive_int(fd, &count))
        return -1;
      for (int i = 0; i < count; i++) {
        char* check_path = receive_str(fd);
        if (!check_path)
          return -1;
        unsigned long long check_size;
        long long check_mtime;
        if (!receive_n_data(fd, &check_size, sizeof(check_size)) ||
            !receive_n_data(fd, &check_mtime, sizeof(check_mtime))) {
          free(check_path);
          return -1;
        }
        char* full_path = path_cat(config->receive_root_directory, check_path);
        struct stat st;
        bool has_old = full_path && lstat(full_path, &st) == 0;
        bool match = has_old && (unsigned long long)st.st_size == check_size &&
                     (long long)st.st_mtime == check_mtime;
        if (match)
          send_status(fd, STATUS_OK);
        else
          send_status(fd, STATUS_NEXT);
        free(full_path);
        free(check_path);
      }
      goto next;
    } else {
      File* file = file_receive(config, fd);
      if (file == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to receive file");
        send_status(fd, STATUS_ERROR);
        return -1;
      }
      if (config->save_to_disk)
        file_save_to_disk(config->receive_root_directory, file, NULL);
      file_destroy(file);
    }
  next:
    if (!receive_status(fd, &status)) {
      send_status(fd, STATUS_ERROR);
      return -1;
    }
  }

  if (status == STATUS_MANIFEST) {
    if (receive_manifest(fd, config, &status) != 0)
      return -1;
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
  SSL* ssl = io_get_ssl();
  Config* config = config_receive(file_descriptor);
  if (config == NULL) {
    log_message(LOG_LEVEL_ERROR, "Failed to receive config");
    close(file_descriptor);
    return;
  }
  if (config->use_multithreading) {
    Queue* q = queue_create(100, file_destroy);
    if (q == NULL) {
      config_delete(config);
      close(file_descriptor);
      return;
    }
    PipelineContextReceiver* context =
        pipeline_context_receiver_create(config, q, file_descriptor, ssl);
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
  } else {
    receive_files(config, file_descriptor);
    config_delete(config);
  }
  close(file_descriptor);
}

#ifndef FASTSYNC_SERVER_AS_LIB
static Server* g_server = NULL;

static void cleanup(int sig) {
  (void)sig;
  if (g_server) {
    server_delete(&g_server);
  }
  _exit(0);
}

static void print_server_usage(void) {
  printf("FastSync Server\n");
  printf("Usage: fastsync-server [options]\n");
  printf("\n");
  printf("Options:\n");
  printf("  --stdio             Run in stdio mode (SSH transport)\n");
  printf("  -p <port>           TCP port (default: 8080, range: 1-65535)\n");
  printf("  --tls               Enable TLS encryption\n");
  printf("  --cert <path>       TLS certificate file (PEM)\n");
  printf("  --key <path>        TLS private key file (PEM)\n");
  printf("  --ca <path>         TLS CA certificate file (PEM)\n");
  printf("  -v, --verbose       Enable debug logging\n");
  printf("  --help              Show this help\n");
}

int main(int argc, char* argv[]) {
  bool use_tls = false;
  char* tls_cert = NULL;
  char* tls_key = NULL;
  char* tls_ca = NULL;
  int port = 8080;

  signal(SIGPIPE, SIG_IGN);
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      print_server_usage();
      return 0;
    } else if (strcmp(argv[i], "--stdio") == 0) {
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
    } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
      tls_ca = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      char* end;
      long p = strtol(argv[++i], &end, 10);
      if (*end || p <= 0 || p > 65535) {
        fprintf(stderr, "Error: invalid port '%s' (must be 1-65535)\n", argv[i]);
        return 1;
      }
      port = (int)p;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_server_usage();
      return 1;
    }
  }

  if (tls_ca && !use_tls) {
    log_message(LOG_LEVEL_WARNING, "--ca has no effect without --tls");
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
    if (!server_create_tls(g_server, tls_cert, tls_key, tls_ca)) {
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
#endif /* !FASTSYNC_SERVER_AS_LIB */
