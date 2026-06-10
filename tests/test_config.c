#include "test_config.h"
#include "config.h"
#include "multiprocessing.h"
#include "queue.h"
#include "utils.h"
#include "test_utils.h"
#include <stdlib.h>

static void test_config_lifecycle() {
  Config *cfg = config_create(str_dup("1.0"), str_dup("/src"), str_dup("/dst"), true, true, false, false, false, 4);
  EXPECT_NOT_NULL(cfg);
  EXPECT_EQ_STR(cfg->version, "1.0");
  EXPECT_EQ_STR(cfg->send_directory, "/src");
  EXPECT_EQ_STR(cfg->receive_root_directory, "/dst");
  EXPECT_TRUE(cfg->save_to_disk);
  EXPECT_TRUE(cfg->use_multithreading);
  EXPECT_FALSE(cfg->use_chunk_serialization);
  EXPECT_FALSE(cfg->use_compression);
  EXPECT_FALSE(cfg->use_multiprocessing);
  EXPECT_EQ_INT(cfg->num_connections, 4);
  config_delete(cfg);
}

static void test_pipeline_sender_lifecycle() {
  Config *cfg = config_create(str_dup("2.0"), str_dup("/src2"), str_dup("/dst2"), false, false, true, true, true, 8);
  Queue *q1 = queue_create(5, NULL);
  Queue *q2 = queue_create(15, NULL);
  
  PipelineContextSender *pcs = pipeline_context_sender_create(cfg, q1, q2);
  EXPECT_NOT_NULL(pcs);
  EXPECT_EQ_STR(pcs->config->version, "2.0");
  EXPECT_EQ_INT(pcs->queue_scanner->capacity, 5);
  EXPECT_EQ_INT(pcs->queue_loader->capacity, 15);
  EXPECT_FALSE(pcs->scanner_done);
  EXPECT_FALSE(pcs->loader_done);
  
  pipeline_context_sender_destroy(pcs);
}

static void test_pipeline_receiver_lifecycle() {
  Config *cfg = config_create(str_dup("3.0"), str_dup("/src3"), str_dup("/dst3"), true, true, true, true, true, 2);
  Queue *q = queue_create(20, NULL);
  
  PipelineContextReceiver *pcr = pipeline_context_receiver_create(cfg, q, 42);
  EXPECT_NOT_NULL(pcr);
  EXPECT_EQ_STR(pcr->config->version, "3.0");
  EXPECT_EQ_INT(pcr->queue->capacity, 20);
  EXPECT_EQ_INT(pcr->file_descriptor, 42);
  EXPECT_FALSE(pcr->receiver_done);
  
  pipeline_context_receiver_destroy(pcr);
}

void test_config() {
  test_config_lifecycle();
  test_pipeline_sender_lifecycle();
  test_pipeline_receiver_lifecycle();
}
