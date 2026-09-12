#include "hardlink.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "utils.h"

/* ---- Sender-side detection table ---- */

HardLinkTable* hardlink_table_create(void) {
  HardLinkTable* table = calloc(1, sizeof(HardLinkTable));
  if (!table)
    return NULL;
  if (mtx_init(&table->mutex, mtx_plain) != thrd_success) {
    free(table);
    return NULL;
  }
  table->next_gid = 1;
  return table;
}

static void hardlink_item_destroy(HardLinkItem* item) {
  if (!item)
    return;
  free(item->first_path);
  item->first_path = NULL;
}

void hardlink_table_destroy(HardLinkTable* table) {
  if (!table)
    return;
  for (size_t i = 0; i < table->count; i++)
    hardlink_item_destroy(&table->items[i]);
  free(table->items);
  table->items = NULL;
  table->count = 0;
  table->capacity = 0;
  mtx_destroy(&table->mutex);
  free(table);
}

static HardLinkItem* hardlink_table_find_locked(HardLinkTable* table, dev_t dev, ino_t ino) {
  for (size_t i = 0; i < table->count; i++) {
    if (table->items[i].dev == dev && table->items[i].ino == ino)
      return &table->items[i];
  }
  return NULL;
}

static bool hardlink_table_add_locked(HardLinkTable* table, dev_t dev, ino_t ino, const char* path,
                                      int gid, HardLinkItem** out) {
  if (table->count == table->capacity) {
    size_t new_capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    if (new_capacity < table->capacity)
      return false;
    HardLinkItem* grown = realloc(table->items, new_capacity * sizeof(HardLinkItem));
    if (!grown)
      return false;
    table->items = grown;
    table->capacity = new_capacity;
  }
  HardLinkItem* item = &table->items[table->count];
  char* dup = str_dup(path);
  if (!dup)
    return false;
  memset(item, 0, sizeof(*item));
  item->dev = dev;
  item->ino = ino;
  item->gid = gid;
  item->first_path = dup;
  table->count++;
  *out = item;
  return true;
}

bool hardlink_table_assign(HardLinkTable* table, const char* wire_path, dev_t dev, ino_t ino,
                           int* gid, bool* is_first, char** first_path_out) {
  if (!table || !wire_path || !gid || !is_first || !first_path_out)
    return false;
  if (mtx_lock(&table->mutex) != thrd_success)
    return false;
  bool ok = true;
  const HardLinkItem* item = hardlink_table_find_locked(table, dev, ino);
  int next_gid;
  if (item) {
    *is_first = false;
    char* dup = str_dup(item->first_path);
    if (!dup) {
      ok = false;
    } else {
      *gid = item->gid;
      *first_path_out = dup;
    }
    next_gid = -1;
  } else {
    if (table->next_gid <= 0) {
      ok = false;
      next_gid = -1;
    } else {
      next_gid = table->next_gid;
      HardLinkItem* created = NULL;
      if (!hardlink_table_add_locked(table, dev, ino, wire_path, next_gid, &created)) {
        ok = false;
      } else {
        char* dup = str_dup(wire_path);
        if (!dup) {
          hardlink_item_destroy(created);
          table->count--;
          ok = false;
        } else {
          *is_first = true;
          *gid = next_gid;
          *first_path_out = dup;
        }
      }
    }
  }
  if (ok && next_gid > 0)
    table->next_gid++;
  mtx_unlock(&table->mutex);
  if (!ok) {
    log_message(LOG_LEVEL_ERROR, "memory allocation failed while detecting hard links");
  }
  return ok;
}
