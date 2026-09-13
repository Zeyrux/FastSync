#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Detect if running under valgrind by checking /proc/self/maps for vgpreload.
// This is used to skip fork-based tests that are incompatible with valgrind
// (the instrumented parent runs too slowly, causing pipe timeouts).
static inline bool is_running_under_valgrind(void) {
  FILE* f = fopen("/proc/self/maps", "r");
  if (!f)
    return false;
  char buf[4096];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';
  return strstr(buf, "vgpreload") != NULL;
}

// Global test suite status
extern int tests_run;
extern int tests_failed;
extern bool current_test_failed;

// Helper to run a test function
#define RUN_TEST(test_func)                                                                        \
  do {                                                                                             \
    printf("Running %s...\n", #test_func);                                                         \
    tests_run++;                                                                                   \
    current_test_failed = false;                                                                   \
    test_func();                                                                                   \
    if (current_test_failed) {                                                                     \
      tests_failed++;                                                                              \
      printf("  \033[1;31m[FAILED]\033[0m %s\n", #test_func);                                      \
    } else {                                                                                       \
      printf("  \033[1;32m[PASSED]\033[0m %s\n", #test_func);                                      \
    }                                                                                              \
  } while (0)

// Assertion macros
#define EXPECT_TRUE(condition)                                                                     \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Assertion failed: %s is false\n", __FILE__,       \
             __LINE__, #condition);                                                                \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define EXPECT_FALSE(condition)                                                                    \
  do {                                                                                             \
    if (condition) {                                                                               \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Assertion failed: %s is true\n", __FILE__,        \
             __LINE__, #condition);                                                                \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define EXPECT_EQ_INT(actual, expected)                                                            \
  do {                                                                                             \
    int act = (actual);                                                                            \
    int exp = (expected);                                                                          \
    if (act != exp) {                                                                              \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Expected %d, got %d\n", __FILE__, __LINE__, exp,  \
             act);                                                                                 \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define EXPECT_EQ_STR(actual, expected)                                                            \
  do {                                                                                             \
    const char* act = (actual);                                                                    \
    const char* exp = (expected);                                                                  \
    if (act == NULL || exp == NULL) {                                                              \
      if (act != exp) {                                                                            \
        printf("    \033[1;31m[FAIL]\033[0m %s:%d: Expected %s, got %s\n", __FILE__, __LINE__,     \
               exp ? exp : "NULL", act ? act : "NULL");                                            \
        current_test_failed = true;                                                                \
        return;                                                                                    \
      }                                                                                            \
    } else if (strcmp(act, exp) != 0) {                                                            \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Expected \"%s\", got \"%s\"\n", __FILE__,         \
             __LINE__, exp, act);                                                                  \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define EXPECT_NOT_NULL(ptr)                                                                       \
  do {                                                                                             \
    if ((ptr) == NULL) {                                                                           \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Expected non-null pointer, got NULL\n", __FILE__, \
             __LINE__);                                                                            \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

#define EXPECT_NULL(ptr)                                                                           \
  do {                                                                                             \
    if ((ptr) != NULL) {                                                                           \
      printf("    \033[1;31m[FAIL]\033[0m %s:%d: Expected NULL, got %p\n", __FILE__, __LINE__,     \
             (void*)(ptr));                                                                        \
      current_test_failed = true;                                                                  \
      return;                                                                                      \
    }                                                                                              \
  } while (0)

/* Unconditional test failure carrying an explanatory message. */
#define EXPECT_FAIL(message)                                                                       \
  do {                                                                                             \
    printf("    \033[1;31m[FAIL]\033[0m %s:%d: %s\n", __FILE__, __LINE__, (message));              \
    current_test_failed = true;                                                                    \
    return;                                                                                        \
  } while (0)

#endif
