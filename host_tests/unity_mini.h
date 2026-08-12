/* Tiny header-only assertion helper for host_tests/. Deliberately not
 * ESP-IDF's Unity harness -- the whole point of host_tests/ is to build
 * and run with a plain host compiler, no ESP-IDF toolchain required. */
#ifndef WESPE_UNITY_MINI_H
#define WESPE_UNITY_MINI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_um_failures = 0;
static int g_um_checks = 0;
static const char *g_um_current_test = "";

#define UM_TEST(name) static void name(void)
#define UM_RUN(name)                                                         \
    do {                                                                     \
        g_um_current_test = #name;                                          \
        name();                                                              \
    } while (0)

#define UM_CHECK(cond)                                                       \
    do {                                                                     \
        g_um_checks++;                                                       \
        if (!(cond)) {                                                       \
            g_um_failures++;                                                 \
            fprintf(stderr, "FAIL %s:%d [%s] condition failed: %s\n",       \
                    __FILE__, __LINE__, g_um_current_test, #cond);          \
        }                                                                    \
    } while (0)

#define UM_CHECK_EQ_INT(a, b)                                                \
    do {                                                                     \
        long long va = (long long)(a);                                      \
        long long vb = (long long)(b);                                      \
        g_um_checks++;                                                       \
        if (va != vb) {                                                      \
            g_um_failures++;                                                 \
            fprintf(stderr, "FAIL %s:%d [%s] %s (%lld) != %s (%lld)\n",     \
                    __FILE__, __LINE__, g_um_current_test, #a, va, #b, vb); \
        }                                                                    \
    } while (0)

#define UM_CHECK_EQ_MEM(a, b, len)                                           \
    do {                                                                     \
        g_um_checks++;                                                       \
        if (memcmp((a), (b), (len)) != 0) {                                  \
            g_um_failures++;                                                 \
            fprintf(stderr, "FAIL %s:%d [%s] memory mismatch: %s != %s\n",  \
                    __FILE__, __LINE__, g_um_current_test, #a, #b);         \
        }                                                                    \
    } while (0)

static int um_summary(void)
{
    fprintf(stderr, "%d checks, %d failures\n", g_um_checks, g_um_failures);
    return g_um_failures == 0 ? 0 : 1;
}

#endif /* WESPE_UNITY_MINI_H */
