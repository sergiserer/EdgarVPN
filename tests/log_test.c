/*
 * Unit tests for the logging module: level filtering (including the
 * env-var parsing that drives it), and the actual text/JSON output
 * format, captured by redirecting stdout to a temp file.
 */

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CAPTURE_PATH "/tmp/edgarvpn_log_test_capture.txt"

/* Redirects stdout to CAPTURE_PATH for the duration of `fn`, then
 * restores it and returns the captured content (NUL-terminated) in
 * `out`. Log lines from this module go to stdout below LOG_LEVEL_WARN
 * (see src/log.c), so log_debug/log_info are what this can capture. */
static void capture_stdout(void (*fn)(void), char *out, size_t out_len)
{
    fflush(stdout);
    int saved_fd = dup(fileno(stdout));

    freopen(CAPTURE_PATH, "w", stdout);
    fn();
    fflush(stdout);

    dup2(saved_fd, fileno(stdout));
    close(saved_fd);
    clearerr(stdout);

    out[0] = '\0';
    FILE *in = fopen(CAPTURE_PATH, "r");
    if (in != NULL) {
        size_t n = fread(out, 1, out_len - 1, in);
        out[n] = '\0';
        fclose(in);
    }
    remove(CAPTURE_PATH);
}

static void log_hello_world(void)
{
    log_info("test-component", "hello %s, count=%d", "world", 3);
}

static void log_with_special_chars(void)
{
    log_info("comp\"onent", "message with \"quotes\" and a\\backslash");
}

static int test_default_level_is_info(void)
{
    unsetenv("LOG_LEVEL");
    unsetenv("LOG_FORMAT");
    log_init();

    if (log_level_enabled(LOG_LEVEL_DEBUG)) {
        fprintf(stderr, "test_default_level_is_info: DEBUG unexpectedly enabled\n");
        return 1;
    }
    if (!log_level_enabled(LOG_LEVEL_INFO) || !log_level_enabled(LOG_LEVEL_WARN) ||
        !log_level_enabled(LOG_LEVEL_ERROR)) {
        fprintf(stderr, "test_default_level_is_info: INFO/WARN/ERROR not all enabled\n");
        return 1;
    }

    printf("test_default_level_is_info: passed\n");
    return 0;
}

static int test_log_level_enabled_respects_level(void)
{
    setenv("LOG_LEVEL", "warn", 1);
    log_init();

    if (log_level_enabled(LOG_LEVEL_DEBUG) || log_level_enabled(LOG_LEVEL_INFO)) {
        fprintf(stderr, "test_log_level_enabled_respects_level: DEBUG/INFO not filtered "
                         "out at LOG_LEVEL=warn\n");
        return 1;
    }
    if (!log_level_enabled(LOG_LEVEL_WARN) || !log_level_enabled(LOG_LEVEL_ERROR)) {
        fprintf(stderr, "test_log_level_enabled_respects_level: WARN/ERROR unexpectedly "
                         "filtered out\n");
        return 1;
    }

    unsetenv("LOG_LEVEL");
    printf("test_log_level_enabled_respects_level: passed\n");
    return 0;
}

static int test_invalid_log_level_falls_back_to_info(void)
{
    setenv("LOG_LEVEL", "not-a-real-level", 1);
    log_init();

    if (log_level_enabled(LOG_LEVEL_DEBUG)) {
        fprintf(stderr,
                "test_invalid_log_level_falls_back_to_info: DEBUG unexpectedly enabled\n");
        return 1;
    }
    if (!log_level_enabled(LOG_LEVEL_INFO)) {
        fprintf(stderr,
                "test_invalid_log_level_falls_back_to_info: INFO unexpectedly disabled\n");
        return 1;
    }

    unsetenv("LOG_LEVEL");
    printf("test_invalid_log_level_falls_back_to_info: passed\n");
    return 0;
}

static int test_text_format_output(void)
{
    unsetenv("LOG_LEVEL");
    unsetenv("LOG_FORMAT");
    log_init();

    char captured[512];
    capture_stdout(log_hello_world, captured, sizeof(captured));

    if (strstr(captured, "INFO") == NULL || strstr(captured, "[test-component]") == NULL ||
        strstr(captured, "hello world, count=3") == NULL) {
        fprintf(stderr, "test_text_format_output: unexpected output: %s\n", captured);
        return 1;
    }

    printf("test_text_format_output: passed\n");
    return 0;
}

static int test_json_format_output_and_escaping(void)
{
    setenv("LOG_FORMAT", "json", 1);
    log_init();

    char captured[512];
    capture_stdout(log_with_special_chars, captured, sizeof(captured));

    if (captured[0] != '{' ||
        strstr(captured, "\"level\":\"INFO\"") == NULL ||
        strstr(captured, "\\\"onent") == NULL ||          /* escaped quote in component */
        strstr(captured, "\\\"quotes\\\"") == NULL ||     /* escaped quotes in message */
        strstr(captured, "a\\\\backslash") == NULL) {      /* escaped backslash */
        fprintf(stderr, "test_json_format_output_and_escaping: unexpected output: %s\n",
                captured);
        return 1;
    }

    unsetenv("LOG_FORMAT");
    printf("test_json_format_output_and_escaping: passed\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_default_level_is_info();
    failures += test_log_level_enabled_respects_level();
    failures += test_invalid_log_level_falls_back_to_info();
    failures += test_text_format_output();
    failures += test_json_format_output_and_escaping();
    return failures == 0 ? 0 : 1;
}
