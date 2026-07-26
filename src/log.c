#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef enum {
    LOG_FORMAT_TEXT,
    LOG_FORMAT_JSON,
} log_format_t;

static log_level_t g_level = LOG_LEVEL_INFO;
static log_format_t g_format = LOG_FORMAT_TEXT;
static int g_initialized = 0;

void log_init(void)
{
    g_level = LOG_LEVEL_INFO;
    g_format = LOG_FORMAT_TEXT;

    const char *level_env = getenv("LOG_LEVEL");
    if (level_env != NULL) {
        if (strcasecmp(level_env, "debug") == 0) {
            g_level = LOG_LEVEL_DEBUG;
        } else if (strcasecmp(level_env, "info") == 0) {
            g_level = LOG_LEVEL_INFO;
        } else if (strcasecmp(level_env, "warn") == 0) {
            g_level = LOG_LEVEL_WARN;
        } else if (strcasecmp(level_env, "error") == 0) {
            g_level = LOG_LEVEL_ERROR;
        }
        /* Anything else is left at the default (info) rather than
         * rejected -- a typo in LOG_LEVEL shouldn't stop the daemon. */
    }

    const char *format_env = getenv("LOG_FORMAT");
    if (format_env != NULL && strcasecmp(format_env, "json") == 0) {
        g_format = LOG_FORMAT_JSON;
    }

    g_initialized = 1;
}

static void ensure_initialized(void)
{
    if (!g_initialized) {
        log_init();
    }
}

int log_level_enabled(log_level_t level)
{
    ensure_initialized();
    return level >= g_level;
}

static const char *level_name(log_level_t level)
{
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
    }
    return "?";
}

static void format_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_utc;
    gmtime_r(&ts.tv_sec, &tm_utc);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/* Writes `text` to `out`, JSON-escaping '"', '\', and control characters. */
static void write_json_escaped(FILE *out, const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (*p < 0x20) {
                    fprintf(out, "\\u%04x", *p);
                } else {
                    fputc(*p, out);
                }
        }
    }
}

static void emit(log_level_t level, const char *component, const char *message)
{
    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));
    FILE *out = (level >= LOG_LEVEL_WARN) ? stderr : stdout;

    if (g_format == LOG_FORMAT_JSON) {
        fprintf(out, "{\"time\":\"%s\",\"level\":\"%s\",\"component\":\"",
                timestamp, level_name(level));
        write_json_escaped(out, component);
        fputs("\",\"message\":\"", out);
        write_json_escaped(out, message);
        fputs("\"}\n", out);
    } else {
        fprintf(out, "%s %-5s [%s] %s\n", timestamp, level_name(level), component, message);
    }
    fflush(out);
}

static void log_at(log_level_t level, const char *component, const char *fmt, va_list args)
{
    if (!log_level_enabled(level)) {
        return;
    }

    char message[1024];
    vsnprintf(message, sizeof(message), fmt, args);
    emit(level, component, message);
}

void log_debug(const char *component, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_at(LOG_LEVEL_DEBUG, component, fmt, args);
    va_end(args);
}

void log_info(const char *component, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_at(LOG_LEVEL_INFO, component, fmt, args);
    va_end(args);
}

void log_warn(const char *component, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_at(LOG_LEVEL_WARN, component, fmt, args);
    va_end(args);
}

void log_error(const char *component, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_at(LOG_LEVEL_ERROR, component, fmt, args);
    va_end(args);
}
