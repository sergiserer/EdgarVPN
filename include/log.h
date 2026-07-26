#ifndef FORGEVPN_LOG_H
#define FORGEVPN_LOG_H

/*
 * Structured, leveled logging. Replaces the ad hoc printf/fprintf calls
 * used through earlier milestones with a single, filterable, consistently
 * formatted mechanism -- see docs/LOGGING.md.
 *
 * Configured via environment variables, read by log_init():
 *   LOG_LEVEL  = debug | info | warn | error (default: info)
 *   LOG_FORMAT = text | json                 (default: text)
 *
 * Every log_* function is safe to call before log_init() (it falls back
 * to the defaults on first use), but call log_init() once at startup so
 * the configured level/format take effect from the first line.
 */

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
} log_level_t;

/* Reads LOG_LEVEL and LOG_FORMAT from the environment. Call once, before
 * any other log_* call, ideally as the first thing in main(). */
void log_init(void);

/* True if a message at `level` would actually be emitted right now.
 * Exposed so tests can check filtering without capturing output, and so
 * callers can skip building an expensive message for a filtered level. */
int log_level_enabled(log_level_t level);

#if defined(__GNUC__)
#define FORGEVPN_PRINTF_FMT(fmt_idx, args_idx) \
    __attribute__((format(printf, fmt_idx, args_idx)))
#else
#define FORGEVPN_PRINTF_FMT(fmt_idx, args_idx)
#endif

void log_debug(const char *component, const char *fmt, ...) FORGEVPN_PRINTF_FMT(2, 3);
void log_info(const char *component, const char *fmt, ...) FORGEVPN_PRINTF_FMT(2, 3);
void log_warn(const char *component, const char *fmt, ...) FORGEVPN_PRINTF_FMT(2, 3);
void log_error(const char *component, const char *fmt, ...) FORGEVPN_PRINTF_FMT(2, 3);

#endif /* FORGEVPN_LOG_H */
