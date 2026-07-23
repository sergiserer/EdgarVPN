#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define CONFIG_DEFAULT_PORT 51820
#define CONFIG_DEFAULT_DEVICE "forge0"
#define CONFIG_MAX_LINE 512

typedef enum {
    SECTION_NONE,
    SECTION_INTERFACE,
    SECTION_PEER,
} section_t;

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

/* Parses "a.b.c.d/prefix" into a dotted address and a dotted netmask. */
static int parse_cidr(const char *cidr, char *addr_out, size_t addr_len,
                       char *mask_out, size_t mask_len)
{
    char buf[CONFIG_MAX_LINE];
    if (strlen(cidr) >= sizeof(buf)) {
        return -1;
    }
    strcpy(buf, cidr);

    char *slash = strchr(buf, '/');
    if (slash == NULL) {
        return -1;
    }
    *slash = '\0';
    const char *prefix_str = slash + 1;

    char *end = NULL;
    long prefix = strtol(prefix_str, &end, 10);
    if (end == prefix_str || *end != '\0' || prefix < 0 || prefix > 32) {
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return -1;
    }
    if (strlen(buf) >= addr_len) {
        return -1;
    }
    strcpy(addr_out, buf);

    uint32_t mask_bits = (prefix == 0) ? 0 : (uint32_t)(~0U << (32 - prefix));
    struct in_addr mask;
    mask.s_addr = htonl(mask_bits);
    if (inet_ntop(AF_INET, &mask, mask_out, mask_len) == NULL) {
        return -1;
    }
    return 0;
}

/* Parses "host:port". */
static int parse_endpoint_value(const char *value, char *host_out, size_t host_len,
                                 unsigned short *port_out)
{
    char buf[CONFIG_MAX_HOST];
    if (strlen(value) >= sizeof(buf)) {
        return -1;
    }
    strcpy(buf, value);

    char *sep = strrchr(buf, ':');
    if (sep == NULL || sep == buf) {
        return -1;
    }
    *sep = '\0';

    char *end = NULL;
    long port = strtol(sep + 1, &end, 10);
    if (end == sep + 1 || *end != '\0' || port <= 0 || port > 65535) {
        return -1;
    }
    if (strlen(buf) >= host_len) {
        return -1;
    }

    strcpy(host_out, buf);
    *port_out = (unsigned short)port;
    return 0;
}

int config_load(const char *path, forgevpn_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strcpy(cfg->name, "unnamed-peer");
    cfg->listen_port = CONFIG_DEFAULT_PORT;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "config: failed to open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    section_t section = SECTION_NONE;
    int have_address = 0;
    char line[CONFIG_MAX_LINE];
    int lineno = 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        char *trimmed = trim(line);

        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        if (trimmed[0] == '[') {
            char *close = strchr(trimmed, ']');
            if (close == NULL) {
                fprintf(stderr, "config: %s:%d: unterminated section header\n", path, lineno);
                fclose(f);
                return -1;
            }
            *close = '\0';
            const char *section_name = trimmed + 1;

            if (strcasecmp(section_name, "Interface") == 0) {
                section = SECTION_INTERFACE;
            } else if (strcasecmp(section_name, "Peer") == 0) {
                if (cfg->has_peer) {
                    fprintf(stderr,
                            "config: %s:%d: only one [Peer] section is supported currently\n",
                            path, lineno);
                    fclose(f);
                    return -1;
                }
                section = SECTION_PEER;
                cfg->has_peer = 1;
            } else {
                fprintf(stderr, "config: %s:%d: unknown section '%s'\n",
                        path, lineno, section_name);
                fclose(f);
                return -1;
            }
            continue;
        }

        char *eq = strchr(trimmed, '=');
        if (eq == NULL) {
            fprintf(stderr, "config: %s:%d: expected 'key = value'\n", path, lineno);
            fclose(f);
            return -1;
        }
        *eq = '\0';
        char *key = trim(trimmed);
        char *value = trim(eq + 1);

        if (section == SECTION_INTERFACE) {
            if (strcasecmp(key, "Name") == 0) {
                if (strlen(value) >= sizeof(cfg->name)) {
                    fprintf(stderr, "config: %s:%d: Name is too long\n", path, lineno);
                    fclose(f);
                    return -1;
                }
                strcpy(cfg->name, value);
            } else if (strcasecmp(key, "DeviceName") == 0) {
                if (strlen(value) >= sizeof(cfg->tun_name)) {
                    fprintf(stderr, "config: %s:%d: DeviceName is too long\n", path, lineno);
                    fclose(f);
                    return -1;
                }
                strcpy(cfg->tun_name, value);
            } else if (strcasecmp(key, "Address") == 0) {
                if (parse_cidr(value, cfg->tun_address, sizeof(cfg->tun_address),
                                cfg->tun_netmask, sizeof(cfg->tun_netmask)) != 0) {
                    fprintf(stderr,
                            "config: %s:%d: invalid Address '%s' (expected a.b.c.d/prefix)\n",
                            path, lineno, value);
                    fclose(f);
                    return -1;
                }
                have_address = 1;
            } else if (strcasecmp(key, "ListenPort") == 0) {
                char *end = NULL;
                long port = strtol(value, &end, 10);
                if (end == value || *end != '\0' || port <= 0 || port > 65535) {
                    fprintf(stderr, "config: %s:%d: invalid ListenPort '%s'\n",
                            path, lineno, value);
                    fclose(f);
                    return -1;
                }
                cfg->listen_port = (unsigned short)port;
            } else {
                fprintf(stderr, "config: %s:%d: unknown key '%s' in [Interface]\n",
                        path, lineno, key);
                fclose(f);
                return -1;
            }
        } else if (section == SECTION_PEER) {
            if (strcasecmp(key, "Endpoint") == 0) {
                if (parse_endpoint_value(value, cfg->peer_host, sizeof(cfg->peer_host),
                                          &cfg->peer_port) != 0) {
                    fprintf(stderr,
                            "config: %s:%d: invalid Endpoint '%s' (expected host:port)\n",
                            path, lineno, value);
                    fclose(f);
                    return -1;
                }
            } else {
                fprintf(stderr, "config: %s:%d: unknown key '%s' in [Peer]\n",
                        path, lineno, key);
                fclose(f);
                return -1;
            }
        } else {
            fprintf(stderr, "config: %s:%d: key outside of a section\n", path, lineno);
            fclose(f);
            return -1;
        }
    }

    fclose(f);

    if (!have_address) {
        fprintf(stderr, "config: %s: missing required Address in [Interface]\n", path);
        return -1;
    }
    if (cfg->has_peer && cfg->peer_host[0] == '\0') {
        fprintf(stderr, "config: %s: [Peer] section is missing Endpoint\n", path);
        return -1;
    }
    if (cfg->tun_name[0] == '\0') {
        strcpy(cfg->tun_name, CONFIG_DEFAULT_DEVICE);
    }

    return 0;
}
