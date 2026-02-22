#ifndef HALMOS_WS_CONFIG_H
#define HALMOS_WS_CONFIG_H

#include <stdbool.h>
#include <json-c/json.h>

typedef struct {
    // Versi Protokol
    char version[10];

    // Mapping Struktur Envelope
    struct {
        char header[64];
        char payload[64];
    } envelope;

    // Mapping Kunci Routing
    struct {
        char action[64]; // type
        char from[64];   // src
        char to[64];     // dst
        char app[64];    // app_id
    } keys;

    // Aturan Main (Policy)
    struct {
        bool allow_anonymous;
        int max_topics_per_client;
        char internal_prefix[32];
    } policy;

    // Batasan (Limits)
    struct {
        long max_payload;
        bool strict_mode;
    } limits;

} halmos_ws_proto_t;

// Fungsi Utama
int halmos_ws_config_load(const char *json_path);
void halmos_ws_config_debug(halmos_ws_proto_t *ws_cfg);

#endif