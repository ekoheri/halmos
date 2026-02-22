#include "halmos_ws_config.h"
#include "halmos_global.h"

#include <stdio.h>
#include <string.h>

// Definisi asli variabel ws_cfg (Alokasi memori terjadi di sini)
halmos_ws_proto_t ws_cfg;

// Fungsi internal untuk mengisi nilai default (SOP Jaga-jaga)
static void set_default_ws_proto() {
    strcpy(ws_cfg.version, "1.0");
    strcpy(ws_cfg.envelope.header, "header");
    strcpy(ws_cfg.envelope.payload, "payload");
    strcpy(ws_cfg.keys.action, "type");
    strcpy(ws_cfg.keys.from, "src");
    strcpy(ws_cfg.keys.to, "dst");
    strcpy(ws_cfg.keys.app, "app_id");
    ws_cfg.policy.allow_anonymous = false;
    ws_cfg.policy.max_topics_per_client = 10;
    ws_cfg.limits.max_payload = 10 * 1024 * 1024; // 10MB
}

int halmos_ws_config_load(const char *json_path) {
    set_default_ws_proto();

    struct json_object *root = json_object_from_file(json_path);
    if (!root) {
        fprintf(stderr, "Error: Gagal memuat file konfigurasi WS di %s\n", json_path);
        return -1;
    }

    struct json_object *protocol, *envelope, *keys, *policy, *limits, *tmp;

    // Gunakan TITIK (.) karena ws_cfg di sini adalah variabel global statis
    if (json_object_object_get_ex(root, "protocol", &protocol)) {
        if (json_object_object_get_ex(protocol, "version", &tmp))
            strncpy(ws_cfg.version, json_object_get_string(tmp), 9);

        if (json_object_object_get_ex(protocol, "envelope_structure", &envelope)) {
            if (json_object_object_get_ex(envelope, "header", &tmp))
                strncpy(ws_cfg.envelope.header, json_object_get_string(tmp), 63);
            if (json_object_object_get_ex(envelope, "body", &tmp))
                strncpy(ws_cfg.envelope.payload, json_object_get_string(tmp), 63);
        }

        if (json_object_object_get_ex(protocol, "routing_keys", &keys)) {
            if (json_object_object_get_ex(keys, "action", &tmp))
                strncpy(ws_cfg.keys.action, json_object_get_string(tmp), 63);
            if (json_object_object_get_ex(keys, "from", &tmp))
                strncpy(ws_cfg.keys.from, json_object_get_string(tmp), 63);
            if (json_object_object_get_ex(keys, "to", &tmp))
                strncpy(ws_cfg.keys.to, json_object_get_string(tmp), 63);
            if (json_object_object_get_ex(keys, "app", &tmp))
                strncpy(ws_cfg.keys.app, json_object_get_string(tmp), 63);
        }
    }

    if (json_object_object_get_ex(root, "routing_policy", &policy)) {
        if (json_object_object_get_ex(policy, "allow_anonymous_topics", &tmp))
            ws_cfg.policy.allow_anonymous = json_object_get_boolean(tmp);
        if (json_object_object_get_ex(policy, "max_topics_per_client", &tmp))
            ws_cfg.policy.max_topics_per_client = json_object_get_int(tmp);
        if (json_object_object_get_ex(policy, "internal_prefix", &tmp))
            strncpy(ws_cfg.policy.internal_prefix, json_object_get_string(tmp), 31);
    }

    if (json_object_object_get_ex(root, "limits", &limits)) {
        if (json_object_object_get_ex(limits, "global_max_payload", &tmp))
            ws_cfg.limits.max_payload = json_object_get_int64(tmp);
        if (json_object_object_get_ex(limits, "strict_mode", &tmp))
            ws_cfg.limits.strict_mode = json_object_get_boolean(tmp);
    }

    json_object_put(root); 
    return 0;
}

void halmos_ws_config_debug(halmos_ws_proto_t *ws_cfg) {
    printf("--- Halmos WS Protocol Config ---\n");
    printf("Ver: %s\n", ws_cfg->version);
    printf("Header Key: %s | Payload Key: %s\n", ws_cfg->envelope.header, ws_cfg->envelope.payload);
    printf("Routing -> Action: %s, To: %s, From: %s\n", ws_cfg->keys.action, ws_cfg->keys.to, ws_cfg->keys.from);
    printf("Max Payload: %ld bytes\n", ws_cfg->limits.max_payload);
    printf("---------------------------------\n");
}