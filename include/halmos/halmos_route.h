#ifndef HALMOS_ROUTE_H
#define HALMOS_ROUTE_H

#include <stdbool.h>

#define MAX_ROUTES 256

// halmos_route.h
typedef enum {
    RT_STATIC,
    RT_FASTCGI_PHP,
    RT_FASTCGI_RS,
    RT_FASTCGI_PY,
    RT_FALLBACK
} RouteType;

typedef struct {
    char pattern[128];     // Misal: "/php/dhe/lib"
    RouteType type;        // Misal: RT_FASTCGI_PHP
    char script_name[128]; // Misal: "test_dhe.php"
    char query_args[128];  // Misal: "mode=lib"
    bool is_wildcard;
} RouteRule;


// Deklarasi agar bisa diakses file lain
extern RouteRule route_table[MAX_ROUTES];
extern int total_routes;

void load_routes(const char *filename);
RouteRule* match_route(const char *uri);

#endif