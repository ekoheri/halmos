#include "halmos_log.h"
#include "halmos_errors.h"
#include "halmos_global.h"
#include "halmos_core_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

// Variabel internal untuk manajemen thread dan file log
static pthread_t log_tid; 
static pthread_t maintenance_tid; 

// Menggunakan atomic_bool untuk sinkronisasi thread yang aman
static atomic_bool log_keep_running = ATOMIC_VAR_INIT(true);

// Status pelacakan keberhasilan pembuatan thread untuk pencegahan crash pthread_join
static bool log_tid_started = false;
static bool maintenance_tid_started = false;

// Inisialisasi Global Log Queue
LogQueue global_log_queue = {
    .head = 0, 
    .tail = 0, 
    .count = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

// Deklarasi helper internal
static void enqueue_log(LogType type, const char *format, va_list args);
static void* log_thread_routine(void* arg);
static void* log_maintenance_thread(void* arg);
static void perform_log_maintenance();
static bool is_valid_date_format(const char *date_str);

// ==========================================
// FUNGSI PUBLIC LOGGING
// ==========================================

void write_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    enqueue_log(LOG_TYPE_SYSTEM, format, args);
    va_end(args);
}

void write_log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    enqueue_log(LOG_TYPE_ERROR, format, args);
    va_end(args);
}

void write_log_error_code(HalmosErrorCode code, ...) {
    const char *module = get_module_prefix(code);
    const char *template_str = get_error_template(code);

    char message_body[MAX_LOG_MESSAGE];
    va_list args;
    va_start(args, code);
    vsnprintf(message_body, sizeof(message_body), template_str, args);
    va_end(args);

    char final_log[MAX_LOG_MESSAGE + 128];
    snprintf(final_log, sizeof(final_log), "[%s] [ERROR] [ERR-%d] %s", module, code, message_body);

    enqueue_log(LOG_TYPE_ERROR, final_log, (va_list){0});
}

void write_log_warn_code(HalmosErrorCode code, ...) {
    const char *module = get_module_prefix(code);
    const char *template_str = get_error_template(code);

    char message_body[MAX_LOG_MESSAGE];
    va_list args;
    va_start(args, code);
    vsnprintf(message_body, sizeof(message_body), template_str, args);
    va_end(args);

    char final_log[MAX_LOG_MESSAGE + 128];
    snprintf(final_log, sizeof(final_log), "[%s] [WARNING] [ERR-%d] %s", module, code, message_body);

    enqueue_log(LOG_TYPE_WARNING, final_log, (va_list){0});
}

void write_log_access(const char *protocol, const char *client_ip, const char *method, const char *uri, int status, long bytes_sent) {
    char access_msg[MAX_LOG_MESSAGE];
    snprintf(access_msg, sizeof(access_msg), "[%s] %s \"%s %s\" %d %ld", 
             protocol, client_ip, method, uri, status, bytes_sent);
    enqueue_log(LOG_TYPE_ACCESS, access_msg, (va_list){0});
}

// ==========================================
// START & STOP THREAD LOGGER & MAINTENANCE
// ==========================================

void start_thread_logger() {
    atomic_store(&log_keep_running, true);

    // 1. Jalankan Thread Utama Consumer Log
    if (pthread_create(&log_tid, NULL, log_thread_routine, NULL) == 0) {
        log_tid_started = true;
    } else {
        fprintf(stderr, "FATAL: Failed to start logger thread!\n");
    }

    // 2. Spawn Thread Maintenance Terpisah
    if (pthread_create(&maintenance_tid, NULL, log_maintenance_thread, NULL) == 0) {
        maintenance_tid_started = true;
    } else {
        fprintf(stderr, "ERROR: Failed to start log maintenance thread!\n");
    }
}

void stop_thread_logger() {
    pthread_mutex_lock(&global_log_queue.mutex);
    atomic_store(&log_keep_running, false); 
    pthread_cond_broadcast(&global_log_queue.cond); 
    pthread_mutex_unlock(&global_log_queue.mutex);

    if (log_tid_started) {
        pthread_join(log_tid, NULL);
        log_tid_started = false;
    }
    if (maintenance_tid_started) {
        pthread_join(maintenance_tid, NULL);
        maintenance_tid_started = false;
    }
}

// ==========================================
// BACKGROUND THREAD 1: LOGGER CONSUMER
// ==========================================

void* log_thread_routine(void* arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&global_log_queue.mutex);
        
        while (global_log_queue.count == 0 && atomic_load(&log_keep_running)) {
            pthread_cond_wait(&global_log_queue.cond, &global_log_queue.mutex);
        }

        if (!atomic_load(&log_keep_running) && global_log_queue.count == 0) {
            pthread_mutex_unlock(&global_log_queue.mutex);
            break; 
        }

        LogEntry current_entry = global_log_queue.entries[global_log_queue.head];
        global_log_queue.head = (global_log_queue.head + 1) % MAX_LOG_QUEUE;
        global_log_queue.count--;
        
        pthread_mutex_unlock(&global_log_queue.mutex);

        struct timespec ts_now;
        clock_gettime(CLOCK_REALTIME, &ts_now);
        struct tm t_storage;
        struct tm *t = localtime_r(&ts_now.tv_sec, &t_storage);
        long milliseconds = ts_now.tv_nsec / 1000000;

        char log_filename[256];
        char date_str[15];
        char time_str[32];

        strftime(date_str, sizeof(date_str), "%Y-%m-%d", t);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", t);
        snprintf(time_str + strlen(time_str), sizeof(time_str) - strlen(time_str), ".%03ld", milliseconds);

        // --- PENULISAN KE DISK (Hanya file System, Error, Warning, Access) ---
        if (current_entry.type == LOG_TYPE_ERROR) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_error.log", LOG_DIR, date_str);
        } else if (current_entry.type == LOG_TYPE_WARNING) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_warning.log", LOG_DIR, date_str);
        } else if (current_entry.type == LOG_TYPE_ACCESS) {
            snprintf(log_filename, sizeof(log_filename), "%s%s_access.log", LOG_DIR, date_str);
        } else {
            snprintf(log_filename, sizeof(log_filename), "%s%s_system.log", LOG_DIR, date_str);
        }

        FILE *f = fopen(log_filename, "a");
        if (f) {
            if (current_entry.type == LOG_TYPE_ACCESS) {
                fprintf(f, "[%s] %s\n", time_str, current_entry.text);
            } else {
                fprintf(f, "[%s] %s\n", time_str, current_entry.text);
            }
            fclose(f);
        }
    }
    return NULL;
}

// ==========================================
// BACKGROUND THREAD 2: MAINTENANCE WORKER
// ==========================================

static void* log_maintenance_thread(void* arg) {
    (void)arg;
    write_log("[CORE] Log maintenance worker thread started.");

    while (atomic_load(&log_keep_running)) {
        perform_log_maintenance();

        for (int i = 0; i < 3600 && atomic_load(&log_keep_running); i++) {
            sleep(1);
        }
    }
    return NULL;
}

// Helper untuk validasi format string tanggal "YYYY-MM-DD"
static bool is_valid_date_format(const char *date_str) {
    if (strlen(date_str) != 10) return false;
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) {
            if (date_str[i] != '-') return false;
        } else {
            if (date_str[i] < '0' || date_str[i] > '9') return false;
        }
    }
    return true;
}

static void perform_log_maintenance() {
    time_t rawtime;
    time(&rawtime);
    struct tm t_storage;
    struct tm *info = localtime_r(&rawtime, &t_storage);
    char today_str[15];
    strftime(today_str, sizeof(today_str), "%Y-%m-%d", info);

    DIR *dir = opendir(LOG_DIR);
    if (!dir) return;

    struct dirent *entry;
    char past_dates[64][15];
    int past_date_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        
        if (strstr(name, ".tar.gz") != NULL || strstr(name, ".tmp") != NULL) {
            continue;
        }

        bool is_valid_suffix = (
            strstr(name, "_system.log") != NULL ||
            strstr(name, "_error.log") != NULL ||
            strstr(name, "_warning.log") != NULL ||
            strstr(name, "_access.log") != NULL
        );

        if (is_valid_suffix && strlen(name) >= 10) {
            char file_date[11];
            strncpy(file_date, name, 10);
            file_date[10] = '\0';

            if (is_valid_date_format(file_date) && strcmp(file_date, today_str) != 0) {
                bool exists = false;
                for (int i = 0; i < past_date_count; i++) {
                    if (strcmp(past_dates[i], file_date) == 0) {
                        exists = true;
                        break;
                    }
                }
                if (!exists && past_date_count < 64) {
                    strcpy(past_dates[past_date_count++], file_date);
                }
            }
        }
    }
    closedir(dir);

    struct stat st;

    for (int d = 0; d < past_date_count; d++) {
        char *target_date = past_dates[d];
        char final_archive[256];
        char temp_archive[256];

        snprintf(final_archive, sizeof(final_archive), "%s/%s.tar.gz", LOG_DIR, target_date);
        snprintf(temp_archive, sizeof(temp_archive), "%s/%s.tar.gz.tmp", LOG_DIR, target_date);

        if (stat(final_archive, &st) == 0) {
            continue; 
        }
        unlink(temp_archive);

        char file_list_str[512] = "";
        int existing_file_count = 0;
        const char *suffixes[] = {"_system.log", "_error.log", "_access.log", "_warning.log"};
        
        for (int s = 0; s < 4; s++) {
            char check_path[512];
            snprintf(check_path, sizeof(check_path), "%s/%s%s", LOG_DIR, target_date, suffixes[s]);
            
            struct stat f_st;
            if (stat(check_path, &f_st) == 0) {
                char filename_only[64];
                snprintf(filename_only, sizeof(filename_only), "%s%s", target_date, suffixes[s]);
                strcat(file_list_str, filename_only);
                strcat(file_list_str, " ");
                existing_file_count++;
            }
        }

        if (existing_file_count == 0) {
            continue;
        }

        char cmd_tar[1024];
        snprintf(cmd_tar, sizeof(cmd_tar), 
                 "cd %s && tar -czf %s.tar.gz.tmp %s 2>/dev/null", 
                 LOG_DIR, target_date, file_list_str);
        
        int tar_res = system(cmd_tar);
        if (tar_res != 0) {
            unlink(temp_archive);
            continue;
        }

        char cmd_verify[512];
        snprintf(cmd_verify, sizeof(cmd_verify), "tar -tzf %s >/dev/null 2>&1", temp_archive);
        int verify_res = system(cmd_verify);

        if (verify_res == 0) {
            if (rename(temp_archive, final_archive) == 0) {
                for (int s = 0; s < 4; s++) {
                    char rm_path[512];
                    snprintf(rm_path, sizeof(rm_path), "%s/%s%s", LOG_DIR, target_date, suffixes[s]);
                    unlink(rm_path);
                }
                write_log("[MAINTENANCE] Successfully archived, verified, and cleaned logs for date: %s", target_date);
            } else {
                unlink(temp_archive);
            }
        } else {
            unlink(temp_archive);
            write_log_error("[MAINTENANCE] ERROR: Archive verification failed for date %s! Raw logs preserved.", target_date);
        }
    }

    dir = opendir(LOG_DIR);
    if (dir) {
        time_t now = time(NULL);
        
        while ((entry = readdir(dir)) != NULL) {
            const char *name = entry->d_name;
            if (strstr(name, ".tar.gz") != NULL && strstr(name, ".tmp") == NULL && strlen(name) >= 14) {
                char file_date_str[11];
                strncpy(file_date_str, name, 10);
                file_date_str[10] = '\0';

                if (is_valid_date_format(file_date_str)) {
                    struct tm file_tm = {0};
                    file_tm.tm_year = atoi(file_date_str) - 1900;
                    file_tm.tm_mon  = atoi(file_date_str + 5) - 1;
                    file_tm.tm_mday = atoi(file_date_str + 8);
                    
                    time_t file_time = mktime(&file_tm);
                    if (file_time != (time_t)-1) {
                        double age_in_days = difftime(now, file_time) / (60 * 60 * 24);
                        if (age_in_days > config.log_retention_days) {
                            char full_path[512];
                            snprintf(full_path, sizeof(full_path), "%s/%s", LOG_DIR, name);
                            if (unlink(full_path) == 0) {
                                write_log("[MAINTENANCE] Retention policy: Removed old archive %s (Parsed Age: %.1f days)", name, age_in_days);
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
    }
}

// ==========================================
// HELPER FUNCTIONS LAINNYA
// ==========================================

static void enqueue_log(LogType type, const char *format, va_list args) {
    pthread_mutex_lock(&global_log_queue.mutex);
    
    if (global_log_queue.count < MAX_LOG_QUEUE) {
        int tail = global_log_queue.tail;
        
        if (format) {
            if (type == LOG_TYPE_ACCESS) {
                snprintf(global_log_queue.entries[tail].text, MAX_LOG_MESSAGE, "%s", format);
            } else {
                vsnprintf(global_log_queue.entries[tail].text, MAX_LOG_MESSAGE, format, args);
            }
        }
        global_log_queue.entries[tail].type = type;
        
        global_log_queue.tail = (tail + 1) % MAX_LOG_QUEUE;
        global_log_queue.count++;
        
        pthread_cond_signal(&global_log_queue.cond);
    }
    
    pthread_mutex_unlock(&global_log_queue.mutex);
}

double hitung_durasi(struct timespec start, struct timespec end) {
    double s = (double)end.tv_sec - (double)start.tv_sec;
    double ns = (double)end.tv_nsec - (double)start.tv_nsec;
    return (s * 1000.0) + (ns / 1000000.0);
}