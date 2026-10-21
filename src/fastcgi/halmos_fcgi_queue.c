#include "halmos_fcgi_queue.h"
#include <stdlib.h>
#include <stdio.h>

extern bool halmos_fcgi_is_running(void);
// Variabel global untuk antrean tugas upstream FastCGI
static FCGITaskQueue fcgi_task_queue;

bool halmos_fcgi_queue_init(void) {
    fcgi_task_queue.head = NULL;
    fcgi_task_queue.tail = NULL;
    fcgi_task_queue.size = 0;

    if (pthread_mutex_init(&fcgi_task_queue.lock, NULL) != 0) {
        return false;
    }

    if (pthread_cond_init(&fcgi_task_queue.not_empty, NULL) != 0) {
        pthread_mutex_destroy(&fcgi_task_queue.lock);
        return false;
    }

    return true;
}

void halmos_fcgi_queue_destroy(void) {
    pthread_mutex_lock(&fcgi_task_queue.lock);
    
    FCGITask *current = fcgi_task_queue.head;
    while (current != NULL) {
        FCGITask *next = current->next;
        free(current);
        current = next;
    }

    fcgi_task_queue.head = NULL;
    fcgi_task_queue.tail = NULL;
    fcgi_task_queue.size = 0;

    pthread_mutex_unlock(&fcgi_task_queue.lock);
    pthread_mutex_destroy(&fcgi_task_queue.lock);
    pthread_cond_destroy(&fcgi_task_queue.not_empty);

    fprintf(stderr, "[FCGI_QUEUE_DEBUG] halmos_fcgi_queue_destroy() completed.\n");
}

bool halmos_fcgi_queue_push(HalmosFCGISession *session, FCGI_TaskType type) {
    if (!session) return false;

    FCGITask *new_task = (FCGITask*)malloc(sizeof(FCGITask));
    if (!new_task) return false;

    new_task->type = type;
    new_task->session = session;
    new_task->next = NULL;

    pthread_mutex_lock(&fcgi_task_queue.lock);

    if (fcgi_task_queue.tail == NULL) {
        // Antrean kosong
        fcgi_task_queue.head = new_task;
        fcgi_task_queue.tail = new_task;
    } else {
        fcgi_task_queue.tail->next = new_task;
        fcgi_task_queue.tail = new_task;
    }

    fcgi_task_queue.size++;

    // Bangunkan satu worker thread yang sedang tidur
    pthread_cond_signal(&fcgi_task_queue.not_empty);
    pthread_mutex_unlock(&fcgi_task_queue.lock);

    return true;
}

FCGITask* halmos_fcgi_queue_pop(void) {
    pthread_mutex_lock(&fcgi_task_queue.lock);

    // Tunggu sampai ada task di dalam antrean ATAU pool berhenti running
    while (fcgi_task_queue.head == NULL) {
        pthread_cond_wait(&fcgi_task_queue.not_empty, &fcgi_task_queue.lock);
        
        // Cek apakah server sudah stop agar tidak terjebak selamanya
        if (!halmos_fcgi_is_running() && fcgi_task_queue.head == NULL) {
            pthread_mutex_unlock(&fcgi_task_queue.lock);
            return NULL;
        }
    }

    FCGITask *task = fcgi_task_queue.head;
    fcgi_task_queue.head = task->next;

    if (fcgi_task_queue.head == NULL) {
        fcgi_task_queue.tail = NULL;
    }

    fcgi_task_queue.size--;

    pthread_mutex_unlock(&fcgi_task_queue.lock);
    return task;
}

void halmos_fcgi_queue_broadcast(void) {
    pthread_mutex_lock(&fcgi_task_queue.lock);
    pthread_cond_broadcast(&fcgi_task_queue.not_empty);
    pthread_mutex_unlock(&fcgi_task_queue.lock);
}