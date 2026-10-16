#ifndef HALMOS_CORE_ADMISSION_H
#define HALMOS_CORE_ADMISSION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <pthread.h>

typedef struct {
    float max_cpu_threshold;      
    float recovery_cpu_threshold; 
    float max_ram_threshold;      
    float recovery_ram_threshold; 
    
    _Atomic float live_cpu_usage;   
    _Atomic float live_ram_usage;   
    _Atomic bool is_cpu_overloaded; 
    _Atomic bool is_ram_overloaded; 
    
    pthread_t monitor_thread;
    atomic_bool is_running;
} AdmissionController;

#define ADMISSION_MAX_CPU       0.92f //Max CPU usage 92%
#define ADMISSION_RECOVERY_CPU  0.82f //Recovery CPU 82%
#define ADMISSION_MAX_RAM       0.90f //Max memory usage 90%
#define ADMISSION_RECOVERY_RAM  0.80f //recovery memory 80%

AdmissionController* core_admission_init(void);

bool core_admission_evaluate(AdmissionController *controller, size_t current_queue_size);

void core_admission_destroy(AdmissionController *controller);

#endif // HALMOS_CORE_ADMISSION_H