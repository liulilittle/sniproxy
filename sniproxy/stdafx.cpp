#include "stdafx.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <sched.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/file.h>
#endif

bool FileWriteAllBytes(const char* path, const void* data, int length) noexcept {
    if (NULL == path || length < 0) {
        return false;
    }

    if (NULL == data && length != 0) {
        return false;
    }

    FILE* f = fopen(path, "wb+");
    if (NULL == f) {
        return false;
    }

    if (length > 0) {
        fwrite((char*)data, length, 1, f);
    }

    fflush(f);
    fclose(f);
    return true;
}

void SetThreadPriorityToMaxLevel() noexcept {
#ifdef _WIN32
    SetThreadPriority(GetCurrentProcess(), THREAD_PRIORITY_TIME_CRITICAL);
#else
    /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
    struct sched_param param_;
    param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param_);
#endif
}

void SetProcessPriorityToMaxLevel() noexcept {
#ifdef _WIN32
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
#else
    char path_[260];
    snprintf(path_, sizeof(path_), "/proc/%d/oom_adj", getpid());

    char level_[] = "-17";
    FileWriteAllBytes(path_, level_, sizeof(level_));

    /* Processo pai deve ter prioridade maior que os filhos. */
    setpriority(PRIO_PROCESS, 0, -20);

    /* ps -eo state,uid,pid,ppid,rtprio,time,comm */
    struct sched_param param_;
    param_.sched_priority = sched_get_priority_max(SCHED_FIFO); // SCHED_RR
    sched_setscheduler(getpid(), SCHED_RR, &param_);
#endif
}