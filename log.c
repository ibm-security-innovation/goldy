#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

static char *log_filename;
static int log_fd;
static int log_level;

int log_stderr_open(int level) {
    log_level = level;
    log_fd = STDERR_FILENO;
    return 0;
}

int log_file_open(int level, char* filename) {
    log_level = level;
    log_filename = filename;
    log_fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (log_fd < 0) {
        perror("Error opening log file");
        return -1;
    }
    return 0;
}

void log_reopen() {
    if (log_fd != STDERR_FILENO) {
        log_close();
        log_file_open(log_level, log_filename);
    }
}

void log_close() {
    if (log_fd != STDERR_FILENO) {
        close(log_fd);
    }
}

static void log_impl(const char* level_name, const char* format, va_list arglist) {
    char line[1024];
    struct timeval tv;
    size_t len;

    gettimeofday(&tv, NULL);
    len = strftime(line, sizeof(line), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
#if defined(__APPLE__) && defined(__MACH__)
    len += snprintf(line + len, sizeof(line) - len, ".%06d %-5s ", tv.tv_usec, level_name);
#else
    len += snprintf(line + len, sizeof(line) - len, ".%06lu %-5s ", tv.tv_usec, level_name);
#endif
    len += vsnprintf(line + len, sizeof(line) - len, format, arglist);
    line[len] = '\n';
    len++;
    line[len] = '\0';
    write(log_fd, line, len);
}

void log_debug(const char* format, ...) {
    va_list arglist;

    if (log_level < LOG_DEBUG) {
        return;
    }
    va_start(arglist, format);
    log_impl("DEBUG", format, arglist);
    va_end(arglist);
}

void log_info(const char* format, ...) {
    va_list arglist;

    if (log_level < LOG_INFO) {
        return;
    }
    va_start(arglist, format);
    log_impl("INFO", format, arglist);
    va_end(arglist);
}

void log_error(const char* format, ...) {
    va_list arglist;

    if (log_level < LOG_ERROR) {
        return;
    }
    va_start(arglist, format);
    log_impl("ERROR", format, arglist);
    va_end(arglist);
}
