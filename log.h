#ifndef _LOG_H_
#define _LOG_H_

#define LOG_ERROR 1
#define LOG_INFO  2
#define LOG_DEBUG 3

int log_stderr_open(int level);
int log_file_open(int level, char* filename);
void log_reopen();
void log_close();

void log_debug(const char* fmt, ...);
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);

#endif
