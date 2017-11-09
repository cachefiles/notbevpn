#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#ifdef __linux__
#include <features.h>
#endif

#include "tx_debug.h"

void __tx_check__(int cond, const char *msg, int line, const char *file)
{
	if (cond == 0) {
		fprintf(stderr, "%s %s:%d\n", msg, file, line);
		/* just an warning */
	}
	return;
}

void __tx_panic__(int cond, const char *msg, int line, const char *file)
{
	if (cond == 0) {
		fprintf(stderr, "%s %s:%d\n", msg, file, line);
		exit(-1);
	}
	return;
}

static struct log_cookie {
	int log_fd;
	int log_nol;

	int log_len;
	char log_fmt[256];
} _log_cookie;

static size_t log_header(struct log_cookie *logcb)
{
	size_t len;
	if (!logcb->log_nol) {
		return 0;
	}

	logcb->log_nol = 0;
	len = write(logcb->log_fd, logcb->log_fmt, logcb->log_len);
	assert(len == logcb->log_len);

	return len;
}

static ssize_t _log_write(void *c, const char *buf, size_t size)
{
	size_t len;
	const char *p = buf;
	const char *buf_limit = buf + size;
	struct log_cookie *logcb = (struct log_cookie *)c;

	if (size == 0) {
		return size;
	}

	for (p = buf; p < buf_limit; p++) {
		const char *next = p + 1;
		if (*p == '\n') {
			len = log_header(logcb);
			len = write(logcb->log_fd, buf, next - buf);
			assert (len == next - buf);

			logcb->log_nol = 1;
			buf = next;
		}
	}

	if (buf < buf_limit) {
		len = log_header(logcb);
		len = write(logcb->log_fd, buf, buf_limit - buf);
		assert (len == buf_limit - buf);
	}

	return size;
}

#ifdef __GLIBC__
#define _logfmt(fmt, tag) fmt
#define log_open(cookie) fopencookie(cookie, "w+", logger_func)

static int _use_line_break = 1;
static cookie_io_functions_t logger_func = {
	.read = NULL,
	.write = _log_write
};
#endif

#ifdef __APPLE__
#define _logfmt(fmt, tag) fmt
#define log_open(cookie) fwopen(cookie, log_write)

static int _use_line_break = 2;
static int log_write(void *c, const char *buf, int size)
{
	return _log_write(c, buf, size);
}
#endif

#ifndef _logfmt
#define _logfmt(fmt, tag) _logfmt(fmt, tag)
#define log_open(cookie) fdopen((cookie)->log_fd, "w")

static int _use_line_break = 0;
static const char *_logfmt(const char *fmt, const char *tag)
{
	size_t len;
	struct timeval tv0;
	struct tm *lt, ltv= {};
	static char _fmt[8192];

	gettimeofday(&tv0, NULL);
	time_t now = tv0.tv_sec;
#ifdef WINNT
	lt = localtime(&now);
#else
	lt = localtime_r(&now, &ltv);
#endif

	if (*fmt == 0 || *tag == '%') {
		return fmt;
	}

	len = snprintf(_fmt, sizeof(_fmt),
			"%2d-%02d %02d:%02d:%02d.%03d %.1s %s\n", 1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec, (int)(tv0.tv_usec / 1000), tag, fmt);

	assert (len < sizeof(_fmt));
	if (len < sizeof(_fmt) && _fmt[len - 2] == '\n') {
		_fmt[len - 1] = 0;
	}

	return _fmt;
}
#endif

static FILE *log_get(int fd, const char *tag)
{
    time_t now;
    size_t count;
	struct timeval tv0;
	struct log_cookie *logcb;

    static struct tm lt = {};
	static struct timeval tv1;
	static FILE *_logfp = NULL;

	logcb = &_log_cookie;
	logcb->log_fd = fd;

	if (_logfp == NULL) {
		_logfp = log_open(&_log_cookie);
		assert (_logfp != NULL);
	}

	gettimeofday(&tv0, NULL);
	if (tv0.tv_sec != tv1.tv_sec) {
		tv1 = tv0;
		now = tv0.tv_sec;
#ifdef WINNT
		lt = *localtime(&now);
#else
		localtime_r(&now, &lt);
#endif
	}

	count = snprintf(logcb->log_fmt, sizeof(logcb->log_fmt),
			"%2d-%02d %02d:%02d:%02d.%03d %s ", 1 + lt.tm_mon, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, (int)(tv0.tv_usec / 1000), tag);

	logcb->log_len = count;
	logcb->log_nol = 1;

	return _logfp;
}

static const char *_logable_tags = NULL;
static const char *default_logable_tags = "FEWID";

static int log_logable(const char *logtag)
{
    if (_logable_tags == NULL) {
        _logable_tags = getenv("LOGABLE_TAGS");

        if (_logable_tags == NULL) {
            _logable_tags = default_logable_tags;
            assert (_logable_tags != NULL);
        }
    }

    return (logtag == NULL) || (NULL != strstr(_logable_tags, logtag));
}

static int log_put(FILE *log)
{
	struct log_cookie *logcb = (struct log_cookie *)&_log_cookie;

	fflush(log);
	if (logcb->log_nol == 0) {
		write(logcb->log_fd, "\r\n", 2);
	}

	return 0;
}

int log_tag_putlog(const char *tag, const char *fmt, ...)
{
	int n = 0;
	va_list ap;
	va_start(ap, fmt);

	if (log_logable(tag)) {
		FILE *logfp = log_get(STDERR_FILENO, tag);
		n = vfprintf(logfp, _logfmt(fmt, tag), ap);
		log_put(logfp);
	}

	va_end(ap);
	return n;
}

int log_tag_vputlog(const char *tag, const char *fmt, va_list args)
{
	int n = 0;

	if (log_logable(tag)) {
		FILE *logfp = log_get(STDERR_FILENO, tag);
		n = vfprintf(logfp, _logfmt(fmt, tag), args);
		log_put(logfp);
	}

	return n;
}
