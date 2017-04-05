#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"

int lcr_log_fd = -1;
static int syslog_enable = 0;

static char log_prefix[LCR_LOG_PREFIX_SIZE] = "lcr";
static char *log_fname = NULL;
static char *log_vmname = NULL;

lcr_log_define(lcr_log, lcr);

static int lcr_log_priority_to_syslog(int priority)
{
	switch (priority) {
	case LCR_LOG_PRIORITY_FATAL:
		return LOG_EMERG;
	case LCR_LOG_PRIORITY_ALERT:
		return LOG_ALERT;
	case LCR_LOG_PRIORITY_CRIT:
		return LOG_CRIT;
	case LCR_LOG_PRIORITY_ERROR:
		return LOG_ERR;
	case LCR_LOG_PRIORITY_WARN:
		return LOG_WARNING;
	case LCR_LOG_PRIORITY_NOTICE:
	case LCR_LOG_PRIORITY_NOTSET:
		return LOG_NOTICE;
	case LCR_LOG_PRIORITY_INFO:
		return LOG_INFO;
	case LCR_LOG_PRIORITY_TRACE:
	case LCR_LOG_PRIORITY_DEBUG:
		return LOG_DEBUG;
	}

	/* Not Reached */
	return LOG_NOTICE;
}

static int log_append_syslog(const struct lcr_log_appender *appender,
			struct lcr_log_event *event)
{
	char *msg;
	int rc, len;
	va_list	args;

	if (!syslog_enable)
		return 0;

	va_copy(args, *event->vap);
	len = vsnprintf(NULL, 0, event->fmt, args) + 1;
	va_end(args);
	msg = malloc(len * sizeof(char));
	if (msg == NULL)
		return 0;
	rc = vsnprintf(msg, len, event->fmt, *event->vap);
	if (rc == -1 | rc >= len) {
		free(msg);
		return 0;
	}

	syslog(lcr_log_priority_to_syslog(event->priority),
		"%s%s %s - %s:%s:%d - %s",
		log_vmname ? log_vmname : "",
		log_vmname ? ":" : "",
		event->category,
		event->locinfo->file,
		event->locinfo->func,
		event->locinfo->line,
		msg);
	free(msg);

	return 0;
}


static int log_append_stderr(const struct lcr_log_appender *appender,
		struct lcr_log_event *event)
{
	if (event->priority < LCR_LOG_PRIORITY_ERROR)
		return 0;
	fprintf(stderr, "%s: %s%s", log_prefix, log_vmname ? log_vmname : "",
		log_vmname ? ":" : "");
	fprintf(stderr, "%s: %s: %d ", event->locinfo->file,
		event->locinfo->func, event->locinfo->line);
	fprintf(stderr, event->fmt, *event->vap);
	fprintf(stderr, "\n");
}

static int log_append_logfile(const struct lcr_log_appender *appender,
		struct lcr_log_event *event)
{
	char buffer[LCR_LOG_BUFFER_SIZE];
	int n;

	if (lcr_log_fd == -1)
		return 0;

	n = snprintf(buffer, sizeof(buffer),
		"%15s%s%s %s %-8s %s - %s:%s:%d - ",
		log_prefix,
		log_vmname ? " " : "",
		log_vmname ? log_vmname : "",
		"",
		lcr_log_priority_to_string(event->priority),
		event->category,
		event->locinfo->file,
		event->locinfo->func,
		event->locinfo->line);

	if ( n < 0)
		return n;

	if ((size_t)n < (sizeof(buffer) - 1))
		n += vsnprintf(buffer + n, sizeof(buffer) - n, event->fmt, *event->vap);
	else
		n = sizeof(buffer) - 1;

	buffer[n] = '\n';

	return write(lcr_log_fd, buffer, n+1);
}


static struct lcr_log_appender log_appender_syslog = {
	.name		= "syslog",
	.append		= log_append_syslog,
	.next		= NULL,
};

static struct lcr_log_appender log_appender_stderr = {
	.name		= "stderr",
	.append		= log_append_stderr,
	.next		= NULL,
};

static struct lcr_log_appender log_appender_logfile = {
	.name		= "logfile",
	.append		= log_append_logfile,
	.next		= NULL,
};


static struct lcr_log_category log_root = {
	.name		= "root",
	.priority	= LCR_LOG_PRIORITY_ERROR,
	.appender	= NULL,
	.parent		= NULL,
};

struct lcr_log_category lcr_log_category_lcr = {
	.name		= "lcr",
	.priority	= LCR_LOG_PRIORITY_ERROR,
	.appender	= &log_appender_logfile,
	.parent		= &log_root,
};

static int build_dir(const char *name)
{
	char *n = strdup(name);
	char *p, *e;
	int ret;

	if (!n) {
		ERROR("out of memory while creating directory '%s'-", name);
		return -1;
	}

	e = &n[strlen(n)];
	for (p = n+1; p < e; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (access(n, F_OK)){
			ret = mkdir(n, 0755);
			if (ret && errno != EEXIST) {
				SYSERROR("failed to create directory '%s'-", n);
				free(n);
				return -1;
			}
		}
		*p = '/';
	}
	free(n);
	return 0;
}

static int log_open(const char *name)
{
	int fd;
	int newfd;

	fd = open(name, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0666);
	if (fd == -1) {
		ERROR("failed to open log file\"%s\": %s", name,
			strerror(errno));
		return -1;
	}
	if (fd > 2)
		return fd;

	newfd = fcntl(fd, F_DUPFD_CLOEXEC, 3);

	if (newfd == -1)
		ERROR("failed to dup log fd %d: %s", fd, strerror(errno));

	close(fd);
	return newfd;
}

static char *build_log_path(const char *name, const char *lcrpath)
{
	char *p;
	int len, ret, use_dir;
	if (!name)
		return NULL;
	// 6 = '/' + '.log' + '\0'
	len = strlen(name) + 6;
	if (lcrpath)
		use_dir = 1;
	else
		lcrpath = "/var/log/lcr";

	if (use_dir)
		// add "/$container name/"
		len += strlen(lcrpath) + 1 + strlen(name) + 1;
	else
		len += strlen(lcrpath) + 1;

	p = malloc(len);
	if (!p)
		return p;

	if (use_dir)
		ret = snprintf(p, len, "%s/%s/%s.log", lcrpath, name, name);
	else
		ret = snprintf(p, len, "%s/%s.log", lcrpath, name);

	if (ret < 0 || ret >= len) {
		free(p);
		return NULL;
	}

	return p;
}

extern void lcr_log_close(void) {
	closelog();
	free(log_vmname);
	log_vmname = NULL;
	if (lcr_log_fd == -1)
		return;
	close(lcr_log_fd);
	lcr_log_fd == -1;
	free(log_fname);
	log_fname = NULL;
}

extern void lcr_log_set_prefix(const char *prefix)
{
	strncpy(log_prefix, prefix, sizeof(log_prefix));
	log_prefix[sizeof(log_prefix) - 1] = 0;
}


static int __lcr_log_set_file(const char *fname, int create_dirs)
{
	if (lcr_log_fd != -1) {
		lcr_log_close();
	}

	if (!fname)
		return -1;

	if (strlen(fname) == 0) {
		log_fname = NULL;
		return 0;
	}

	if (create_dirs)
		if (build_dir(fname)) {
			ERROR("failed to create dir for log file \"%s\" : %s",
			fname, strerror(errno));
			return -1;
		}

	lcr_log_fd = log_open(fname);
	if (lcr_log_fd == -1)
		return -1;

	log_fname = strdup(fname);

	return 0;
}

static int _lcr_log_set_file(const char *fname, const char *lcrpath,
			int create_dirs)
{
	char *logfile;
	int ret;

	logfile = build_log_path(fname, lcrpath);
	if (!logfile) {
		ERROR("could not build log path");
		return -1;
	}

	ret = __lcr_log_set_file(logfile, create_dirs);
	free(logfile);
	return ret;
}
extern int lcr_log_init(const char *name, const char *file,
			const char *priority, const char *prefix,
			int quiet, const char *lcrpath)
{
	int lcr_priority = LCR_LOG_PRIORITY_ERROR;
	int ret = 0;

	if (lcr_log_fd != -1) {
		WARN("lcr_log_init called with log already initialized");
		return 0;
	}

	if (priority)
		lcr_priority = lcr_log_priority_to_int(priority);

	lcr_log_category_lcr.priority = lcr_priority;

	if (!quiet)
		lcr_log_category_lcr.appender->next = &log_appender_stderr;

	if (prefix)
		lcr_log_set_prefix(prefix);
	if (name)
		log_vmname = strdup(name);

	if (file) {
		if (strcmp(file, "none") == 0)
			return 0;
		ret = __lcr_log_set_file(file, 1);
	}else {
		if (!name)
			return 0;
		ret = -1;
		// FIXME: remove the hardcode for lcrpath
		if (!lcrpath)
			lcrpath = "/var/log/lcr";

		ret = _lcr_log_set_file(name, lcrpath, 1);

	}

	if (!file && ret != 0) {
		INFO("Ignoring failure to open default logfile");
		ret = 0;
	}
	return ret;
}

extern int lcr_log_syslog(int facility) {
	struct lcr_log_appender *appender;

	openlog(log_prefix, LOG_PID, facility);
	if (!lcr_log_category_lcr.appender) {
		lcr_log_category_lcr.appender = &log_appender_syslog;
		return 0;
	}
	appender = lcr_log_category_lcr.appender;
	while(appender->next != NULL)
		appender = appender->next;
	appender->next = &log_appender_syslog;

	return 0;
}
extern void lcr_log_enable_syslog(void) {
	syslog_enable = 1;
}
