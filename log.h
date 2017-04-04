#ifndef __LCR_LOG_H
#define __LCR_LOG_H

#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <syslog.h>


#define	LCR_LOG_PREFIX_SIZE	32
#define	LCR_LOG_BUFFER_SIZE	4096

// This attribute, attached to a function, means that the function
// is meant to be possibly unused. GCC does not produce a warning
// for this function.
#if defined(__GUNC__)
#define ATTR_UNUSED __attribute__ ((unused))
#else
#define ATTR_UNUSED
#endif

/* predefined lcr log priorities */
enum lcr_loglevel {
	LCR_LOG_PRIORITY_TRACE,
	LCR_LOG_PRIORITY_DEBUG,
	LCR_LOG_PRIORITY_INFO,
	LCR_LOG_PRIORITY_NOTICE,
	LCR_LOG_PRIORITY_WARN,
	LCR_LOG_PRIORITY_ERROR,
	LCR_LOG_PRIORITY_CRIT,
	LCR_LOG_PRIORITY_ALERT,
	LCR_LOG_PRIORITY_FATAL,
	LCR_LOG_PRIORITY_NOTSET,
};

/* location information of the logging event */
struct lcr_log_locinfo {
	const char	*file;
	const char	*func;
	int		line;
};

#define LCR_LOG_LOCINFO_INIT		\
	{				\
		.file = __FILE__,	\
		.func = __func__,	\
		.line = __LINE__,	\
	}

/* brief logging event object */
struct lcr_log_event {
	const char		*category;
	int			priority;
	struct timespec		timestamp;
	struct lcr_log_locinfo	*locinfo;
	const char		*fmt;
	va_list			*vap;
};
/* log_appender_object */
struct lcr_log_appender {
	const char*	name;
	int (*append)(const struct lcr_log_appender *, struct lcr_log_event *);

	// appenders can be stacked
	struct lcr_log_appender *next;
};


/* log catagory object */
struct lcr_log_category {
	const char			*name;
	int				priority;
	struct lcr_log_appender		*appender;
	const struct lcr_log_category	*parent;
};


/*
 * Returns true if the chained priority is equal or higher than
 * given priority.
 */
static inline int lcr_log_priority_is_enable(
	const struct lcr_log_category *category,
	int priority)
{
	while (category->priority == LCR_LOG_PRIORITY_NOTSET &&
		category->parent)
		category = category->parent;

	int cmp_prio = category->priority;

	return cmp_prio <= priority;
}

/*
 * converts a priority to a literal string
 */
static inline const char* lcr_log_priority_to_string(int priority)
{
	switch (priority) {
	case LCR_LOG_PRIORITY_TRACE:	return "TRACE";
	case LCR_LOG_PRIORITY_DEBUG:	return "DEBUG";
	case LCR_LOG_PRIORITY_INFO:	return "INFO";
	case LCR_LOG_PRIORITY_NOTICE:	return "NOTICE";
	case LCR_LOG_PRIORITY_WARN:	return "WARN";
	case LCR_LOG_PRIORITY_ERROR:	return "ERROR";
	case LCR_LOG_PRIORITY_CRIT:	return "CRIT";
	case LCR_LOG_PRIORITY_ALERT:	return "ALERT";
	case LCR_LOG_PRIORITY_FATAL:	return "FATAL";
	default:
		return "NOTSET";
	}
}

static inline const char* lcr_syslog_priority_to_string(int priority)
{
	switch (priority) {
	case LOG_DAEMON: return "daemon";
	case LOG_LOCAL0: return "local0";
	case LOG_LOCAL1: return "local1";
	case LOG_LOCAL2: return "local2";
	case LOG_LOCAL3: return "local3";
	case LOG_LOCAL4: return "local4";
	case LOG_LOCAL5: return "local5";
	case LOG_LOCAL6: return "local6";
	case LOG_LOCAL7: return "local7";
	default:
		return "NOTSET";
	}
}

/*
 * converts a literal priority to an int
 */
static inline int lcr_log_priority_to_int(const char *name)
{
	if (!strcasecmp("TRACE",  name)) return LCR_LOG_PRIORITY_TRACE;
	if (!strcasecmp("DEBUG",  name)) return LCR_LOG_PRIORITY_DEBUG;
	if (!strcasecmp("INFO",   name)) return LCR_LOG_PRIORITY_INFO;
	if (!strcasecmp("NOTICE", name)) return LCR_LOG_PRIORITY_NOTICE;
	if (!strcasecmp("WARN",   name)) return LCR_LOG_PRIORITY_WARN;
	if (!strcasecmp("ERROR",  name)) return LCR_LOG_PRIORITY_ERROR;
	if (!strcasecmp("CRIT",   name)) return LCR_LOG_PRIORITY_CRIT;
	if (!strcasecmp("ALERT",  name)) return LCR_LOG_PRIORITY_ALERT;
	if (!strcasecmp("FATAL",  name)) return LCR_LOG_PRIORITY_FATAL;

	return LCR_LOG_PRIORITY_NOTSET;
}

static inline int lcr_syslog_priority_to_int(const char *name)
{
	if (!strcasecmp("daemon", name)) return LOG_DAEMON;
	if (!strcasecmp("local0", name)) return LOG_LOCAL0;
	if (!strcasecmp("local1", name)) return LOG_LOCAL1;
	if (!strcasecmp("local2", name)) return LOG_LOCAL2;
	if (!strcasecmp("local3", name)) return LOG_LOCAL3;
	if (!strcasecmp("local4", name)) return LOG_LOCAL4;
	if (!strcasecmp("local5", name)) return LOG_LOCAL5;
	if (!strcasecmp("local6", name)) return LOG_LOCAL6;
	if (!strcasecmp("local7", name)) return LOG_LOCAL7;

	return -EINVAL;
}

static inline void
__lcr_log_append(const struct lcr_log_appender	*appender,
		struct lcr_log_event	*event)
{
	va_list	va, *va_keep;
	va_keep = event->vap;

	while (appender) {
		va_copy(va, *va_keep);
		event->vap = &va;
		appender->append(appender, event);
		appender = appender->next;
		va_end(va);
	}
}

static inline void
__lcr_log(const struct lcr_log_category *category,
	struct lcr_log_event	*event)
{
	while (category) {
		__lcr_log_append(category->appender, event);
		category = category->parent;
	}
}


/*
 * Helper macro to define log functions
 */
#define lcr_log_priority_define(acategory, PRIORITY)			\
ATTR_UNUSED static inline void LCR_##PRIORITY(struct lcr_log_locinfo *,	\
	const char *, ...) __attribute__ ((format (printf, 2, 3)));	\
									\
ATTR_UNUSED static inline void LCR_##PRIORITY(struct lcr_log_locinfo *locinfo,\
	const char *format, ...)					\
{									\
	if (lcr_log_priority_is_enable(acategory,			\
				LCR_LOG_PRIORITY_##PRIORITY)) {		\
		struct lcr_log_event evt = {				\
			.category	= (acategory)->name,		\
			.priority	= LCR_LOG_PRIORITY_##PRIORITY,	\
			.fmt		= format,			\
			.locinfo	= locinfo			\
		};							\
		va_list	va_ref;						\
									\
		clock_gettime(CLOCK_REALTIME, &evt.timestamp);		\
									\
		va_start(va_ref, format);				\
		evt.vap = &va_ref;					\
		__lcr_log(acategory, &evt);				\
		va_end(va_ref);						\
	}								\
}


/*
 * Helper macro to define and use static categories.
 */
#define lcr_log_category_define(name, parent)				\
	extern struct lcr_log_category lcr_log_category_##parent;	\
	struct lcr_log_category	lcr_log_category_##name = {		\
		#name,							\
		LCR_LOG_PRIORITY_NOTSET,				\
		NULL,							\
		&lcr_log_category_##parent				\
	};

#define lcr_log_define(name, parent)					\
	lcr_log_category_define(name, parent)				\
									\
	lcr_log_priority_define(&lcr_log_category_##name, TRACE)	\
	lcr_log_priority_define(&lcr_log_category_##name, DEBUG)	\
	lcr_log_priority_define(&lcr_log_category_##name, INFO)		\
	lcr_log_priority_define(&lcr_log_category_##name, NOTICE)	\
	lcr_log_priority_define(&lcr_log_category_##name, WARN)		\
	lcr_log_priority_define(&lcr_log_category_##name, ERROR)	\
	lcr_log_priority_define(&lcr_log_category_##name, CRIT)		\
	lcr_log_priority_define(&lcr_log_category_##name, ALERT)	\
	lcr_log_priority_define(&lcr_log_category_##name, FATAL)	\

#define lcr_log_category_priority(name)					\
	(lcr_log_priority_to_string(lcr_log_catetory_##name,priority))

/*
 * Top categories
 */
#define TRACE(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_TRACE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define DEBUG(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_DEBUG(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define INFO(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_INFO(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define NOTICE(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_NOTICE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define WARN(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_WARN(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ERROR(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_ERROR(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define CRIT(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_CRIT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define ALERT(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_ALERT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define FATAL(format, ...) do {						\
	struct lcr_log_locinfo locinfo = LCR_LOG_LOCINFO_INIT;		\
	LCR_FATAL(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define	SYSERROR(format, ...) do {					\
	ERROR("%s - " format, strerror(errno), ##__VA_ARGS__);		\
} while (0)

extern int lcr_log_fd;
extern int lcr_log_init(const char *name, const char *file,
		const char *priority, const char *prefix, int quiet,
		const char *lcrpath);
extern void lcr_log_enable_syslog(void);
extern int lcr_log_syslog(int facility);
#endif /* __LCR_LOG_H */
