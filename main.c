#include <stdio.h>
#include <stdlib.h>

#include "log.h"

// Define the category
// @param1: the category name
// @param2: must be `lcr`
lcr_log_define(the_test_ui, lcr);

int main(int argc, char **argv) {
	int ret;

	/**
	 * lcr_log_init: initalize teh defaults
	 * @param1: the container name(Can be NULL)
	 * @param2: the log file(eg: `/tmp/log.txt` or `mylog.txt`)
	 * @param3: the log priority
	 * @param4: the prefix string: usually set to sub-command name
	 * @param5: whether to output to stderr, 0 for enable, 1 for disable
	 * @param6: the log path, if the `param2` is NULL, we output the log to `$param6/$param1/$param1.log`
	 **/

	/**
	 * Out put the log to mylog.txt in current directory
	 **/
	// ret = lcr_log_init("container-one", "mylog.txt", "trace", "test-log", 0, "/var/log/lcr");

	/**
	 * Out put the log to `/var/log/lcr/container-one/container-one.log`
	 **/
	//ret = lcr_log_init("container-one", NULL, "trace", "test-log", 0, "/var/log/lcr");

	/**
	 * Out put the log to `/tmp/log.txt`
	 **/
	ret = lcr_log_init("container-one", "/tmp/log.txt", "trace", "test-log", 0, "/var/log/lcr");
	if (ret != 0)
		exit(ret);
	TRACE("TRACE");
	DEBUG("DEBUG");
	INFO("INFO");
	NOTICE("NOTICE");
	WARN("WARN = %d", argc);
	ERROR("ERROR");
	CRIT("CRIT");
	FATAL("FATAL");
	ALERT("ALERT");

	lcr_log_syslog(LOG_LOCAL0);
	lcr_log_enable_syslog();
	TRACE("trace-syslog");
	DEBUG("debug-syslog");
	INFO("info-syslog");
	NOTICE("notice-syslog");
	WARN("warn-syslog");
	ERROR("error-syslog");
	CRIT("crit-syslog");
	FATAL("fatal-syslog");
	ALERT("alert-syslog");

	return 0;
}
