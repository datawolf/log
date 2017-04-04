#include <stdio.h>
#include <stdlib.h>

#include "log.h"

lcr_log_define(the_test_ui, lcr);

int main(int argc, char **argv) {
	int ret;
	ret = lcr_log_init("container one", "mylog.txt", "trace", "test-log", 0, "/var/lib/lcr");
	if (ret != 0)
		exit(ret);

	WARN("test1 = %d", argc);
	INFO("test1");
	DEBUG("test2");
	ERROR("test3");
	FATAL("TEST4");

	lcr_log_syslog(LOG_LOCAL0);
	lcr_log_enable_syslog();
	DEBUG("test2-syslog");
	ERROR("test3-syslog");
	FATAL("TEST4-syslog");

	return 0;
}
