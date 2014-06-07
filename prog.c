#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void die_errno(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);

        fprintf(stderr, ": %s\n", strerror(errno));
        exit(1);
}

static void write_file(const char *path, const char *fmt, ...)
{
        va_list ap;
	int res;
	const char *action = "opening";
	FILE *fp = fopen(path, "w");
	if (!fp)
		goto err;

	action = "writing to";
        va_start(ap, fmt);
        res = vfprintf(fp, fmt, ap);
        va_end(ap);
	if (res < 0)
		goto err;

	action = "closing";
	if (fclose(fp))
		goto err;

	return;

 err:
	die_errno("%s \"%s\"", action, path);
}

static void unexport(void)
{
	write_file("/sys/class/gpio/unexport", "%d\n", 8);
}

int main(int argc, char **argv)
{
	int i = 0;

	(void)argc;
	(void)argv;

	write_file("/sys/class/gpio/export", "8\n");
	atexit(unexport);
	write_file("/sys/class/gpio/gpio8/direction", "out\n");

	for (i = 0; i < 10; i++) {
		write_file("/sys/class/gpio/gpio8/value", "1\n");
		sleep(1);
		write_file("/sys/class/gpio/gpio8/value", "0\n");
		sleep(1);
	}

	return 0;
}


