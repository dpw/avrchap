#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <linux/spi/spidev.h>

static void die(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
	putc('\n', stderr);
        exit(1);
}

static void die_errno(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);

        fprintf(stderr, ": %s\n", strerror(errno));
        exit(1);
}

static void write_file(const char *path, int ignore_ebusy,
		       const char *fmt, ...)
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
	if (res < 0 && !(errno == EBUSY  && ignore_ebusy))
		goto err;

	action = "closing";
	if (fclose(fp) && !(errno == EBUSY && ignore_ebusy))
		goto err;

	return;

 err:
	die_errno("%s \"%s\"", action, path);
}

static void unexport(void)
{
	write_file("/sys/class/gpio/unexport", 0, "%d\n", 8);
}

static int init_spidev(void)
{
	const char path[] = "/dev/spidev0.0";
	int fd;
	uint8_t b;
	uint32_t speed;

	fd = open(path, O_RDWR);
	if (fd < 0)
		die_errno("opening \"%s\"", path);

	/* SCK idle low, sample on leading edge */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_MODE, &b) < 0)
		die_errno("Setting SPI mode");

	/* MSB first */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_LSB_FIRST, &b) < 0)
		die_errno("Setting SPI LSB-first");

	/* 8 bits per word */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &b) < 0)
		die_errno("Setting SPI bits-per-word");

	/* ATMEGAs ship with 1MHz CPU clock, SCK period should be at
	   least 4 CPU cycles, hence 200kHz */
	speed = 200000;
	if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0)
		die_errno("Setting SPI speed");

	return fd;
}

static void do_instruction(int fd, uint8_t tx[4], uint8_t rx[4])
{
	struct spi_ioc_transfer xfer;
	int res;

	memset(&xfer, 0, sizeof xfer);
	xfer.tx_buf = (uintptr_t)tx;
	xfer.rx_buf = (uintptr_t)rx;
	xfer.len = 4;

	res = ioctl(fd, SPI_IOC_MESSAGE(1), &xfer);
	if (res < 0)
		die_errno("SPI_IOC_MESSAGE");

	if (res < 4)
		die("short response from SPI_IOC_MESSAGE");
}

static void read_signature(int fd, uint8_t sig[4])
{
	uint8_t tx[4], rx[4];
	uint8_t i;

	tx[0] = 0x30;
	tx[1] = tx[2] = tx[3] = 0;

	for (i = 0; i < 4; i++) {
		tx[2] = i;
		do_instruction(fd, tx, rx);
		sig[i] = rx[3];
	}
}

int main(int argc, char **argv)
{
	int spidev;
	uint8_t tx[4], rx[4];

	(void)argc;
	(void)argv;

	spidev = init_spidev();

	write_file("/sys/class/gpio/export", 1, "8\n");
	atexit(unexport);
	write_file("/sys/class/gpio/gpio8/direction", 0, "out\n");

	/* Positive pulse on RESETn */
	write_file("/sys/class/gpio/gpio8/value", 0, "1\n");
	usleep(1000);
	write_file("/sys/class/gpio/gpio8/value", 0, "0\n");

	/* Wait at least 20ms with RESETn low. */
	usleep(25000);

	/* Try "Programming Enable" */
	tx[0] = 0xAC;
	tx[1] = 0x53;
	tx[2] = tx[3] = 0;
	do_instruction(spidev, tx, rx);
	if (rx[2] != 0x53)
		fprintf(stderr,
			"Unacknowledged 'Programming Enable' instruction "
			"(%02x %02x %02x %02x)\n",
			rx[0], rx[1], rx[2], rx[3]);

	read_signature(spidev, rx);
	fprintf(stderr, "Signature: %02x %02x %02x %02x\n",
		rx[0], rx[1], rx[2], rx[3]);

	close(spidev);
	return 0;
}


