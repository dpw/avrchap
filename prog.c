#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <linux/spi/spidev.h>

static void die(const char *fmt, ...)
	__attribute__ ((noreturn,format (printf, 1, 2)));
static void die_errno(const char *fmt, ...)
	__attribute__ ((noreturn,format (printf, 1, 2)));

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

static void die_alloc()
{
	fprintf(stderr, "failed to allocate memory\n");
	exit(1);
}

static void print_errno(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static void print_errno(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);

        fprintf(stderr, ": %s\n", strerror(errno));
}

static void print_err(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static void print_err(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);

	putc('\n', stderr);
}

static int write_file(const char *path, int ignore_ebusy,
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
		goto err_close;

	action = "closing";
	if (fclose(fp) && !(errno == EBUSY && ignore_ebusy))
		goto err;

	return 1;

 err_close:
	fclose(fp);
 err:
	fprintf(stderr, "%s \"%s\"\n", action, path);
	return 0;
}

static void unexport(void)
{
	write_file("/sys/class/gpio/unexport", 0, "%d\n", 8);
}

static int resetn_low(void)
{
	if (!write_file("/sys/class/gpio/export", 1, "8\n"))
		goto err;

	atexit(unexport);

	if (!write_file("/sys/class/gpio/gpio8/direction", 0, "out\n"))
		goto err;

	/* Positive pulse on RESETn */
	if (!write_file("/sys/class/gpio/gpio8/value", 0, "1\n"))
		goto err;

	usleep(1000);

	if (!write_file("/sys/class/gpio/gpio8/value", 0, "0\n"))
		goto err;

	/* Wait at least 20ms with RESETn low before programming. */
	usleep(25000);
	return 1;

 err:
	return 0;
}

static int init_spidev(void)
{
	const char path[] = "/dev/spidev0.0";
	int fd;
	uint8_t b;
	uint32_t speed;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		print_errno("opening \"%s\"", path);
		goto err;
	}

	/* SCK idle low, sample on leading edge */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_MODE, &b) < 0) {
		print_errno("Setting SPI mode");
		goto err_close;
	}

	/* MSB first */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_LSB_FIRST, &b) < 0) {
		print_errno("Setting SPI LSB-first");
		goto err_close;
	}

	/* 8 bits per word */
	b = 0;
	if (ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &b) < 0) {
		print_errno("Setting SPI bits-per-word");
		goto err_close;
	}

	/* ATMEGAs ship with 1MHz CPU clock, SCK period should be at
	   least 4 CPU cycles, hence 200kHz */
	speed = 200000;
	if (ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
		print_errno("Setting SPI speed");
		goto err_close;
	}

	return fd;

 err_close:
	close(fd);
 err:
	return -1;
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

static unsigned int hex_digit(unsigned char c, const char *path)
{
	if (c <= '9') {
		if (c >= '0')
			return c - '0';
	}
	else {
		unsigned char uc = c & ~32U;
		if (uc >= 'A' && uc <= 'F')
			return uc - 'A' + 10;
	}

	die("bad hex digit '%c' in \"%s\"", c, path);
}

static uint8_t hex_byte(const char *s, const char *path)
{
	return hex_digit(s[0], path) << 4 | hex_digit(s[1], path);
}

static int trailing_whitespace(const char *s)
{
	for (;;) {
		char c = *s++;
		if (c == 0)
			return 1;

		if (!isspace(c))
			return 0;
	}
}

struct hex {
	unsigned int origin;
	unsigned int len;
	size_t capacity;
	uint8_t *data;
};

static uint8_t *grow_hex(struct hex *hex, unsigned int len)
{
	uint8_t *data;

	if (hex->len + len > hex->capacity) {
		do {
			hex->capacity *= 2;
		} while (hex->len + len > hex->capacity);

		hex->data = realloc(hex->data, hex->capacity);
		if (!hex->data)
			die_alloc();
	}

	data = hex->data + hex->len;
	hex->len += len;
	return data;
}

static int read_hex(const char *path, struct hex *hex)
{
	const int buf_size = 512 + 11 + 10;
	char buf[buf_size];
	int line = 1;
	char *p;
	uint8_t *data;
	size_t l;
	uint8_t count, b, csum, type;
	uint16_t addr;
	unsigned int next_addr = -1;
	const char *msg;
	FILE *fp = fopen(path, "r");

	if (!fp) {
		print_errno("%s", path);
		goto err;
	}

	hex->origin = hex->len = 0;
	hex->capacity = 512;
	hex->data = malloc(hex->capacity);
	if (!hex->data)
		die_alloc();

	for (;;) {
		if (feof(fp)) {
			print_err("%s: missing EOF record", path);
			goto err_close;
		}

		if (!fgets(buf, buf_size, fp) && ferror(fp)) {
			print_errno("%s", path);
			goto err_close;
		}

		l = strlen(buf);
		msg = "truncated line";
		if (l < 11)
			goto err_format;

		p = buf;
		msg = "line does not start with ':'";
		if (*p != ':')
			goto err_format;

		count = hex_byte(p += 1, path);
		msg = "truncated line";
		if (l < count * 2 + (size_t)11)
			goto err_format;

		msg = "excess characters";
		if (!trailing_whitespace(buf + count * 2 + 11))
			goto err_format;

		csum = count;

		b = hex_byte(p += 2, path);
		addr = hex_byte(p += 2, path);
		csum += b + addr;
		addr |= (uint16_t)b << 8;

		type = hex_byte(p += 2, path);
		csum += type;
		if (type == 0) {
			/* Data record */
			if (next_addr == (unsigned)-1) {
				hex->origin = addr;
			}
			else if (addr != next_addr) {
				msg = "decreasing address";
				if (addr < next_addr)
					goto err_format;

				memset(grow_hex(hex, addr - next_addr),
				       0, addr - next_addr);
			}

			next_addr = addr + count;
			data = grow_hex(hex, count);
			while (count--) {
				b = hex_byte(p += 2, path);
				*data++ = b;
				csum += b;
			}
		}
		else {
			while (count--)
				csum += hex_byte(p += 2, path);
		}

		msg = "checksum incorrect";
		if ((uint8_t)-csum != hex_byte(p += 2, path))
			goto err_format;

		if (type == 1)
			/* EOF record */
			break;

		/* ignore other record types */
		line++;
	}

	if (fclose(fp)) {
		print_errno("closing \"%s\"", path);
		goto err;
	}

	return 1;

 err_format:
	print_err("%s:%d: %s", path, line, msg);
 err_close:
	fclose(fp);
 err:
	return 0;
}

static void load_page(int spidev, uint8_t *data, unsigned int len)
{
	unsigned int i = 0;
	uint8_t tx[4], rx[4];

	tx[1] = 0;

	while (len) {
		/* program data holds little-endian words */
		tx[0] = 0x40;
		tx[2] = i++;
		tx[3] = *data++;
		do_instruction(spidev, tx, rx);

		tx[0] = 0x48;
		tx[3] = *data++;
		do_instruction(spidev, tx, rx);

		len -= 2;
	}
}

static void write_program_page(int spidev, unsigned int addr)
{
	uint8_t tx[4], rx[4];
	int i;

	/* addr is in bytes, so need to divide by 2 */
	tx[0] = 0x4c;
	tx[1] = addr >> 9;
	tx[2] = addr >> 1;
	tx[3] = 0;

	do_instruction(spidev, tx, rx);

	/* Wait until the Flash write is completed. */
	tx[0] = 0xf0;
	tx[1] = tx[2] = tx[3] = 0;

	for (i = 0; i < 100; i++) {
		usleep(1000);
		do_instruction(spidev, tx, rx);
		if (!(rx[3] & 1))
			return;
	}

	die("Timed out waiting for program memory page write to complete");
}

static void write_program(int spidev, struct hex *hex)
{
	const unsigned int page_len = 128;
	unsigned int addr, len;
	uint8_t *data;

	data = hex->data;
	len = hex->len;
	if (len & 1)
		die("Program is not a whole number of words");

	addr = hex->origin;
	if (addr & (page_len - 1))
		die("Program does not start on page boundary");

	fprintf(stderr, "Writing program: ");

	while (len >= page_len) {
		load_page(spidev, data, page_len);
		write_program_page(spidev, addr);
		putc('.', stderr);
		data += page_len;
		len -= page_len;
		addr += page_len;
	}

	if (len) {
		load_page(spidev, data, len);
		write_program_page(spidev, addr);
		putc('.', stderr);
	}

	putc('\n', stderr);
}

static void verify_program(int spidev, struct hex *hex)
{
	unsigned int addr, len;
	uint8_t *data;
	uint8_t tx[4], rx[4];

	data = hex->data;
	len = hex->len;
	if (len & 1)
		die("Program is not a whole number of words");

	addr = hex->origin;

	fprintf(stderr, "Verifying program: ");

	while (len) {
		if (!(len & 127))
			putc('.', stderr);

		tx[0] = 0x20;
		tx[1] = addr >> 9;
		tx[2] = addr >> 1;
		tx[3] = 0;
		do_instruction(spidev, tx, rx);
		if (rx[3] != *data)
			goto mismatch;

		data++;
		addr++;
		tx[0] = 0x28;
		do_instruction(spidev, tx, rx);
		if (rx[3] != *data)
			goto mismatch;

		data++;
		addr++;
		len -= 2;
	}

	putc('\n', stderr);
	return;

 mismatch:
	die("\nVerification error: Expected %x, got %x at address %x",
	    *data, rx[3], addr);
}

int main(int argc, char **argv)
{
	int spidev = 0;
	struct hex hex;
	uint8_t tx[4], rx[4];

	hex.data = NULL;

	if (argc != 2) {
		print_err("usage: %s <hex file>", argv[0]);
		goto err;
	}

	if (!read_hex(argv[1], &hex))
		goto err;

	spidev = init_spidev();
	if (spidev < 0)
		goto err;

	if (!resetn_low())
		goto err_close_spidev;

	/* Try "Programming Enable" */
	tx[0] = 0xac;
	tx[1] = 0x53;
	tx[2] = tx[3] = 0;
	do_instruction(spidev, tx, rx);
	if (rx[2] != 0x53) {
		fprintf(stderr,
			"Unacknowledged 'Programming Enable' instruction "
			"(%02x %02x %02x %02x)\n",
			rx[0], rx[1], rx[2], rx[3]);
		goto err_close_spidev;
	}

	read_signature(spidev, rx);
	fprintf(stderr, "Signature: %02x %02x %02x %02x\n",
		rx[0], rx[1], rx[2], rx[3]);

	write_program(spidev, &hex);
	verify_program(spidev, &hex);
	close(spidev);
	return 0;

 err_close_spidev:
	close(spidev);
 err:
	free(hex.data);
	return 1;
}


