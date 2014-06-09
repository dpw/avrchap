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

static int gpio_init(void)
{
	if (!write_file("/sys/class/gpio/export", 1, "8\n"))
		return 0;

	atexit(unexport);

	if (!write_file("/sys/class/gpio/gpio8/direction", 0, "out\n"))
		return 0;

	return 1;
}

static int resetn_low(void)
{
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

static int do_instruction(int fd, uint8_t tx[4], uint8_t rx[4])
{
	struct spi_ioc_transfer xfer;
	int res;

	memset(&xfer, 0, sizeof xfer);
	xfer.tx_buf = (uintptr_t)tx;
	xfer.rx_buf = (uintptr_t)rx;
	xfer.len = 4;

	res = ioctl(fd, SPI_IOC_MESSAGE(1), &xfer);
	if (res == 4)
		return 1;

	if (res < 0)
		print_errno("SPI_IOC_MESSAGE");
	else
		print_err("short response from SPI_IOC_MESSAGE");

	return 0;
}

static int enable_programming(int spidev)
{
	uint8_t tx[4], rx[4];

	if (!resetn_low())
		return 0;

	/* Try "Programming Enable" */
	tx[0] = 0xac;
	tx[1] = 0x53;
	tx[2] = tx[3] = 0;
	if (!do_instruction(spidev, tx, rx))
		return 0;

	if (rx[2] == 0x53)
		return 1;

	fprintf(stderr,
		"Unacknowledged 'Programming Enable' instruction "
		"(%02x %02x %02x %02x)\n",
		rx[0], rx[1], rx[2], rx[3]);
	return 0;
}

static int read_signature(int fd, uint8_t sig[4])
{
	uint8_t tx[4], rx[4];
	uint8_t i;

	tx[0] = 0x30;
	tx[1] = tx[2] = tx[3] = 0;

	for (i = 0; i < 4; i++) {
		tx[2] = i;
		if (!do_instruction(fd, tx, rx))
			return 0;

		sig[i] = rx[3];
	}

	return 1;
}

static int hex_digit(unsigned char c, const char *path)
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

	print_err("bad hex digit '%c' in \"%s\"", c, path);
	return -1;
}

static int hex_byte(const char *s, const char *path)
{
	int hi, lo;

	hi = hex_digit(s[0], path);
	if (hi < 0)
		return -1;

	lo = hex_digit(s[1], path);
	if (lo < 0)
		return -1;

	return hi << 4 | lo;
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
	int count, b, type, addr;
	uint8_t csum;
	int next_addr = -1;
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
		if (count < 0)
			goto err_close;

		msg = "truncated line";
		if (l < count * 2 + (size_t)11)
			goto err_format;

		msg = "excess characters";
		if (!trailing_whitespace(buf + count * 2 + 11))
			goto err_format;

		csum = count;

		b = hex_byte(p += 2, path);
		if (b < 0)
			goto err_close;

		addr = hex_byte(p += 2, path);
		if (addr < 0)
			goto err_close;

		csum += b + addr;
		addr |= (uint16_t)b << 8;

		type = hex_byte(p += 2, path);
		if (type < 0)
			goto err_close;

		csum += type;
		if (type == 0) {
			/* Data record */
			if (next_addr == -1) {
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
				if (b < 0)
					goto err_close;

				*data++ = b;
				csum += b;
			}
		}
		else {
			while (count--) {
				b = hex_byte(p += 2, path);
				if (b < 0)
					goto err_close;

				csum += b;
			}
		}

		b = hex_byte(p += 2, path);
		if (b < 0)
			goto err_close;

		msg = "checksum incorrect";
		if ((uint8_t)-csum != b)
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

static int load_page(int spidev, uint8_t *data, unsigned int len)
{
	unsigned int i = 0;
	uint8_t tx[4], rx[4];

	tx[1] = 0;

	while (len) {
		/* program data holds little-endian words */
		tx[0] = 0x40;
		tx[2] = i++;
		tx[3] = *data++;
		if (!do_instruction(spidev, tx, rx))
			return 0;

		tx[0] = 0x48;
		tx[3] = *data++;
		if (!do_instruction(spidev, tx, rx))
			return 0;

		len -= 2;
	}

	return 1;
}

static int write_program_page(int spidev, unsigned int addr)
{
	uint8_t tx[4], rx[4];
	int i;

	/* addr is in bytes, so need to divide by 2 */
	tx[0] = 0x4c;
	tx[1] = addr >> 9;
	tx[2] = addr >> 1;
	tx[3] = 0;

	if (!do_instruction(spidev, tx, rx))
		return 0;

	/* Wait until the Flash write is completed. */
	tx[0] = 0xf0;
	tx[1] = tx[2] = tx[3] = 0;

	for (i = 0; i < 100; i++) {
		usleep(1000);

		if (!do_instruction(spidev, tx, rx))
			return 0;

		if (!(rx[3] & 1))
			return 1;
	}

	print_err("Time out waiting for program memory page write to complete");
	return 0;
}

static int write_program(int spidev, struct hex *hex)
{
	const unsigned int page_len = 128;
	unsigned int addr, len;
	uint8_t *data;

	data = hex->data;
	len = hex->len;
	if (len & 1) {
		print_err("Program is not a whole number of words");
		return 0;
	}

	addr = hex->origin;
	if (addr & (page_len - 1)) {
		print_err("Program does not start on page boundary");
		return 0;
	}

	fprintf(stderr, "Writing program: ");

	while (len >= page_len) {
		if (!load_page(spidev, data, page_len)
		    || !write_program_page(spidev, addr))
			return 0;

		putc('.', stderr);
		data += page_len;
		len -= page_len;
		addr += page_len;
	}

	if (len) {
		if (!load_page(spidev, data, len)
		    || !write_program_page(spidev, addr))
			return 0;

		putc('.', stderr);
	}

	putc('\n', stderr);
	return 1;
}

static int verify_program(int spidev, struct hex *hex)
{
	unsigned int addr, len;
	uint8_t *data;
	uint8_t tx[4], rx[4];

	data = hex->data;
	len = hex->len;
	if (len & 1) {
		print_err("Program is not a whole number of words");
		return 0;
	}

	addr = hex->origin;

	fprintf(stderr, "Verifying program: ");

	while (len) {
		if (!(len & 127))
			putc('.', stderr);

		tx[0] = 0x20;
		tx[1] = addr >> 9;
		tx[2] = addr >> 1;
		tx[3] = 0;
		if (!do_instruction(spidev, tx, rx))
			return 0;

		if (rx[3] != *data)
			goto mismatch;

		data++;
		addr++;
		tx[0] = 0x28;
		if (!do_instruction(spidev, tx, rx))
			return 0;

		if (rx[3] != *data)
			goto mismatch;

		data++;
		addr++;
		len -= 2;
	}

	putc('\n', stderr);
	return 1;

 mismatch:
	print_err("\nVerification error: Expected %x, got %x at address %x",
		  *data, rx[3], addr);
	return 0;
}

static int write_config_byte(int spidev, const char *name,
			     uint8_t wr0, uint8_t wr1,
			     uint8_t rd0, uint8_t rd1, uint8_t val)
{
	uint8_t tx[4], rx[4];

	tx[0] = rd0;
	tx[1] = rd1;
	tx[2] = tx[3] = 0;
	if (!do_instruction(spidev, tx, rx))
		return 0;

	if (rx[3] == val) {
		fprintf(stderr, "Not writing %s; already set to 0x%x\n",
			name, val);
		return 1;
	}

	tx[0] = wr0;
	tx[1] = wr1;
	tx[2] = 0;
	tx[3] = val;
	if (!do_instruction(spidev, tx, rx))
		return 0;

	fprintf(stderr, "Set %s to 0x%x; verifying... ", name, val);

	/* Bits are latched during programming mode */
	if (!enable_programming(spidev))
		return 0;

	tx[0] = rd0;
	tx[1] = rd1;
	tx[2] = tx[3] = 0;
	if (!do_instruction(spidev, tx, rx))
		return 0;

	if (rx[3] == val) {
		fprintf(stderr, "ok\n");
		return 1;
	}
	else {
		fprintf(stderr, "mismatch (got 0x%x)\n", rx[3]);
		return 0;
	}
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [ -p <hex file> ]\n", name);
}

static int safe_atob(const char *s)
{
	char *endptr;
	long res = strtol(s, &endptr, 0);
	if (res >= 0 && res <= 255 && !*endptr)
		return res;

	print_err("bad byte value \"%s\"", s);
	return -1;
}

int main(int argc, char **argv)
{
	int spidev;
	struct hex hex;
	uint8_t sig[4];
	int c;
	int lock_bits = -1;
	int fuse_bits = -1;
	int high_fuse_bits = -1;
	int ext_fuse_bits = -1;

	hex.data = NULL;

	while ((c = getopt(argc, argv, "p:F:H:E:L:")) != -1) {
		switch (c) {
		case 'p':
			if (hex.data) {
				print_err("Can only use the -p option once");
				goto err;
			}

			if (!read_hex(optarg, &hex))
				goto err;

			break;

		case 'F':
			fuse_bits = safe_atob(optarg);
			if (fuse_bits < 0)
				goto err;

			break;

		case 'H':
			high_fuse_bits = safe_atob(optarg);
			if (high_fuse_bits < 0)
				goto err;

			break;

		case 'E':
			ext_fuse_bits = safe_atob(optarg);
			if (ext_fuse_bits < 0)
				goto err;

			break;

		case 'L':
			lock_bits = safe_atob(optarg);
			if (lock_bits < 0)
				goto err;

			break;
		}
	}

	if (optind != argc) {
		usage(argv[0]);
		goto err;
	}

	spidev = init_spidev();
	if (spidev < 0)
		goto err;

	if (!gpio_init()
	    || !enable_programming(spidev))
		goto err_close_spidev;

	if (!read_signature(spidev, sig))
		goto err_close_spidev;

	fprintf(stderr, "Signature: %02x %02x %02x %02x\n",
		sig[0], sig[1], sig[2], sig[3]);

	if (hex.data) {
		if (!write_program(spidev, &hex)
		    || !verify_program(spidev, &hex))
			goto err_close_spidev;
	}

	if (fuse_bits >= 0
	    && !write_config_byte(spidev, "fuse bits",
				  0xac, 0xa0, 0x50, 0, fuse_bits))
		goto err_close_spidev;

	if (high_fuse_bits >= 0
	    && !write_config_byte(spidev, "high fuse bits",
				  0xac, 0xa8, 0x58, 0x08, high_fuse_bits))
		goto err_close_spidev;

	if (ext_fuse_bits >= 0
	    && !write_config_byte(spidev, "extended fuse bits",
				  0xac, 0xa4, 0x50, 0x08, ext_fuse_bits | 0xf8))
		goto err_close_spidev;

	if (lock_bits >= 0
	    && !write_config_byte(spidev, "lock bits",
				  0xac, 0xe0, 0x58, 0, lock_bits | 0xc0))
		goto err_close_spidev;

	close(spidev);
	return 0;

 err_close_spidev:
	close(spidev);
 err:
	free(hex.data);
	return 1;
}


