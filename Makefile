CFLAGS=-Wall -Wextra -Werror -g

avrchap: avrchap.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean::
	rm -f prog
