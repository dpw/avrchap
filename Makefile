CFLAGS=-Wall -Wextra -Werror

prog: prog.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean::
	rm -f prog
