CFLAGS=-Wall -Wextra -Werror -g

prog: prog.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean::
	rm -f prog
