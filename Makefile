SHELL    = /bin/bash
PROG_BIN = zreap
TEST_BIN = zombie
TEST_PID = /tmp/ztest.pid
CC       = $(shell which clang)
CFLAGS   = -m64 -Wall -Werror -Wextra -pedantic -ggdb -O3
FMT      = $(shell which clang-format) -style='{IndentWidth: 4, TabWidth: 4}' -i
VALGRIND = valgrind --leak-check=full --show-leak-kinds=all
PS       = $(shell which ps)
XARGS    = $(shell which xargs)
PRINTF   = $(shell which printf)
SRC_DIR  = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))


build:
	@$(CC) $(CFLAGS) $(PROG_BIN).c -o $(PROG_BIN)

test: build
	@$(CC) $(CFLAGS) test/$(TEST_BIN).c -o test/$(TEST_BIN)
	@./test/ztest.sh "$(SRC_DIR)"


format:
	@$(FMT) *.c test/*.c

clean:
	@/bin/rm -rf *~ *.o $(PROG_BIN) test/$(TEST_BIN) $(TEST_PID)

.PHONY: build test format clean
