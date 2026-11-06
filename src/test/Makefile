CC = gcc
CFLAGS = -Wall -Wimplicit-function-declaration -I../netguard/include
SANITIZERS = -fsanitize=address,undefined -fno-omit-frame-pointer -g

# Override to run the split and fuzz tests against another parser version, e.g. make test_tls_split TLS_PARSER=/path/to/tls_parser.c
TLS_PARSER ?= ../netguard/tls_parser.c

SRC = test_tls.c stubs.c ../netguard/tls_parser.c
OBJ = $(SRC:.c=.o)
EXECUTABLE = test_tls
SPLIT_EXECUTABLE = test_tls_split
FUZZ_EXECUTABLE = test_tls_fuzz

all: $(EXECUTABLE) $(SPLIT_EXECUTABLE) $(FUZZ_EXECUTABLE)

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

# Built from sources (not the shared objects) so the parser is instrumented by the sanitizers
$(SPLIT_EXECUTABLE): test_tls_split.c client_hellos.h stubs.c $(TLS_PARSER)
	$(CC) $(CFLAGS) $(SANITIZERS) test_tls_split.c stubs.c $(TLS_PARSER) -o $@ $(LDFLAGS)

$(FUZZ_EXECUTABLE): test_tls_fuzz.c client_hellos.h stubs.c $(TLS_PARSER)
	$(CC) $(CFLAGS) $(SANITIZERS) test_tls_fuzz.c stubs.c $(TLS_PARSER) -o $@ $(LDFLAGS)

# Not a dependency of the build on purpose: the fixtures depend on the local OpenSSL version
fixtures:
	python3 -I gen_client_hellos.py > client_hellos.h

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(EXECUTABLE) $(SPLIT_EXECUTABLE) $(FUZZ_EXECUTABLE) *.dSYM

.PHONY: all clean fixtures
