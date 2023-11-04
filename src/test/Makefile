CC = gcc
CFLAGS = -Wall -Wimplicit-function-declaration -I../netguard/include

SRC = test_tls.c stubs.c ../netguard/tls_parser.c
OBJ = $(SRC:.c=.o)
EXECUTABLE = test_tls

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXECUTABLE)

