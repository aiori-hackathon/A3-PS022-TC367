CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE

TARGET = kavach_gen
SRC = kavach_gen.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean

