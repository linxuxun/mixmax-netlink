CC = gcc
CFLAGS = -Wall -O2 -lm
TARGET = netlink
SRC = netlink.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
