CC = gcc
CFLAGS = -Wall -fPIC -shared
TARGET = metasploit_core.so
SRC = metasploit_core.c
INCLUDES = -I.

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean
