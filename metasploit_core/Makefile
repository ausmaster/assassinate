# Makefile for Metasploit Core C Wrapper

CC = gcc
CFLAGS = -Wall -fPIC -shared -O2 -g
RUBY_CFLAGS = $(shell pkg-config --cflags ruby-3.2 || ruby -rrbconfig -e 'print RbConfig::CONFIG["CFLAGS"]')
RUBY_LDFLAGS = $(shell pkg-config --libs ruby-3.2 || ruby -rrbconfig -e 'print RbConfig::CONFIG["LDFLAGS"]')

TARGET = metasploit_core.so
SRC = metasploit_core.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "Using RUBY_CFLAGS: $(RUBY_CFLAGS)"
	@echo "Using RUBY_LDFLAGS: $(RUBY_LDFLAGS)"
	$(CC) $(CFLAGS) $(RUBY_CFLAGS) -o $(TARGET) $(SRC) $(RUBY_LDFLAGS)

clean:
	rm -f $(TARGET) *.o

install:
	install -D $(TARGET) /usr/local/lib/$(TARGET)
	install -D metasploit_core.h /usr/local/include/metasploit_core.h

uninstall:
	rm -f /usr/local/lib/$(TARGET)
	rm -f /usr/local/include/metasploit_core.h

.PHONY: all clean install uninstall
