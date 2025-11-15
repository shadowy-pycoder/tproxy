TARGET = tproxy
CC = gcc
CFLAGS = -g -Wall -Wextra -Werror -Os -std=c2x -march=native
CPPFLAGS=
SERVER_HOST =  0.0.0.0
SERVER_PORT = 8888

.PHONY: default all clean run stop

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) $(CPPFLAGS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	sudo ./scripts/set_iptables_rules.sh $(SERVER_PORT)
	sudo ./$(TARGET) $(SERVER_HOST) $(SERVER_PORT)

stop:
	sudo ./scripts/clear_iptables_rules.sh

