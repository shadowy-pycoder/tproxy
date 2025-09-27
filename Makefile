TARGET = tproxy
CC = gcc
CFLAGS = -g -Wall -Wextra

.PHONY: default all clean run

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

