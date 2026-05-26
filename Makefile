CC = cc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -O2
TARGET = gitward
SRCS = main.c scan.c clue.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c gitward.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/$(TARGET)

.PHONY: all clean install
