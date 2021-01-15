CC=g++
CFLAGS=-c
LDFLAGS=-lpcap
SOURCES=packet-stat-main.cpp packet-stat.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=packet-stat

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o $(EXECUTABLE)