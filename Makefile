all: packet-stat

packet-stat: packet-stat-main.cpp packet-stat.cpp
	g++ -o $@ $^ -lpcap

clean:
	rm packet-stat