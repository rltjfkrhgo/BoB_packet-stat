// packet-stat-main.cpp

#include <pcap.h>
#include <stdio.h>
#include "packet-stat.h"

void usage() {
    printf("syntax: packet-stat <pcapfile>\n");
    printf("sample: packet-stat test.pcap\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(filename, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", filename, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);  // 패킷 수신
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        
        StatPacket(packet, header->caplen); 
    }

    pcap_close(handle);

    PrintStat();  // 정보 출력!!
}
