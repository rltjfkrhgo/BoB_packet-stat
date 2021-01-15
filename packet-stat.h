// packet-stat.h

#pragma once
#include <sys/types.h>

#include <libnet.h>
#include <map>

#include <stdio.h>

typedef struct libnet_ethernet_hdr EthHdr;
typedef struct libnet_ipv4_hdr     IpHdr;
typedef struct libnet_tcp_hdr      TcpHdr;
typedef struct libnet_udp_hdr      UdpHdr;

typedef struct
{
    int txPackets;
    int txBytes;
    int rxPackets;
    int rxBytes;
} Stat;

void func(const u_char* packet, u_int packet_size)
{
    static std::map<in_addr_t, Stat> map;

    IpHdr* ipPacket = (IpHdr*)(packet+LIBNET_ETH_H);

    printf("srcIp: %s\n", inet_ntoa(ipPacket->ip_src));
    printf("dstIp: %s\n", inet_ntoa(ipPacket->ip_dst));

    map[ipPacket->ip_src.s_addr].txPackets++;
    map[ipPacket->ip_src.s_addr].txBytes += packet_size;
    map[ipPacket->ip_dst.s_addr].rxPackets++;
    map[ipPacket->ip_dst.s_addr].rxBytes += packet_size;

    Stat* statptr = nullptr;
    for (auto it = map.begin(); it != map.end(); it++)
    {
        statptr = &(it->second);
        printf("%d\t%d\t%d\t%d\t%d\n", it->first,
        statptr->txPackets, statptr->txBytes, statptr->rxPackets, statptr->rxBytes);
    }
}