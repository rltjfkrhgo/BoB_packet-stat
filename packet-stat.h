// packet-stat.h

#ifndef _PACKET_STAT_H_
#define _PACKET_STAT_H_

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
    int  txPackets;
    int  txBytes;
    int  rxPackets;
    int  rxBytes;
} Stat;

class L2Key
{
public:
    u_int8_t  mac[ETHER_ADDR_LEN];

    bool operator<(const L2Key& rhs) const
    {
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
        {
            if(mac[i] != rhs.mac[i])
                return mac[i] < rhs.mac[i];
        }
        return mac[ETHER_ADDR_LEN-1] < rhs.mac[ETHER_ADDR_LEN-1];
    }

    void setMac(u_int8_t* _mac)
    {
        for(int i = 0; i < ETHER_ADDR_LEN; i++)
            mac[i] = _mac[i];
    }

    void printMac() const
    {
        int i = 0;
        for(i = 0; i < ETHER_ADDR_LEN-1; i++)
            printf("%02x:", mac[i]);
        printf("%02x", mac[i]);
    }
};

class L4Key
{
public:
    in_addr_t  ip;
    u_int16_t  port;

    bool operator<(const L4Key& rhs) const
    {
        if(ip == rhs.ip)
            return port < rhs.port;
        
        return ip < rhs.ip;
    }
};

static std::map<L2Key, Stat>     ethMap;
static std::map<in_addr_t, Stat>  ipMap;
static std::map<L4Key, Stat>     tcpMap;
static std::map<L4Key, Stat>     udpMap;

void StatPacket(const u_char* packet, u_int packet_size);
void PrintStat();

#endif