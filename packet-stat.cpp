// packet-stat.cpp

#include "packet-stat.h"

void StatPacket(const u_char* packet, u_int packet_size)
{
    int offset = 0;

    // ========== 이더넷 헤더 ==========

    EthHdr* ethPacket = (EthHdr*)(packet);
    
    Mac srcMac, dstMac;
    srcMac.setMac(ethPacket->ether_shost);
    dstMac.setMac(ethPacket->ether_dhost);

    ethMap[srcMac].txPackets++;
    ethMap[srcMac].txBytes += packet_size;
    ethMap[dstMac].rxPackets++;
    ethMap[dstMac].rxBytes += packet_size;

    if(ntohs(ethPacket->ether_type) != ETHERTYPE_IP)
        return;

    // ========== IP 헤더 ==========

    offset += LIBNET_ETH_H;
    IpHdr* ipPacket = (IpHdr*)(packet+offset);

    ipMap[ipPacket->ip_src.s_addr].txPackets++;
    ipMap[ipPacket->ip_src.s_addr].txBytes += packet_size;
    ipMap[ipPacket->ip_dst.s_addr].rxPackets++;
    ipMap[ipPacket->ip_dst.s_addr].rxBytes += packet_size;

    if(ipPacket->ip_p != 6 && 
       ipPacket->ip_p != 17)
       return;

    // TCP 이면
    if(ipPacket->ip_p == 6)
    {
        offset += ipPacket->ip_hl*4;
        TcpHdr* tcpPacket = (TcpHdr*)(packet+offset);

        L4Key src, dst;
        src.ip = ipPacket->ip_src.s_addr;
        src.port = tcpPacket->th_sport;
        dst.ip = ipPacket->ip_dst.s_addr;
        dst.port = tcpPacket->th_dport;

        tcpMap[src].txPackets++;
        tcpMap[src].txBytes += packet_size;
        tcpMap[dst].rxPackets++;
        tcpMap[dst].rxBytes += packet_size;
    }

    // UDP 이면
    if(ipPacket->ip_p == 17)
    {
        offset += ipPacket->ip_hl*4;
        UdpHdr* udpPacket = (UdpHdr*)(packet+offset);
        L4Key src, dst;
        src.ip = ipPacket->ip_src.s_addr;
        src.port = udpPacket->uh_sport;
        dst.ip = ipPacket->ip_dst.s_addr;
        dst.port = udpPacket->uh_dport;

        udpMap[src].txPackets++;
        udpMap[src].txBytes += packet_size;
        udpMap[dst].rxPackets++;
        udpMap[dst].rxBytes += packet_size;
    }
}

void PrintStat()
{
    Stat* statptr = nullptr;

    printf("\n========== Ethernet ==========\n");
    printf("Mac                Tx Packets  Tx Bytes  Rx Packets  Rx Bytes\n");
    for (auto it = ethMap.begin(); it != ethMap.end(); it++)
    {
        it->first.printMac();
        statptr = &(it->second);
        printf("  %10d  %8d  %10d  %8d\n",
        statptr->txPackets, statptr->txBytes, statptr->rxPackets, statptr->rxBytes);
    }

    printf("\n========== IP ==========\n");
    printf("IP\t\tTx Packets  Tx Bytes  Rx Packets  Rx Bytes\n");
    for (auto it = ipMap.begin(); it != ipMap.end(); it++)
    {
        struct in_addr ip = {it->first};
        statptr = &(it->second);
        printf("%s\t%10d  %8d  %10d  %8d\n", inet_ntoa(ip),
        statptr->txPackets, statptr->txBytes, statptr->rxPackets, statptr->rxBytes);
    }

    printf("\n========== TCP ==========\n");
    printf("IP\t\t Port  Tx Packets  Tx Bytes  Rx Packets  Rx Bytes\n");
    for (auto it = tcpMap.begin(); it != tcpMap.end(); it++)
    {
        struct in_addr ip = {it->first.ip};
        statptr = &(it->second);
        printf("%s\t%5d  %10d  %8d  %10d  %8d\n", inet_ntoa(ip), ntohs(it->first.port),
        statptr->txPackets, statptr->txBytes, statptr->rxPackets, statptr->rxBytes);
    }

    printf("\n========== UDP ==========\n");
    printf("IP\t\t Port  Tx Packets  Tx Bytes  Rx Packets  Rx Bytes\n");
    for (auto it = udpMap.begin(); it != udpMap.end(); it++)
    {
        struct in_addr ip = {it->first.ip};
        statptr = &(it->second);
        printf("%s\t%5d  %10d  %8d  %10d  %8d\n", inet_ntoa(ip), ntohs(it->first.port),
        statptr->txPackets, statptr->txBytes, statptr->rxPackets, statptr->rxBytes);
    }
}