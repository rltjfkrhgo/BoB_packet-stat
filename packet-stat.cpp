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

    Convo<Mac> macConvo = {srcMac, dstMac};
    ethConvoMap[macConvo].txPackets++;
    ethConvoMap[macConvo].txBytes += packet_size;

    if(ntohs(ethPacket->ether_type) != ETHERTYPE_IP)
        return;

    // ========== IP 헤더 ==========

    offset += LIBNET_ETH_H;
    IpHdr* ipPacket = (IpHdr*)(packet+offset);

    in_addr_t srcIp = ipPacket->ip_src.s_addr;
    in_addr_t dstIp = ipPacket->ip_dst.s_addr;

    ipMap[srcIp].txPackets++;
    ipMap[srcIp].txBytes += packet_size;
    ipMap[dstIp].rxPackets++;
    ipMap[dstIp].rxBytes += packet_size;

    Convo<in_addr_t> ipConvo = {srcIp, dstIp};
    ipConvoMap[ipConvo].txPackets++;
    ipConvoMap[ipConvo].txBytes += packet_size;

    if(ipPacket->ip_p != 6 && 
       ipPacket->ip_p != 17)
       return;

    // ========== TCP or UDP 헤더 ==========

    // TCP 이면
    if(ipPacket->ip_p == 6)
    {
        offset += ipPacket->ip_hl*4;
        TcpHdr* tcpPacket = (TcpHdr*)(packet+offset);

        L4Key srcTcp, dstTcp;
        srcTcp.ip = ipPacket->ip_src.s_addr;
        srcTcp.port = tcpPacket->th_sport;
        dstTcp.ip = ipPacket->ip_dst.s_addr;
        dstTcp.port = tcpPacket->th_dport;

        tcpMap[srcTcp].txPackets++;
        tcpMap[srcTcp].txBytes += packet_size;
        tcpMap[dstTcp].rxPackets++;
        tcpMap[dstTcp].rxBytes += packet_size;

        Convo<L4Key> tcpConvo = {srcTcp, dstTcp};
        tcpConvoMap[tcpConvo].txPackets++;
        tcpConvoMap[tcpConvo].txBytes += packet_size;
    }

    // UDP 이면
    if(ipPacket->ip_p == 17)
    {
        offset += ipPacket->ip_hl*4;
        UdpHdr* udpPacket = (UdpHdr*)(packet+offset);

        L4Key srcUdp, dstUdp;
        srcUdp.ip = ipPacket->ip_src.s_addr;
        srcUdp.port = udpPacket->uh_sport;
        dstUdp.ip = ipPacket->ip_dst.s_addr;
        dstUdp.port = udpPacket->uh_dport;

        udpMap[srcUdp].txPackets++;
        udpMap[srcUdp].txBytes += packet_size;
        udpMap[dstUdp].rxPackets++;
        udpMap[dstUdp].rxBytes += packet_size;

        Convo<L4Key> udpConvo = {srcUdp, dstUdp};
        udpConvoMap[udpConvo].txPackets++;
        udpConvoMap[udpConvo].txBytes += packet_size;
    }
}

void PrintStat()
{
    Stat* statptr = nullptr;

    printf("\n\n    Endpoints\n");

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

    printf("\n\n    Conversations\n");

    printf("\n========== Ethernet ==========\n");
    printf("from Mac\t\tto Mac             Packets    Bytes\n");
    for(auto it = ethConvoMap.begin(); it != ethConvoMap.end(); it++)
    {
        it->first.src.printMac();
        printf("\t");
        it->first.dst.printMac();
        statptr = &(it->second);
        printf("  %7d  %7d\n", statptr->txPackets, statptr->txBytes);
    }

    printf("\n========== IP ==========\n");
    printf("from IP\t\tto IP\t\tPackets    Bytes\n");
    for(auto it = ipConvoMap.begin(); it != ipConvoMap.end(); it++)
    {
        struct in_addr srcIp = {it->first.src};
        struct in_addr dstIp = {it->first.dst};
        statptr = &(it->second);
        printf("%s\t", inet_ntoa(srcIp));
        printf("%s\t%7d  %7d\n",  inet_ntoa(dstIp),
        statptr->txPackets, statptr->txBytes);
    }

    printf("\n========== TCP ==========\n");
    printf("from IP\t\tfrom Port  to IP\t\tto Port  Packets    Bytes\n");
    for(auto it = tcpConvoMap.begin(); it != tcpConvoMap.end(); it++)
    {
        struct in_addr srcIp = {it->first.src.ip};
        struct in_addr dstIp = {it->first.dst.ip};
        statptr = &(it->second);
        printf("%s\t%8d  ", inet_ntoa(srcIp), ntohs(it->first.src.port));
        printf("%s\t%7d  %7d  %7d\n", inet_ntoa(dstIp), ntohs(it->first.dst.port),
        statptr->txPackets, statptr->txBytes);
    }

    printf("\n========== UCP ==========\n");
    printf("from IP\t\tfrom Port  to IP\t\tto Port  Packets    Bytes\n");
    for(auto it = udpConvoMap.begin(); it != udpConvoMap.end(); it++)
    {
        struct in_addr srcIp = {it->first.src.ip};
        struct in_addr dstIp = {it->first.dst.ip};
        statptr = &(it->second);
        printf("%s\t%8d  ", inet_ntoa(srcIp), ntohs(it->first.src.port));
        printf("%s\t%7d  %7d  %7d\n", inet_ntoa(dstIp), ntohs(it->first.dst.port),
        statptr->txPackets, statptr->txBytes);
    }
}