// packet-stat.cpp

#include <stdio.h>
#include <netinet/in.h>
#include "packet-stat.h"

void printPacketInfo(const u_char* packet, u_int packet_size)
{
    struct ethernet_header*  eth_hdr = NULL;
    struct ipv4_header*       ip_hdr = NULL;
    struct tcp_header*       tcp_hdr = NULL;
    u_char*                  payload = NULL;
    
    // 이더넷 헤더 set
    eth_hdr = (struct ethernet_header*)packet;
    // IPv4 타입이 아니면 건너뛴다.
    if(ntohs(eth_hdr->ether_type) != 0x0800)
        return;
    
    // IP 헤더 오프셋
    int offset = 14;
    // IP 헤더 set
    ip_hdr = (struct ipv4_header*)(packet+offset);
    // TCP가 아니면 건너뛴다.
    if(ip_hdr->protocol != 0x6)
        return;
    
    // TCP 헤더 오프셋
    // IP 헤더의 IHL의 하위 4비트 * 4 만큼 더해준다.
    offset += ((ip_hdr->ihl) & 0xf) * 4;
    // TCP 헤더 set
    tcp_hdr = (struct tcp_header*)(packet+offset);    
    
    // 페이로드의 오프셋
    // TCP 헤더의 data_offset의 상위 4비트 * 4 만큼 더해준다.
    offset += (((tcp_hdr->data_offset) & 0xf0) >> 4) * 4;
    payload = (u_char*)(packet+offset);
    // 페이로드의 사이즈
    u_int payload_size = packet_size - offset;
    
    // 과제에서 요구한 정보 출력!!
    printEthernetHeader(eth_hdr);
    printIpHeader(ip_hdr);
    printTcpHeader(tcp_hdr);
    printPayload(payload, min((u_int)16, payload_size));  // 최대 16바이트
}

void printEthernetHeader(struct ethernet_header* eth_hdr)
{
    printf("src mac: ");
    printMacAddress(eth_hdr->src_mac);
    printf("\ndst mac: ");
    printMacAddress(eth_hdr->dst_mac);
    printf("\n");
}

void printIpHeader(struct ipv4_header* ip_hdr)
{
    printf("src ip: ");
    printIpAddress(ip_hdr->src_ip);
    printf("\ndst ip: ");
    printIpAddress(ip_hdr->dst_ip);
    printf("\n");
}

void printTcpHeader(struct tcp_header* tcp_hdr)
{
    // 2Byte 이므로 ntohs를 사용하여 바이트오더를 맞춘다.
    printf("src port: %d\n", ntohs(tcp_hdr->src_port));
    printf("dst port: %d\n", ntohs(tcp_hdr->dst_port));
}

void printPayload(u_char payload[], u_int print_len)
{
    printf("data: ");
    for(int i = 0; i < print_len; i++)
        printf("%02x ", payload[i]);
    printf("\n\n");
}

void printMacAddress(u_int8_t mac_address[])
{
    int i = 0;
    for(i = 0; i < MAC_ADDR_SIZE-1; i++)
        printf("%02x:", mac_address[i]);
    printf("%02x", mac_address[i]);
}

void printIpAddress(u_int8_t ip_address[])
{
    int i = 0;
    for(i = 0; i < IP_ADDR_SIZE-1; i++)
        printf("%d.", ip_address[i]);
    printf("%d", ip_address[i]);
}

u_int min(u_int x, u_int y)
{
    if(x < y)
        return x;
    else
        return y;
}
