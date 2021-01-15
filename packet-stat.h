// packet-stat.h
// 참고 "libnet-headers.h"

#pragma once
#include <sys/types.h>

// 바이트 단위
#define MAC_ADDR_SIZE 6
#define IP_ADDR_SIZE 4

// ethernet header
// size: 14 Byte
struct ethernet_header
{
    u_int8_t   dst_mac[MAC_ADDR_SIZE];  // destination MAC address
    u_int8_t   src_mac[MAC_ADDR_SIZE];  // source MAC address
    u_int16_t  ether_type;  // protocol
};

// IPv4 header
// size: 20 Byte
struct ipv4_header
{
    u_int8_t  ihl;          // 하위 4bit = IP 헤더 길이
    u_int8_t  padding1[8];
    u_int8_t  protocol;     // protocol
    u_int8_t  padding2[2];
    u_int8_t  src_ip[4];    // source IP address
    u_int8_t  dst_ip[4];    // destination IP address
};

// TCP header
// size: 20 Byte
struct tcp_header
{
    u_int16_t  src_port;     // source port number
    u_int16_t  dst_port;     // destination port number
    u_int8_t   padding[8];
    u_int8_t   data_offset;  // 상위 4bit = TCP 헤더 길이
};

// 패킷 정보 출력 함수
// 과제에서 요구한 packet의 정보를 출력해 준다.
void printPacketInfo(const u_char* packet, u_int packet_size);

// 이더넷 헤더 정보 출력 함수
// src_mac과 dst_mac을 출력해 준다.
void printEthernetHeader(struct ethernet_header* eth_hdr);

// IP 헤더 정보 출력 함수
// src_ip와 dst_ip를 출력해 준다.
void printIpHeader(struct ipv4_header* ip_hdr);

// TCP 헤더 정보 출력 함수
// src_port와 dst_port를 출력해 준다.
void printTcpHeader(struct tcp_header* tcp_hdr);

// 페이로드 데이터 출력 함수
// print_len만큼 출력하여 준다. (바이트 단위)
void printPayload(u_char payload[], u_int print_len);

// MAC주소 출력 함수
void printMacAddress(u_int8_t mac_address[]);

// IP주소 출력 함수
void printIpAddress(u_int8_t ip_address[]);

// x, y중 더 작은 값을 반환
u_int min(u_int x, u_int y);
