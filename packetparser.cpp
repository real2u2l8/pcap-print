#include "pch.h"
#include "packetparser.h"
#include "header.h"

u_int8_t getIpVesion(u_int8_t bits){ //IP version 데이터를 구하는 함수
    return ((u_int8_t)0xF0 & bits) >> 4;
}

u_int8_t getIpLength(u_int8_t bits){ //IP Header Length를 구하는 함수
    u_int8_t ip_length = ((u_int8_t)0x0F & bits) * 4;
    return ip_length;
}

u_int8_t getTcpLength(u_int8_t bits){ //tcplength구하는 함수
    return ((u_int8_t)0xF0 & bits) >> 4;
}

u_int8_t getTcpOffset(const u_char* packet){ //tcpOffset 구하는 함수
    struct IpHeader* packet_ip = (struct IpHeader*)(packet + ETH_OFFSET);
    return getIpLength(packet_ip->ip_verlen) + ETH_OFFSET;
}

u_int8_t getDataOffset(const u_char *packet, u_int8_t tcp_hdr_offset){ //Payload를 구하기위한 Offset을 구하는 함수
    struct TcpHeader* packet_tcp = (struct TcpHeader*)(packet + tcp_hdr_offset);
    u_int8_t data_offset = (getTcpLength(packet_tcp->tcp_off) * 4);
    return data_offset;
}
