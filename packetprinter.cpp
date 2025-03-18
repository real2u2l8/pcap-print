#include "pch.h"
#include "packetparser.h"
#include "packetprinter.h"
#include "header.h"

/*ethernet헤더 정보를 출력하는 함수*/
void printEthData(const u_char* packet){
    struct EthHeader* packet_eth = (struct EthHeader* )packet;
    printf("[*]Ethernet Header Frame\n");
    printf("\tMAC Destination - %x:%x:%x:%x:%x:%x\n"
           , packet_eth->mac_dst[0]
           , packet_eth->mac_dst[1]
           , packet_eth->mac_dst[2]
           , packet_eth->mac_dst[3]
           , packet_eth->mac_dst[4]
           , packet_eth->mac_dst[5]);
    printf("\tMAC Source - %x:%x:%x:%x:%x:%x\n"
           , packet_eth->mac_src[0]
           , packet_eth->mac_src[1]
           , packet_eth->mac_src[2]
           , packet_eth->mac_src[3]
           , packet_eth->mac_src[4]
           , packet_eth->mac_src[5]);
}

/*IP Header 데이터를 출력하는 함수*/
void printIpData(const u_char* packet){
    struct IpHeader* packet_ip = (struct IpHeader* )(packet + ETH_OFFSET);
    printf("[*]IP Header Packet\n");
    printf("\tIP Source - %d.%d.%d.%d\n"
           , packet_ip->ip_src[0]
           , packet_ip->ip_src[1]
           , packet_ip->ip_src[2]
           , packet_ip->ip_src[3]);
    printf("\tIP Destination - %d.%d.%d.%d\n"
           , packet_ip->ip_dst[0]
           , packet_ip->ip_dst[1]
           , packet_ip->ip_dst[2]
           , packet_ip->ip_dst[3]);
    printf("\tIP Version - v%d\n",getIpVesion(packet_ip->ip_verlen));
    printf("\tIP Header length - %d\n", getIpLength(packet_ip->ip_verlen));
}

/*TCP Header 데이터를 출력하는 함수*/
void printTcpData(const u_char* packet, u_int8_t tcp_hdr_offset){
    struct TcpHeader* packet_tcp = (struct TcpHeader *)(packet + tcp_hdr_offset);
    printf("[*]TCP Header Segment\n");
    printf("\tTCP Source Port - %d\n", ntohs(packet_tcp->tcp_srcpt));
    printf("\tTCP Destination Port - %d\n", ntohs(packet_tcp->tcp_despt));
}

/*payload를 출력하는 함수*/
void printPayload(const u_char* packet, u_int8_t tcp_hdr_offset, u_int16_t data_offset){
    int offset = ETH_OFFSET + tcp_hdr_offset + data_offset;

    printf("[*]Payload(DATA) 20Bytes\n");
    if(data_offset == 40){ //TCP Header length가 40바이트인 경우 데이터가 없다고 판단
        printf("\tno data\n\n");
        return ;
    }
    if(packet[offset] == 0x0){ //하나 더 실제 data가 00으로만 있다면? 데이터가 없다고 판단.
        printf("\tno data\n\n");
        return ;
    }else{
        printf("\t");
        for(int i = 0; i < 20; i++){ //상위 20byte만 출력
            printf("%02x ",packet[offset+i]);
        }
    }
    printf("\n\n");
}
