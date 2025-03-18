#pragma once

/*Ethernet Header 구조체 선언 부분*/
struct EthHeader{
    u_int8_t mac_dst[MAC_ADDR_LENG_BYTE];	/*MAC Address Destinaion*/
    u_int8_t mac_src[MAC_ADDR_LENG_BYTE];	/*MAC Address Source*/
    u_int8_t ethtype;						/*Ethernet Type */
};

/*IP Header 구조체 선언 부분*/
struct IpHeader{
    u_int8_t ip_verlen; 	/*version 4bit + length 4bit*/
    u_int8_t ip_tos;        /* type of service aka DSCP*/
    u_int16_t ip_tlen;         /* total length */
    u_int16_t ip_id;          /* fragment identification */
    u_int16_t ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t ip_ttl;            /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IP_ADDR_LENG_BYTE];
    u_int8_t ip_dst[IP_ADDR_LENG_BYTE];  /* source and dest address */
};

/*TCP Header 구조체 선언 정의 부분*/
struct TcpHeader{
    u_int16_t tcp_srcpt;     /* tcp source port */
    u_int16_t tcp_despt;     /* tcp destination port */
    u_int32_t tcp_seq;     /* sequence number */
    u_int32_t tcp_ack;     /* acknowledgement number */
    u_int8_t tcp_off;      /* data offset(0000) + RSV(000)+ NS (0) */
    u_int8_t tcp_flags;
#define TCP_FIN		0x01
#define TCP_SYN		0x02
#define TCP_RST		0x04
#define TCP_PUSH	0x08
#define TCP_ACK		0x10
#define TCP_URG		0x20
#define TCP_ECE		0x40
#define TCP_CWR		0x80
#define TCP_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_int16_t tcp_win;       /* window */
    u_int16_t tcp_sum;       /* checksum */
    u_int16_t tcp_urp;       /* urgent pointer */
};
