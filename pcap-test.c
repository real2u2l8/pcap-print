/*
*	Ethernet Header의 	src mac | dst mac
*	IP Header의 		src ip  | dst ip
*	TCP Header의		src port| dst port
*	Payload(data)의		hex value (최대 10 byte)
*/
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define IP_ADDR_LENG_BYTE 4
#define MAC_ADDR_LENG_BYTE 6

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct{ //TCP Header 구조체 선언 정의 부분
    u_int16_t tcp_srcpt;     /* tcp source port */
    u_int16_t tcp_despt;     /* tcp destination port */
    u_int32_t tcp_seq;     /* sequence number */
    u_int32_t tcp_ack;     /* acknowledgement number */
    u_int8_t tcp_off;      /* data offset(0x0000) + RSV(0x000)+ NS (0x0) */
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
}TcpHeader;

typedef struct{ //IP Header 구조체 선언 부분
	u_int8_t ip_verlen; 	/*version 0x0000 + length 0x0000*/
    u_int8_t ip_tos;        /* type of service aka DSCP*/
    u_int16_t ip_tlen;         /* total length */
    u_int16_t ip_id;          /* fragment identification */
    u_int8_t ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_int8_t ip_ttl;            /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IP_ADDR_LENG_BYTE];
	u_int8_t ip_dst[IP_ADDR_LENG_BYTE];  /* source and dest address */
} IpHeader;

typedef struct{ //Ethernet Header 구조체 선언 부분
	u_int8_t mac_dst[MAC_ADDR_LENG_BYTE];	/*MAC Address Destinaion*/
	u_int8_t mac_src[MAC_ADDR_LENG_BYTE];	/*MAC Address Source*/
	u_int8_t ethtype;						/*Ethernet Type */
} EthHeader;


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) { //param 변수는 이더넷 인터페이스 정보를 대입 한다.
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
//1.인터페이스 정보 2. 받아들일 수 있는 최대 패킷 크기, 3. promiscuous mode, 4. 읽기 시간초과 millisecond 5. 에러 메시지 저장 -> 에러 발생 시 null 리턴 
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); //해당 함수는 PDC(= packet capture descriptor)를 만들기 위한 함수
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
