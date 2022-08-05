/*
*	Ethernet Header의 	src mac | dst mac
*	IP Header의 		src ip  | dst ip
*	TCP Header의		src port| dst port
*	Payload(data)의		hex value (최대 10 byte)
*/
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define IP_ADDR_LENG_BYTE 4 //IP 크기
#define MAC_ADDR_LENG_BYTE 6 // MAC ADDR 크기 
#define ETH_OFFSET 14 // ethnet 헤더 크기 (-preamble)

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

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

typedef struct { //파라미터[1] 인터페이스정보를 담는 구조체
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
	struct IpHeader* packet_ip = (struct IpHeader* )(packet + ETH_OFFSET);
	return  getIpLength(packet_ip->ip_verlen) + ETH_OFFSET;
}
u_int8_t getDataOffset(const u_char *packet, u_int8_t tcp_hdr_offset){ //tcpOffset 구하는 함수
	struct TcpHeader* packet_tcp = (struct TcpHeader* )(packet + tcp_hdr_offset);
	u_int8_t data_offset = (getTcpLength(packet_tcp->tcp_off) * 4);
	return data_offset;
}

void print_eth_data(const u_char* packet){
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

void print_ip_data(const u_char* packet){
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

void print_tcp_data(const u_char* packet, u_int8_t tcp_hdr_offset){
	struct TcpHeader* packet_tcp = (struct TcpHeader *)(packet + tcp_hdr_offset);
	printf("[*]TCP Header Segment\n");
	printf("\tTCP Source Port - %d\n", ntohs(packet_tcp->tcp_srcpt));
	printf("\tTCP Destination Port - %d\n", ntohs(packet_tcp->tcp_despt));
	
}

/*payload를 출력하는 함수*/
void print_payload(const u_char* packet, u_int8_t tcp_hdr_offset, u_int16_t data_offset){
	int offset = ETH_OFFSET + tcp_hdr_offset + data_offset;

	printf("[*]Payload(DATA) 10Bytes\n");
	if(data_offset == 40){ //length가 40바이트인 경우 데이터가 없다고 판단 사실 데이터가 뒤에 없다는 판단을 어떻게 해야할지 모르겠어서 이렇게 잡음
		printf("\tno data\n\n");
		return ;
	}
	if(packet[offset] == 0x0){ //하나 더 실제 data가 00으로만 있다면? 데이터가 없다고 판단.
		printf("\tno data\n\n");
		return ;
	}else{
		printf("\t");
		for(int i = 0; i < 10; i++){ //상위 10byte만 출력
			printf("%02x ",packet[offset+i]);
		}
	}
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)){
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
//1.인터페이스 정보 2. 받아들일 수 있는 최대 패킷 크기, 3. promiscuous mode, 4. 읽기 시간초과 millisecond 5. 에러 메시지 저장 -> 에러 발생 시 null 리턴 
	pcap_t* pcd = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); //해당 함수는 PDC(= packet capture descriptor)를 만들기 위한 함수
	if (pcd == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	int number = 1;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcd, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcd));
			break;
		}
		printf("[%d]- %u bytes captured\n",number ,header->caplen); //header->caplen은 캡처된 길이가 저장된 멤버
		u_int8_t tcp_hdr_offset =  getTcpOffset(packet); //tcp헤더 부분위치의 오프셋 
		u_int8_t data_offset = getDataOffset(packet, tcp_hdr_offset);
		struct EthHeader* packet_eth = (struct EthHeader* )packet; //ip헤더가 있는지 없는지 판단하기 위해서 이더넷 구조체 선언
		struct IpHeader* packet_ip = (struct IpHeader* )(packet + ETH_OFFSET); //ip헤더내 protocal identifier를 가져오기위한 ip헤더 구조체 선언
		/*캡쳐된 길이 출력*/
		if(packet_eth->ethtype != 0x08){ //IPv4만 출력
			printf("[*]This Protocal is not IPv4\n");
			printf("[*]Ethernet Type - 0x%02x\n\n", packet_eth->ethtype);
			number++;
			continue;
		}
		if(packet_ip->ip_p != 0x6){ //tcp가 포함되면 출력
			printf("[*]This Protocal is not TCP\n");
			printf("[*]Protocol Identifier - 0x%02x(%d)\n\n", packet_ip->ip_p, packet_ip->ip_p);
			number++;
			continue;
		}
		printf("[*]IPv4, TCP Protocol Captured\n");
		
		print_eth_data(packet);
		print_ip_data(packet);
		print_tcp_data(packet, tcp_hdr_offset);
		print_payload(packet, tcp_hdr_offset, data_offset);
		number++;
	}

	pcap_close(pcd);
}
