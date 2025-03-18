/*
*	Ethernet Header의 	src mac | dst mac
*	IP Header의 		src ip  | dst ip
*	TCP Header의		src port| dst port
*	Payload(data)의		hex value (최대 10 byte)
*/
#include "pch.h"
#include "header.h"
#include "packetparser.h"
#include "packetprinter.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

struct Param { // 파라미터[1] 인터페이스 정보를 담는 구조체
    char* dev_;
};

Param param = { .dev_ = nullptr }; // nullptr로 초기화

bool parse(Param* param, int argc, char* argv[]) { // param 변수는 이더넷 인터페이스 정보를 대입 한다.
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)) {
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // 1. 인터페이스 정보 2. 받아들일 수 있는 최대 패킷 크기, 3. promiscuous mode, 4. 읽기 시간초과 millisecond 5. 에러 메시지 저장 -> 에러 발생 시 null 리턴 
    pcap_t* pcd = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // 해당 함수는 PDC(= packet capture descriptor)를 만들기 위한 함수

    if (pcd == nullptr) { // nullptr 체크로 변경
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    int number = 1; // 캡쳐된 패킷의 순서를 기입하기 위한 변수

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcd, &header, &packet);

        // res 값에 따른 처리
        if (res == 0) continue; // 패킷이 없으면 계속 진행
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcd));
            break; // 에러 발생 시 루프 종료
        }

        printf("[%d]- %u bytes captured\n", number, header->caplen); // header->caplen은 캡처된 길이가 저장된 멤버
        u_int8_t tcp_hdr_offset = getTcpOffset(packet); // tcp헤더 부분위치의 오프셋 
        u_int8_t data_offset = getDataOffset(packet, tcp_hdr_offset); // data_offset의 크기 
        struct EthHeader* packet_eth = (struct EthHeader*)packet; // ip헤더가 있는지 없는지 판단하기 위해서 이더넷 구조체 선언
        struct IpHeader* packet_ip = (struct IpHeader*)(packet + ETH_OFFSET); // ip헤더내 protocal identifier를 가져오기위한 ip헤더 구조체 선언

        // 캡쳐된 길이 출력
        if (packet_eth->ethtype != 0x08) { // IPv4가 아닐때의 분기
            printf("[*]This Protocol is not IPv4\n");
            printf("[*]Ethernet Type - 0x%02x\n\n", packet_eth->ethtype);
            number++;
            continue; // 다음 루프 진행
        }

        if (packet_ip->ip_p != 0x6) { // tcp protocol이 포함이 되지않을 때의 분기
            printf("[*]This Protocol is not TCP\n");
            printf("[*]Protocol Identifier - 0x%02x(%d)\n\n", packet_ip->ip_p, packet_ip->ip_p);
            number++;
            continue; // 다음 루프 진행
        }

        printf("[*]IPv4, TCP Protocol Captured\n");

        printEthData(packet);
        printIpData(packet);
        printTcpData(packet, tcp_hdr_offset);
        printPayload(packet, tcp_hdr_offset, data_offset);
        number++;
    }

    pcap_close(pcd);
}
