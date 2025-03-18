#pragma once

/*ethernet헤더 정보를 출력하는 함수*/
void printEthData(const u_char* packet);

/*IP Header 데이터를 출력하는 함수*/
void printIpData(const u_char* packet);

/*TCP Header 데이터를 출력하는 함수*/
void printTcpData(const u_char* packet, u_int8_t tcp_hdr_offset);

/*payload를 출력하는 함수*/
void printPayload(const u_char* packet, u_int8_t tcp_hdr_offset, u_int16_t data_offset);
