#pragma once

u_int8_t getIpVesion(u_int8_t bits); //IP version 데이터를 구하는 함수
u_int8_t getIpLength(u_int8_t bits); //IP Header Length를 구하는 함수
u_int8_t getTcpLength(u_int8_t bits); //tcplength구하는 함수
u_int8_t getTcpOffset(const u_char* packet); //tcpOffset 구하는 함수
u_int8_t getDataOffset(const u_char *packet, u_int8_t tcp_hdr_offset); //Payload를 구하기위한 Offset을 구하는 함수
