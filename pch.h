#pragma once

//LIB
#include <pcap.h>

//C
#include <stdbool.h>
#include <stdio.h>


//Macro
#define IP_ADDR_LENG_BYTE 4 //IP 크기
#define MAC_ADDR_LENG_BYTE 6 // MAC ADDR 크기
#define ETH_OFFSET 14 // ethnet 헤더 크기 (-preamble)
