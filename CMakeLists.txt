cmake_minimum_required(VERSION 3.16)

project(pcap-print LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# PCH 설정
set(CMAKE_PCH_ENABLED ON)
set(CMAKE_PCH_FILE "pch.h")

add_executable(pcap-print main.cpp
    pch.h
    pch.cpp
    packetparser.h packetparser.cpp
    packetprinter.h packetprinter.cpp
    header.h header.cpp)

target_precompile_headers(pcap-print PRIVATE pch.h)

include(GNUInstallDirs)
install(TARGETS pcap-print
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_link_libraries(pcap-print PRIVATE ${PCAP_LIBRARIES})
