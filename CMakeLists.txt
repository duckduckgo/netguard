cmake_minimum_required(VERSION 3.22)
project(netguard C)

set(CMAKE_C_STANDARD 11)

include_directories(src)

add_executable(netguard
        src/android.c
        src/dhcp.c
        src/dns.c
        src/global.h
        src/icmp.c
        src/icmp.h
        src/ip.c
        src/memory.c
        src/memory.h
        src/netguard.c
        src/netguard.h
        src/pcap.c
        src/pcap.h
        src/platform.h
        src/session.c
        src/session.h
        src/socks5.c
        src/tcp.c
        src/tls.c
        src/udp.c
        src/udp.h
        src/util.c
        src/util.h
        src/tls.h)
