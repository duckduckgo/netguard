
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TIMEOUT_MS 300
#define MIN_BUFFER_SIZE 17
#define MAX_BUFFER_SIZE 213

typedef enum {
    SEND_RANDOM_DATA_OK,
    SEND_RANDOM_DATA_ERROR_BIND_SOCKET,
    SEND_RANDOM_DATA_ERROR_SEND_SOCKET
} send_data_result_t;

/**
 * Returns whether the given address represents a public IP address or not
 * @param address IPv4 or IPv6 address
 * @return `true` if it's public IP address, false otherwise
 */
static bool is_public_ip(const struct sockaddr_storage* address);

/**
 * Sends random data to a random public IP address
 * @return `send_data_result_t` that identifies success or error
 */
static send_data_result_t try_sending_random_udp();

#define TIMEOUT_SECONDS 60
#define TIMEOUT_MICROSECONDS 300000

int wait_for_tunnel_up(int tun_fd) {
    fd_set fd_set;
    struct timeval timeout;
    struct timeval start_time, current_time;

    FD_ZERO(&fd_set);
    FD_SET(tun_fd, &fd_set);

    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = TIMEOUT_MICROSECONDS;

    gettimeofday(&start_time, NULL);

    while (1) {
        gettimeofday(&current_time, NULL);
        long elapsed_seconds = current_time.tv_sec - start_time.tv_sec;
        long elapsed_microseconds = current_time.tv_usec - start_time.tv_usec;

        if (elapsed_seconds > TIMEOUT_SECONDS ||
            (elapsed_seconds == TIMEOUT_SECONDS && elapsed_microseconds >= TIMEOUT_MICROSECONDS)) {
            return -1; // Timeout occurred
        }

        int ready = select(tun_fd + 1, &fd_set, NULL, NULL, &timeout);
        if (ready > 0) {
            return 0; // Tunnel device is ready
        }

        FD_SET(tun_fd, &fd_set);
        try_sending_random_udp();
    }
}

///////////////////////////////////////////////////////////////////////////

static send_data_result_t try_sending_random_udp() {
    struct timespec start, current;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &current);
        int elapsed = (current.tv_sec - start.tv_sec) * 1000 + (current.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= TIMEOUT_MS) {
            return SEND_RANDOM_DATA_OK;
        }

        uint16_t rand_port = rand();
        struct sockaddr_storage local_addr, rand_dest_addr;

        // generate IPv4 packet
        struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)&local_addr;
        memset(ipv4_addr, 0, sizeof(*ipv4_addr));
        ipv4_addr->sin_family = AF_INET;
        ipv4_addr->sin_port = 0;

        struct sockaddr_in *ipv4_dest_addr = (struct sockaddr_in *)&rand_dest_addr;
        memset(ipv4_dest_addr, 0, sizeof(*ipv4_dest_addr));
        ipv4_dest_addr->sin_family = AF_INET;
        ipv4_dest_addr->sin_port = htons(rand_port);
        ipv4_dest_addr->sin_addr.s_addr = rand();

        // continue if not a public IP address
        if (is_public_ip(&rand_dest_addr) == false) {
            continue;
        }

        int socket_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            return SEND_RANDOM_DATA_ERROR_BIND_SOCKET;
        }

        uint8_t buf[MAX_BUFFER_SIZE];
        int buf_size = rand() % (MAX_BUFFER_SIZE - MIN_BUFFER_SIZE + 1) + MIN_BUFFER_SIZE;
        for (int i = 0; i < buf_size; i++) {
            buf[i] = rand();
        }

        ssize_t send_result = sendto(socket_fd, buf, buf_size, 0, (struct sockaddr *)&rand_dest_addr, sizeof(rand_dest_addr));
        if (send_result >= 0) {
            close(socket_fd);
            return SEND_RANDOM_DATA_OK;
        } else {
            close(socket_fd);
            return SEND_RANDOM_DATA_ERROR_SEND_SOCKET;
        }
    }
}

static bool is_public_ip(const struct sockaddr_storage* address) {
    char ip_str[INET6_ADDRSTRLEN];

    if (address->ss_family == AF_INET) {
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)address;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
    } else if (address->ss_family == AF_INET6) {
        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)address;
        inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
    } else {
        // just in case
        return false;
    }

    // Check if the IP address is public
    if (strncmp(ip_str, "10.", 3) == 0 ||
        strncmp(ip_str, "172.16.", 7) == 0 ||
        strncmp(ip_str, "192.168.", 8) == 0 ||
        strncmp(ip_str, "169.254.", 8) == 0 ||
        strncmp(ip_str, "192.0.0.", 8) == 0 ||
        strncmp(ip_str, "192.0.2.", 8) == 0 ||
        strncmp(ip_str, "198.51.100.", 12) == 0 ||
        strncmp(ip_str, "203.0.113.", 11) == 0 ||
        strncmp(ip_str, "fc", 2) == 0 ||
        strncmp(ip_str, "fe80:", 5) == 0) {
        return false;
    }

    return true;
}

