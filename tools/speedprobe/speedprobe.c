/*
 * Downloads or uploads a number of bytes over plain HTTP on one or more TCP connections at once, and reports the
 * throughput.
 *
 * Usage: speedprobe <down|up> [bytes] [streams] [host] [path]   (defaults: 50000000 1 speed.cloudflare.com)
 *
 * Bytes are split between the streams. Each stream keeps one connection open and sends requests of at most
 * REQUEST_BYTES on it: GET /__down?bytes=N for downloads and POST /__up for uploads, which is what
 * speed.cloudflare.com serves. It refuses larger downloads. With a path, downloads instead GET the start of that
 * file, which must be larger than REQUEST_BYTES, from any server that serves byte ranges.
 */
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TIMEOUT_S 30
#define CHUNK 65536
#define REQUEST_BYTES 10000000LL

struct stream {
    pthread_t thread;
    int up;
    long long bytes;
    long long transferred;
    double connect_ms;
    const char *error;
    char error_buf[64];
    int sock;
    // Received but not yet consumed
    char buf[CHUNK];
    size_t start, end;
};

static const char *host;
static const char *path;
static struct addrinfo *server;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int send_all(int sock, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = send(sock, data, len, 0);
        if (n <= 0) return -1;
        data += n;
        len -= n;
    }
    return 0;
}

static int fill(struct stream *s) {
    ssize_t n = recv(s->sock, s->buf, sizeof(s->buf), 0);
    if (n <= 0) {
        s->error = n < 0 ? strerror(errno) : "connection closed early";
        return -1;
    }
    s->start = 0;
    s->end = n;
    return 0;
}

// Reads a response's headers and returns its Content-Length, or -1 on an error or a status other than 200 or 206
static long long read_headers(struct stream *s) {
    char headers[4096];
    size_t len = 0;
    while (len < 4 || memcmp(headers + len - 4, "\r\n\r\n", 4) != 0) {
        if (s->start == s->end && fill(s) < 0) return -1;
        if (len == sizeof(headers) - 1) {
            s->error = "headers too long";
            return -1;
        }
        headers[len++] = s->buf[s->start++];
    }
    headers[len] = 0;
    int status = 0;
    sscanf(headers, "HTTP/1.%*d %d", &status);
    if (status != 200 && status != 206) {
        snprintf(s->error_buf, sizeof(s->error_buf), "HTTP status %d", status);
        s->error = s->error_buf;
        return -1;
    }
    const char *length = strcasestr(headers, "\r\nContent-Length:");
    if (!length) {
        s->error = "no Content-Length";
        return -1;
    }
    return atoll(length + 17);
}

// Reads and discards a response body, counting it when it's the download
static int read_body(struct stream *s, long long length, int count) {
    while (length > 0) {
        if (s->start == s->end && fill(s) < 0) return -1;
        size_t n = s->end - s->start < (size_t) length ? s->end - s->start : (size_t) length;
        s->start += n;
        length -= n;
        if (count) s->transferred += n;
    }
    return 0;
}

static int request(struct stream *s, long long bytes) {
    char req[512];
    int len;
    if (s->up) {
        len = snprintf(req, sizeof(req),
                       "POST /__up HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\n"
                       "Content-Length: %lld\r\n\r\n", host, bytes);
    } else if (path) {
        len = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=0-%lld\r\n\r\n",
                       path, host, bytes - 1);
    } else {
        len = snprintf(req, sizeof(req), "GET /__down?bytes=%lld HTTP/1.1\r\nHost: %s\r\n\r\n", bytes, host);
    }
    if (send_all(s->sock, req, len) < 0) {
        s->error = strerror(errno);
        return -1;
    }
    if (s->up) {
        static const char zeros[CHUNK];
        for (long long sent = 0; sent < bytes;) {
            size_t chunk = bytes - sent < CHUNK ? bytes - sent : CHUNK;
            if (send_all(s->sock, zeros, chunk) < 0) {
                s->error = strerror(errno);
                return -1;
            }
            sent += chunk;
        }
    }
    // An upload counts once the server has answered, so data still in the socket buffer doesn't count
    long long length = read_headers(s);
    if (length < 0 || read_body(s, length, !s->up) < 0) return -1;
    if (s->up) s->transferred += bytes;
    return 0;
}

static void *run_stream(void *arg) {
    struct stream *s = arg;

    double start = now_ms();
    s->sock = socket(server->ai_family, SOCK_STREAM, 0);
    if (s->sock < 0) {
        s->error = strerror(errno);
        return NULL;
    }
    struct timeval tv = {TIMEOUT_S, 0};
    setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(s->sock, server->ai_addr, server->ai_addrlen) < 0) {
        s->error = strerror(errno);
        close(s->sock);
        return NULL;
    }
    s->connect_ms = now_ms() - start;

    for (long long left = s->bytes; left > 0;) {
        long long bytes = left < REQUEST_BYTES ? left : REQUEST_BYTES;
        if (request(s, bytes) < 0) break;
        left -= bytes;
    }
    close(s->sock);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "down") != 0 && strcmp(argv[1], "up") != 0)) {
        printf("usage: speedprobe <down|up> [bytes] [streams] [host] [path]\n");
        return 2;
    }
    int up = strcmp(argv[1], "up") == 0;
    long long bytes = argc > 2 ? atoll(argv[2]) : 50000000;
    int streams = argc > 3 ? atoi(argv[3]) : 1;
    host = argc > 4 ? argv[4] : "speed.cloudflare.com";
    path = argc > 5 ? argv[5] : NULL;
    if (bytes <= 0 || streams < 1 || streams > 16) {
        printf("bytes must be positive and streams between 1 and 16\n");
        return 2;
    }

    // IPv4 only, so that runs compare the same path
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(host, "80", &hints, &server);
    if (err != 0) {
        printf("%s failed to resolve %s: %s\n", argv[1], host, gai_strerror(err));
        return 1;
    }

    static struct stream s[16];
    double start = now_ms();
    for (int i = 0; i < streams; i++) {
        s[i].up = up;
        s[i].bytes = bytes / streams;
        pthread_create(&s[i].thread, NULL, run_stream, &s[i]);
    }
    long long transferred = 0;
    double connect_ms = 0;
    const char *error = NULL;
    for (int i = 0; i < streams; i++) {
        pthread_join(s[i].thread, NULL);
        transferred += s[i].transferred;
        if (s[i].connect_ms > connect_ms) connect_ms = s[i].connect_ms;
        if (s[i].error && !error) error = s[i].error;
    }
    double seconds = (now_ms() - start) / 1000;

    if (error) {
        printf("%s failed after %lld bytes in %.2f s: %s\n", argv[1], transferred, seconds, error);
        return 1;
    }
    printf("%s %lld bytes on %d streams in %.2f s: %.1f Mbit/s (connect %.0f ms)\n",
           argv[1], transferred, streams, seconds, transferred * 8 / seconds / 1e6, connect_ms);
    return 0;
}
