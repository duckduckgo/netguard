#ifndef TLS_H
#define TLS_H

#define FQDN_LENGTH 256

#define TLS_TYPE_HANDSHAKE_RECORD 22
#define TLS_TYPE_APPLICATION_DATA 23

#define TLS_EXTENSION_TYPE_SERVER_NAME 0

int get_server_name(
    const uint8_t *pkt,
    size_t length,
    const uint8_t *tcp_payload,
    char *server_name
);

#endif //TLS_H
