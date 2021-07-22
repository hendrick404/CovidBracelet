#include "http_client.h"

#include <stdio.h>
#include <stdlib.h>

// #if !defined(__ZEPHYR__) || defined(CONFIG_POSIX_API)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// #else

// #include <net/socket.h>
// #include <kernel.h>

// #if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
// #include <net/tls_credentials.h>
// #include "ca_certificate.h"
// #endif

// #endif

#define HTTP_HOST "svc90.main.px.t-online.de"
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define HTTP_PORT "443"
#else
#define HTTP_PORT "80"
#endif
#define HTTP_PATH1 "/version/v1/diagnosis-keys/country/EUR/date"

#define SSTRLEN(s) (sizeof(s) - 1)
#define CHECK(r)                       \
    {                                  \
        if (r == -1) {                 \
            printf("Error: " #r "\n"); \
            exit(1);                   \
        }                              \
    }

// #define REQUEST "GET " HTTP_PATH " HTTP/1.0\r\nHost: " HTTP_HOST "\r\n\r\n"

static char response[1024];

void dump_addrinfo(const struct addrinfo* ai) {
    printf(
        "addrinfo @%p: ai_family=%d, ai_socktype=%d, ai_protocol=%d, "
        "sa_family=%d, sin_port=%x\n",
        ai, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addr->sa_family,
        ((struct sockaddr_in*)ai->ai_addr)->sin_port);
}

int get_infected_keys() {
    static struct addrinfo hints;
    struct addrinfo* res;
    int st, sock;

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate, sizeof(ca_certificate));
#endif

    // printf("Preparing HTTP GET request for http://" HTTP_HOST
    //        ":" HTTP_PORT HTTP_PATH "\n");

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    st = getaddrinfo(HTTP_HOST, HTTP_PORT, &hints, &res);
    printf("getaddrinfo status: %d\n", st);

    if (st != 0) {
        printf("Unable to resolve address, quitting\n");
        return st;
    }

    dump_addrinfo(res);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    sock = socket(res->ai_family, res->ai_socktype, IPPROTO_TLS_1_2);
#else
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#endif
    CHECK(sock);
    printf("sock = %d\n", sock);

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    sec_tag_t sec_tag_opt[] = {
        CA_CERTIFICATE_TAG,
    };
    CHECK(setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_opt, sizeof(sec_tag_opt)));

    CHECK(setsockopt(sock, SOL_TLS, TLS_HOSTNAME, HTTP_HOST, sizeof(HTTP_HOST)))
#endif

// #define REQUEST1 "GET " HTTP_PATH1 " HTTP/1.0\r\nHost: " HTTP_HOST "\r\n\r\n"

    char date[16] = "2021-07-21";
    char request[128];

    for (int i = 0; i < 24; i++) {
        sprintf(request,
               "GET version/v1/diagnosis-keys/country/EUR/date/%s/hour/%d HTTP/1.0\r\nHost: svc90.main.px.t-online.de "
               "\r\n\r\n",
               date, i);
        CHECK(connect(sock, res->ai_addr, res->ai_addrlen));
        CHECK(send(sock, request, SSTRLEN(request), 0));

        while (1) {
            int len = recv(sock, response, sizeof(response) - 1, 0);

            if (len < 0) {
                printf("Error reading response\n");
                return -1;
            }

            if (len == 0) {
                break;
            }

            response[len] = 0;
            printf("%s", response);
        }

        printf("\n");
    }
    (void)close(sock);
    return 0;
}
