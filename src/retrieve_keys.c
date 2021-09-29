#include "retrieve_keys.h"
// #include "diagnosis_key.pb-c.h"
#include "export.pb.h"
// #include "export.pb-c.h"


#include <pb_decode.h>
#include <pb_encode.h>
#include <pb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include <zlib.h>
// #include <zip.h>
// #include <openssl/pem.h>
// #include <openssl/rsa.h>
// #include <openssl/sha.h>
// #include <zip/zip.h>

#if !defined(__ZEPHYR__) || defined(CONFIG_POSIX_API)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#else

#include <kernel.h>
#include <net/socket.h>

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#include <net/tls_credentials.h>
#include "ca_certificate.h"
#endif

#endif

#define HTTP_HOST "svc90.main.px.t-online.de"
// #define HTTP_HOST "google.com"
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
#define HTTP_PORT "443"
#else
#define HTTP_PORT "80"
#endif

#define SSTRLEN(s) (sizeof(s) - 1)
#define CHECK(r)                       \
    {                                  \
        if (r == -1) {                 \
            printf("Error: " #r "\n"); \
            exit(1);                   \
        }                              \
    }

#define STORAGE_NODE DT_NODE_BY_FIXED_PARTITION_LABEL(temporary_key_storage)
#define FLASH_NODE DT_MTD_FROM_FIXED_PARTITION(STORAGE_NODE)

#define KEY_SIZE 8
#ifndef PROTOBUF_BLOCK_SIZE
#define PROTOBUF_BLOCK_SIZE 0
#endif
#define EXPORT_BUFFER_SIZE 4096

// Dynamically allocate based on http-header
// static char response[1024];
static uint8_t export_buffer[EXPORT_BUFFER_SIZE];
static int export_buffer_len = 0;
static int static_num_keys = 0;
// static char unzipped[100000];
// static char export_buffer[MAX_MSG_SIZE];
// static char signature[1000];
// static unsigned char digest[SHA256_DIGEST_LENGTH];
// static EVP_MD_CTX* ctx;
// static char pubkey_str[256] = "-----BEGIN PUBLIC
// KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEml59itec9qzwVojreLXdPNRsUWzf\nYHc1cKvIIi6/H56AJS/kZEYQnfDpxrgyGhdAm+pNN2GAJ3XdnQZ1Sk4amg==\n-----END
// PUBLIC KEY-----\n"; static  EVP_PKEY* pubkey; static char signature_data[1000]; static size_t signature_len;

void dump_addrinfo(const struct zsock_addrinfo* ai) {
    printf(
        "addrinfo @%p: ai_family=%d, ai_socktype=%d, ai_protocol=%d, "
        "sa_family=%d, sin_port=%x\n",
        ai, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addr->sa_family,
        ((struct sockaddr_in*)ai->ai_addr)->sin_port);
}

// bool write_key_data(pb_ostream_t* stream, const pb_field_iter_t* field, void* const* arg) {
//     // pb_bytes_array_t data;
//     // for (int i = 0; i < KEY_SIZE; i++) {
//     //     data.bytes[i] = i & 0xFF;
//     // }
//     // data.size = KEY_SIZE;
//     // if (!pb_encode_tag_for_field(stream, field)) {
//     //     return false;
//     // }
//     // // return true;
//     // return pb_encode(stream, PB_LTYPE_BYTES, &data);
//     return false;
// }

// bool write_keys(pb_ostream_t* stream, const pb_field_iter_t* field, void* const* arg) {
//     // int num = *((int*)arg);
//     printk("Num: %d\n",static_num_keys);
//     for (int i = 0; i < static_num_keys; i++) {
//         printk("Generating key\n");
//         TemporaryExposureKey key = TemporaryExposureKey_init_zero;
//         // pb_callback_t data_callback;
//         // key.key_data = data_callback;
//         // key.key_data.funcs.encode = &write_key_data;
//         // key.key_data.arg = NULL;
//         key.report_type = 0;
//         if (!pb_encode_tag_for_field(stream, field)) {
//             return false;
//         }
//         if (!pb_encode_submessage(stream, TemporaryExposureKey_fields, &key)) {
//             return false;
//         }
//     }
//     return true;
// }



int generate_keys(uint8_t* buf, int max_len, int num_keys) {
    static_num_keys = num_keys;
    TemporaryExposureKeyExport export = TemporaryExposureKeyExport_init_zero;
    pb_ostream_t stream = pb_ostream_from_buffer(buf, max_len);
    export.batch_size = num_keys;
    export.has_batch_size = true;
    for(int i = 0; i < num_keys; i++) {
         printk("Generating key\n");
        TemporaryExposureKey key = TemporaryExposureKey_init_zero;
        key.report_type = 0;
        if (!pb_encode_tag(&stream, 2, 7)) {
            return false;
        }
        if (!pb_encode_submessage(&stream, TemporaryExposureKey_fields, &key)) {
            return false;
        }
    }
    bool status = pb_encode(&stream, TemporaryExposureKeyExport_fields, &export);
    if (!status) {
        printk("Error encoding %s\n", PB_GET_ERROR(&stream));
    }
    return stream.bytes_written;
}

// static size_t read_buffer(unsigned max_length, uint8_t* out) {
//     size_t cur_len = 0;
//     size_t nread;
//     EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey);
//     FILE* fp = fopen("testExport-2-records-1-of-1/export.bin", "r");
//     while ((nread = fread(out + cur_len, 1, max_length - cur_len, fp)) != 0) {
//         EVP_DigestVerifyUpdate(ctx, out + cur_len, nread);
//         cur_len += nread;
//         if (cur_len == max_length) {
//             fprintf(stderr, "max message length exceeded\n");
//             exit(1);
//         }
//     }
//     if (EVP_DigestVerifyFinal(ctx, signature_data, signature_len) != 1) {
//         printf("Invalid signature");
//     } else {
//         printf("Valid signature");
//     }
//     fclose(fp);
//     return cur_len;
// }

// static size_t read_signature(unsigned max_length, uint8_t* out) {
//     size_t cur_len = 0;
//     size_t nread;
//     FILE* fp = fopen("testExport-2-records-1-of-1/export.sig", "r");
//     while ((nread = fread(out + cur_len, 1, max_length - cur_len, fp)) != 0) {
//         cur_len += nread;
//         if (cur_len == max_length) {
//             fprintf(stderr, "max message length exceeded\n");
//             exit(1);
//         }
//     }
//     fclose(fp);
//     return cur_len;
// }

void process_key(TemporaryExposureKey* key) {
    printk("Processing key %d\n", key->report_type);
}

bool TemporaryExporureKey_callback(pb_istream_t* stream, const pb_field_iter_t* field, void** arg) {
        TemporaryExposureKey key;
        if(!pb_decode(stream, TemporaryExposureKey_fields, &key)) {
            return false;
        }
        process_key(&key);
    return true;
}

bool input_stream_callback(pb_istream_t* stream, uint8_t* buf, size_t count) {
    return false;
}

int unpack_infected_keys() {
    export_buffer_len = generate_keys(export_buffer, EXPORT_BUFFER_SIZE, 10);
    printk("Bytes written: %d\n", export_buffer_len);

    pb_istream_t stream;
    #if PROTOBUF_BLOCK_SIZE
    stream.callback = &input_stream_callback;
    #else
    stream = pb_istream_from_buffer(export_buffer, export_buffer_len);  //{&callback, export_buffer, strlen(export_buffer)};
    #endif

    TemporaryExposureKeyExport tek_export = TemporaryExposureKeyExport_init_zero;

    bool status = pb_decode(&stream, TemporaryExposureKeyExport_fields, &tek_export);

    if (!status) {
        printk("Decoding failed: %s\n", PB_GET_ERROR(&stream));
        return -1;
    }
    if (tek_export.has_batch_size) {
        printk("Batch size: %d\n", (int)tek_export.batch_size);
    }

    printk("Status: ", stream.state)
    // tek_export.keys.funcs.decode();

    // tek_export.keys.arg = NULL;
    // tek_export.keys.funcs.decode = &read_keys;
 
    printk("Executed unpack_infected_keys()\n");
    return 0;
}

int get_infected_keys() {
    // {
    //         // message[0] = '\0';
    //         static struct zsock_addrinfo hints;
    //         struct zsock_addrinfo* res;
    //         int st, sock;

    //     #if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    //         tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ca_certificate,
    //         sizeof(ca_certificate));
    //     #endif
    //         printf("Trying to connect to %s:%s\n", HTTP_HOST, HTTP_PORT);
    //         hints.ai_family = AF_INET;
    //         hints.ai_socktype = SOCK_STREAM;
    //         st = getaddrinfo(HTTP_HOST, HTTP_PORT, NULL, &res);
    //         printf("getaddrinfo status: %d\n", st);
    //         if (st) {
    //             printf("%s\n", gai_strerror(st));
    //             printf("Unable to resolve address, quitting\n");
    //             return st;
    //         }

    //         dump_addrinfo(res);

    //     #if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    //         sock = socket(res->ai_family, res->ai_socktype, IPPROTO_TLS_1_2);
    //     #else
    //         sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    //     #endif
    //         CHECK(sock);
    //         printf("sock = %d\n", sock);

    //     #if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    //         sec_tag_t sec_tag_opt[] = {
    //             CA_CERTIFICATE_TAG,
    //         };
    //         CHECK(setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_opt, sizeof(sec_tag_opt)));

    //         CHECK(setsockopt(sock, SOL_TLS, TLS_HOSTNAME, HTTP_HOST, sizeof(HTTP_HOST)))
    //     #endif

    //         char date[16] = "2021-09-16";
    //         char request[256];  // = "GET / HTTP/1.0\r\nHost: " HTTP_HOST "\r\n\r\n      " ;

    //         // // for (int i = 0; i < 24; i++) {
    //         sprintf(request, "GET /version/v1/diagnosis-keys/country/EUR/date/%s
    //         HTTP/1.0\r\nHost:svc90.main.px.t-online.de\r\n\r\n", date); printf("Request %s\n", request);
    //         CHECK(connect(sock, res->ai_addr, res->ai_addrlen));
    //         CHECK(send(sock, request, SSTRLEN(request), 0));

    //         //     DiagnosisKeyBatch* batch;
    //         //     uint8_t buf[MAX_MSG_SIZE];
    //         //     recv(sock, response, sizeof(response) - 1, 0);
    //         //     printf("%s\n", response);

    //         size_t msg_len = 0;
    //         while (1) {
    //             int len = recv(sock, response, sizeof(response) - 1, 0);
    //             if (len < 0) {
    //                 // Error
    //                 return -1;
    //             }
    //             if (len == 0) {
    //                 // Reached end
    //                 break;
    //             }
    //             printf("Received %d bytes\n", len);
    //             // memcpy(message + msg_len, response, len);
    //             msg_len += len;
    //         }

    //     //     char* buf = NULL;
    //     //     size_t bufsize = 0;

    //     //     struct zip_t* zip = zip_stream_open(message, msg_len, 0, 'r');
    //     //     if (zip == NULL) {
    //     //         printf("Error opening the zip\n");
    //     //     }
    //     //     {
    //     //         int ret = zip_entry_open(zip, "export.bin");
    //     //         if (ret < 0) {
    //     //             printf("Error opening export.bin\n");
    //     //         }
    //     //         {
    //     //             ret = zip_entry_read(zip, (void**)&buf, &bufsize);
    //     //             if (ret < 0) {
    //     //                 printf("Error extracting the zip\n");
    //     //             }
    //     //         }
    //     //         zip_entry_close(zip);
    //     //     }
    //     //     zip_close(zip);

    //     //         // size_t msg_len = strlen(message);
    //     //         printf("Message length: %lu\n", msg_len);
    //     //         if (msg_len <= 1000) {
    //     //             // message[1000] = 0;
    //     //             printf("%s\n", message);
    //     //         }

    //     // // Unzip the message
    //     // struct z_stream_s stream;
    //     // stream.next_in = message;
    //     // stream.avail_in = msg_len;
    //     // stream.next_out = unzipped;
    //     // stream.avail_out = MAX_MSG_SIZE;
    //     // stream.zalloc = Z_NULL;
    //     // stream.zfree = Z_NULL;
    //     // stream.opaque = Z_NULL;

    //     // int ret = inflateInit2(&stream, 32);
    //     // if (ret != Z_OK) {
    //     //     printf("Something went wrong in inflateInit: %d\n%s\n", ret, stream.msg);
    //     //     return ret;
    //     // }

    //     // ret = inflate(&stream, Z_NO_FLUSH);
    //     // if (ret != Z_OK) {
    //     //     printf("Something went wrong in inflate: %d\n%s\n", ret, stream.msg);
    //     //     ret = inflateSync(&stream);
    //     //     if (ret != Z_OK) {
    //     //         printf("Something went wrong in inflateSync: %d\n%s\n", ret, stream.msg);
    //     //         return ret;
    //     //     }
    //     // }

    //     (void)close(sock);
    // }

    // // ctx = EVP_MD_CTX_new();

    // // // Verify signature
    // // size_t sig_len = read_signature(1000, signature);
    // // printf("Read signature file\n");
    // // TEKSignatureList* sigs = teksignature_list__unpack(NULL, sig_len, signature);
    // // if (sigs == NULL) {
    // //     fprintf(stderr, "error unpacking signature\n");
    // //     return -2;
    // // }
    // // printf("Unpacked signature\n");

    // // signature_len = sigs->signatures[0]->signature.len;
    // // memcpy(signature_data, sigs->signatures[0]->signature.data, signature_len);

    // // for (int i = 0; i < signature_len; i++) {
    // //     printf("%c", signature_data[i]);
    // // }
    // // printf("\n");

    // // FILE* pubkey_file = fopen("src/public.pem", "r");
    // // if (pubkey_file == NULL) {
    // //     printf("pubkey_file is NULL");
    // // }
    // // BIO* bio = BIO_new_file("src/public.pem","r");
    // // // BIO_write(bio, pubkey_str, strlen(pubkey_str));
    // // pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    // // // PEM_read_RSA_PUBKEY(pubkey_file, NULL, NULL, NULL);
    // // // if (pubkey == NULL) {
    // // //     printf("pubkey is NULL\n");
    // // // }

    // // printf("Read public key\n");
    // // size_t msg_len = read_buffer(MAX_MSG_SIZE, export_buffer);

    // // printf("Read payload file\n");

    // // Check header
    // if (memcmp("EK Export v1    ", export_buffer, 16)) {
    //     printf("Invalid header\n");
    //     return -1;
    // }
    // // // if (DSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature_data,
    // // //                signature_len, pubkey) != 1) {
    // // //     printf("Invalid signature\n");
    // // // } else {
    // // //     printf("Valid signature\n");
    // // // }

    // // for (int i = 0; i < sigs->n_signatures; i++) {
    // //     TEKSignature* sig = sigs->signatures[i];
    // //     SignatureInfo* signature_info = sig->signature_info;
    // //     if (signature_info != NULL) {
    // //         printf("Algorithm: %s\n", signature_info->signature_algorithm);
    // //         printf("Key Version: %s\n", signature_info->verification_key_version);
    // //         printf("Key ID:%s\n", signature_info->verification_key_id);
    // //     }
    // // }

    // // Unpack protocol buffer
    // TemporaryExposureKeyExport* export = temporary_exposure_key_export__unpack(NULL, msg_len - 16, export_buffer +
    // 16); if (export == NULL) {
    //     fprintf(stderr, "error unpacking incoming message\n");
    //     return -2;
    // }

    // // Iterate over new keys
    // for (int i = 0; i < export->n_keys; i++) {
    //     TemporaryExposureKey* key = export->keys[i];
    //     if (key->has_key_data) {
    //         int len = (key->key_data.len) + 1;
    //         char data[len + 1];
    //         memcpy(data, key->key_data.data, len - 1);
    //         data[len] = 0;
    //         printf("New key: %s\n", data);
    //     }
    // }

    // // Iterate over revised keys
    // for (int i = 0; i < export->n_revised_keys; i++) {
    //     TemporaryExposureKey* key = export->revised_keys[i];
    //     if (key->has_key_data) {
    //         int len = (key->key_data.len) + 1;
    //         char data[len + 1];
    //         memcpy(data, key->key_data.data, len - 1);
    //         data[len] = 0;
    //         printf("Revised key: %s\n", data);
    //     }
    // }

    // printf("Received %lu new keys and %lu revised keys\n", export->n_keys, export->n_revised_keys);

    // temporary_exposure_key_export__free_unpacked(export, NULL);

    return 0;
}

// int deserialize(/*uint8_t* data, size_t len*/) {
//     size_t msg_len = read_buffer(MAX_MSG_SIZE, message);
//     printf("Read file succesfully %lu bytes\n", msg_len);
// }

#if !defined(__ZEPHYR__) || defined(CONFIG_POSIX_API)

int main(void) {
    get_infected_keys();
    // deserialize();
}

#endif
