#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS client context (TLS_client_method)
     * 3. Load CA certificate to verify server
     * 4. Configure SSL_CTX to verify server certificate
     */
    SSL_CTX *ctx = NULL;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create new client-method instance and context
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL){
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load CA certificate(s) used to verify client certificates */
    /* Assume ca.crt is present in working directory */
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        fprintf(stderr, "Error loading CA certificate (ca.crt)\n");
        ERR_print_errors_fp(stderr);
    }

    /* Require server certificate to be verified */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* TODO:
     * 1. Load client certificate using SSL_CTX_use_certificate_file
     * 2. Load client private key using SSL_CTX_use_PrivateKey_file
     * 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */

    // Load client certificate
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading client certificate %s\n", CertFile);
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Load client private key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading client private key %s\n", KeyFile);
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Verify private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Client private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
     * 2. Load client certificate and key using LoadCertificates
     */
    ctx = InitCTX();
    LoadCertificates(ctx, "client.crt", "client.key");

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Establish SSL connection using SSL_connect
     * 2. Ask user to enter username and password
     * 3. Build XML message dynamically
     * 4. Send XML message over SSL
     * 5. Read server response and print it
     */
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Get username and password from user
    char username[64], password[64];
    printf("Enter username: ");
    if (scanf("%63s", username) != 1) username[0] = '\0';
    printf("Enter password: ");
    if (scanf("%63s", password) != 1) password[0] = '\0';

    // Build XML message
    char msg[512];
    snprintf(msg, sizeof(msg),
             "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
             username, password);

    // Send XML message over SSL
    if (SSL_write(ssl, msg, strlen(msg)) <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        ERR_print_errors_fp(stderr);
    } else {    // Read server response
        char reply[1024];
        int bytes = SSL_read(ssl, reply, sizeof(reply)-1);
        if (bytes > 0) {
            reply[bytes] = '\0';
            printf("Server reply: %s\n", reply);
        } else {
            printf("Peer did not return a certificate or returned an invalid one\n");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
