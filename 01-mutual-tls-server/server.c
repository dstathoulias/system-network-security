#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
    SSL_CTX *ctx = NULL;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create new server-method instance and context
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load CA certificate(s) used to verify client certificates */
    /* Assume ca.crt is present in working directory */
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        fprintf(stderr, "Error loading CA certificate (ca.crt)\n");
        ERR_print_errors_fp(stderr);
    }

    // Require client certificate and verify it
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
     */

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server certificate %s\n", CertFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Load server private key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading server private key %s\n", KeyFile);
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Verify private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Server private key does not match the certificate public key\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
}

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */

    // Get client certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        if (subj) {
            printf("Client certificate Subject: %s\n", subj);
            OPENSSL_free(subj);
        }
        if (iss) {
            printf("Client certificate Issuer: %s\n", iss);
            OPENSSL_free(iss);
        }
        X509_free(cert);
    } else {
        printf("No client certificate presented by peer.\n");
    }
}

static int extract_tag(const char *xml, const char *tag, char *out, size_t outlen) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    char *s = strstr(xml, open);
    if (!s) return 0;
    s += strlen(open);
    char *e = strstr(s, close);
    if (!e) return 0;
    size_t len = e - s;
    if (len + 1 > outlen) len = outlen - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    return 1;
}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */

     // Extract username and password from XML
    char username[128] = {0};
    char password[128] = {0};
    int gotUser = extract_tag(buf, "UserName", username, sizeof(username));
    int gotPass = extract_tag(buf, "Password", password, sizeof(password));

    // Validate credentials and respond
    if (gotUser && gotPass) {
        printf("Parsed username='%s' password='%s'\n", username, password);
        if (strcmp(username, "2018030109") == 0 && strcmp(password, "123") == 0) {
            const char *response =
                "<Body>\n"
                "<Name>2018030109</Name>\n"
                "<year>1.5</year>\n"
                "<BlogType>Embededed and c c++</BlogType>\n"
                "<Author>Dimitris Stathoulias</Author>\n"
                "</Body>\n";
            SSL_write(ssl, response, strlen(response));
        } else {
            const char *invalid = "Invalid Message";
            SSL_write(ssl, invalid, strlen(invalid));
        }
    } else {
        const char *invalid = "Invalid Message";
        SSL_write(ssl, invalid, strlen(invalid));
    }

    int sd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);  // Properly shutdown SSL connection
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    ctx = InitServerCTX();
    LoadCertificates(ctx, "server.crt", "server.key");

    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);

        // Handle accept errors
        if (client < 0) {
            perror("accept");
            continue;
        }
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */
        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new() failed\n");
            close(client);
            continue;
        }
        SSL_set_fd(ssl, client);
        Servlet(ssl);
    }

    close(server);
    SSL_CTX_free(ctx);
}
