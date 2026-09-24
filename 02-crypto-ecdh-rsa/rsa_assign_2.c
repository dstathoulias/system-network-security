// Task 2: RSA + Digital Signature tool
// Default comp: gcc -o rsa_assign_2 rsa_assign_2.c -lgmp -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <openssl/sha.h>

#define BUF_SIZE 4096

// ---------- RSA CORE FUNCTIONS ----------
void generate_keys(int bits) {
    mpz_t p, q, n, lambda, e, d, temp1, temp2;
    gmp_randstate_t state;

    mpz_inits(p, q, n, lambda, e, d, temp1, temp2, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // generate primes p, q
    mpz_urandomb(p, state, bits / 2);
    mpz_nextprime(p, p);
    mpz_urandomb(q, state, bits / 2);
    mpz_nextprime(q, q);

    // n = p * q
    mpz_mul(n, p, q);

    // lambda = (p-1)*(q-1)
    mpz_sub_ui(temp1, p, 1);
    mpz_sub_ui(temp2, q, 1);
    mpz_mul(lambda, temp1, temp2);

    // e = 65537
    mpz_set_ui(e, 65537);
    // d = e^-1 mod lambda
    mpz_invert(d, e, lambda);

    // save keys
    char pub_name[64], priv_name[64];
    sprintf(pub_name, "public_%d.key", bits);
    sprintf(priv_name, "private_%d.key", bits);
    FILE *pub = fopen(pub_name, "w");
    FILE *priv = fopen(priv_name, "w");
    gmp_fprintf(pub, "%Zd\n%Zd\n", n, e);
    gmp_fprintf(priv, "%Zd\n%Zd\n", n, d);
    fclose(pub);
    fclose(priv);

    gmp_randclear(state);
    mpz_clears(p, q, n, lambda, e, d, temp1, temp2, NULL);
}

// read n, e/d from key file
void read_key(mpz_t n, mpz_t exp, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("key file"); exit(1); }
    gmp_fscanf(f, "%Zd\n%Zd\n", n, exp);
    fclose(f);
}

// ---------- ENCRYPTION  ----------
void rsa_encrypt(const char *input_path, const char *output_path, const char *key_path) {
    mpz_t n, e, m, c;
    mpz_inits(n, e, m, c, NULL);

    read_key(n, e, key_path);

    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "w");
    unsigned char buf[BUF_SIZE];
    size_t len = fread(buf, 1, BUF_SIZE, in);
    mpz_import(m, len, 1, 1, 0, 0, buf);
    mpz_powm(c, m, e, n);
    gmp_fprintf(out, "%Zd\n", c);

    fclose(in); fclose(out);
    mpz_clears(n, e, m, c, NULL);
}

// ---------- DECRYPTION  ----------
void rsa_decrypt(const char *input_path, const char *output_path, const char *key_path) {
    mpz_t n, d, m, c;
    mpz_inits(n, d, m, c, NULL);

    read_key(n, d, key_path);
    FILE *in = fopen(input_path, "r");
    FILE *out = fopen(output_path, "wb");
    gmp_fscanf(in, "%Zd\n", c);
    mpz_powm(m, c, d, n);

    size_t count;
    unsigned char *buf = (unsigned char*) mpz_export(NULL, &count, 1, 1, 0, 0, m);
    fwrite(buf, 1, count, out);
    free(buf);

    fclose(in); fclose(out);
    mpz_clears(n, d, m, c, NULL);
}

// ---------- DIGITAL SIGNATURE ----------
void rsa_sign(const char *input_path, const char *output_path, const char *key_path) {
    mpz_t n, d, hash_int, sig;
    mpz_inits(n, d, hash_int, sig, NULL);
    read_key(n, d, key_path);

    // read file and hash
    FILE *in = fopen(input_path, "rb");
    unsigned char buf[BUF_SIZE], hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    size_t len;
    // compute SHA-256 hash
    while ((len = fread(buf, 1, BUF_SIZE, in)) > 0)
        SHA256_Update(&sha, buf, len);
    SHA256_Final(hash, &sha);
    fclose(in);

    mpz_import(hash_int, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_powm(sig, hash_int, d, n);

    FILE *out = fopen(output_path, "w");
    gmp_fprintf(out, "%Zd\n", sig);
    fclose(out);
    mpz_clears(n, d, hash_int, sig, NULL);
}

// ---------- SIGNATURE VERIFICATION ----------
void rsa_verify(const char *input_path, const char *key_path, const char *sig_path) {
    mpz_t n, e, hash_int, sig, check;
    mpz_inits(n, e, hash_int, sig, check, NULL);
    read_key(n, e, key_path);

    // compute hash
    FILE *in = fopen(input_path, "rb");
    unsigned char buf[BUF_SIZE], hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    size_t len;
    // compute SHA-256 hash
    while ((len = fread(buf, 1, BUF_SIZE, in)) > 0)
        SHA256_Update(&sha, buf, len);
    SHA256_Final(hash, &sha);
    fclose(in);
    mpz_import(hash_int, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    FILE *sf = fopen(sig_path, "r");
    gmp_fscanf(sf, "%Zd\n", sig);
    fclose(sf);

    mpz_powm(check, sig, e, n);
    // compare hashes
    if (mpz_cmp(hash_int, check) == 0)
        printf("Signature is VALID\n");
    else
        printf("Signature is INVALID\n");

    mpz_clears(n, e, hash_int, sig, check, NULL);
}

// ---------- PERFORMANCE ANALYSIS ----------
void rsa_performance(const char *output_path) {
    FILE *output = fopen(output_path, "w");
    int keys[3] = {1024, 2048, 4096};
    for (int i = 0; i < 3; i++) {
        int bits = keys[i];
        clock_t start, end;
        double enc_t, dec_t, sig_t, ver_t;

        // Key generation time
        start = clock();
        generate_keys(bits);
        end = clock();
        fprintf(output, "Key Length: %d bits\n", bits);
        fprintf(output, "KeyGen Time: %.3fs\n", (double)(end - start) / CLOCKS_PER_SEC);

        // Create a sample file
        FILE *tmp = fopen("tmp.txt", "w");
        fputs("performance test", tmp);
        fclose(tmp);

        // Build key filenames for current bit size (1024, 2048, 4096)
        char pub[64], priv[64];
        sprintf(pub, "public_%d.key", bits);
        sprintf(priv, "private_%d.key", bits);

        // Encryption time
        start = clock();
        rsa_encrypt("tmp.txt", "tmp_enc.txt", pub);
        end = clock(); enc_t = (double)(end - start) / CLOCKS_PER_SEC;

        // Decryption time
        start = clock();
        rsa_decrypt("tmp_enc.txt", "tmp_dec.txt", priv);
        end = clock(); dec_t = (double)(end - start) / CLOCKS_PER_SEC;

        // Signing time
        start = clock();
        rsa_sign("tmp.txt", "tmp_sig.txt", priv);
        end = clock(); sig_t = (double)(end - start) / CLOCKS_PER_SEC;

        // Verification time
        start = clock();
        rsa_verify("tmp.txt", pub, "tmp_sig.txt");
        end = clock(); ver_t = (double)(end - start) / CLOCKS_PER_SEC;


        fprintf(output, "Encryption Time: %.3fs\n", enc_t);
        fprintf(output, "Decryption Time: %.3fs\n", dec_t);
        fprintf(output, "Signing Time: %.3fs\n", sig_t);
        fprintf(output, "Verification Time: %.3fs\n\n", ver_t);
    }
    fclose(output);
}

// ---------- MAIN ----------
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./rsa_assign_2 [options]\n");
        printf("-g bits : generate RSA keypair\n");
        printf("-i in -o out -k key -e : encrypt\n");
        printf("-i in -o out -k key -d : decrypt\n");
        printf("-i in -o out -k key -s : sign\n");
        printf("-i in -k key -v sig    : verify\n");
        printf("-a out                 : performance analysis\n");
        return 0;
    }

    if (strcmp(argv[1], "-g") == 0)
        generate_keys(atoi(argv[2]));
    else if (strcmp(argv[3], "-e") == 0)
        rsa_encrypt(argv[2], argv[4], argv[6]);
    else if (strcmp(argv[3], "-d") == 0)
        rsa_decrypt(argv[2], argv[4], argv[6]);
    else if (strcmp(argv[3], "-s") == 0)
        rsa_sign(argv[2], argv[4], argv[6]);
    else if (strcmp(argv[3], "-v") == 0)
        rsa_verify(argv[2], argv[4], argv[6]);
    else if (strcmp(argv[1], "-a") == 0)
        rsa_performance(argv[2]);
    else
        printf("Invalid command.\n");

    return 0;
}
