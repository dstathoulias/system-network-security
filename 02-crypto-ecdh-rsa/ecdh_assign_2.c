// Task 1: ECDH (Curve25519) + KDF tool
// Default comp: gcc -o ecdh_assign_2 ecdh_assign_2.c -lsodium

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// print usage info
static void print_usage(const char *p) {
    fprintf(stderr,
        "Usage: %s -o output.txt [-a 0xhex_alice_priv] [-b 0xhex_bob_priv] [-c context]\n"
        "  -o path    Path to output file (required)\n"
        "  -a hex     Alice private key (optional, hex, 32 bytes)\n"
        "  -b hex     Bob private key (optional, hex, 32 bytes)\n"
        "  -c string  KDF context (optional, default: \"ECDH_KDF\")\n"
        "  -h         This help message\n", p);
}

// function to write bytes as hex to file
static void write_hex_line(FILE *f, const char *label, const unsigned char *b, size_t n) {
    fprintf(f, "%s\n\n", label);
    for (size_t i=0;i<n;i++) fprintf(f, "%02x", b[i]);
    fprintf(f, "\n\n");
}

int main(int argc, char **argv) {
    // initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    // parse command line args
    char *output_path = NULL;
    char *hex_alice = NULL; 
    char *hex_bob = NULL;
    char *context_in = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "o:a:b:c:h")) != -1) {
        switch (opt) {
            case 'o': output_path = optarg; break;
            case 'a': hex_alice = optarg; break;
            case 'b': hex_bob = optarg; break;
            case 'c': context_in = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!output_path) { print_usage(argv[0]); return 1; }   // output file is required

    const char default_context[] = "ECDH_KDF";  // default context string
    unsigned char context[crypto_kdf_CONTEXTBYTES]; // KDF context
    memset(context, ' ', sizeof(context)); // fill with spaces
    // copy context string
    if (context_in) {
        size_t len = strlen(context_in);
        if (len > crypto_kdf_CONTEXTBYTES) len = crypto_kdf_CONTEXTBYTES;
        memcpy(context, context_in, len);
    } else {
        memcpy(context, default_context, strlen(default_context));
    }

    // arrays for keys
    unsigned char alice_priv[crypto_scalarmult_BYTES];
    unsigned char bob_priv[crypto_scalarmult_BYTES];
    unsigned char alice_pub[crypto_scalarmult_BYTES];
    unsigned char bob_pub[crypto_scalarmult_BYTES];

    /* --------- parse or generate Alice private key --------- */
    if (hex_alice) {    // if hex for Alice provided, parse
        const char *p = hex_alice;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        size_t hexlen = strlen(p);
        size_t bin_len = 0;
        // parse provided Alice hex key
        if (sodium_hex2bin(alice_priv, sizeof alice_priv, p, hexlen, NULL, &bin_len, NULL) != 0 || bin_len != sizeof alice_priv) {
            fprintf(stderr, "Invalid Alice private key (expected 64 hex chars / 32 bytes)\n");
            return 1;
        }
    } else {
        randombytes_buf(alice_priv, sizeof alice_priv); // if not, generate random
    }

    /* --------- parse or generate Bob private key --------- */
    if (hex_bob) {  // if hex for Bob provided, parse
        const char *p = hex_bob;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        size_t hexlen = strlen(p);
        size_t bin_len = 0;
        // parse provided Bob hex key
        if (sodium_hex2bin(bob_priv, sizeof bob_priv, p, hexlen, NULL, &bin_len, NULL) != 0 || bin_len != sizeof bob_priv) {
            fprintf(stderr, "Invalid Bob private key (expected 64 hex chars / 32 bytes)\n");
            return 1;
        }
    } else {
        randombytes_buf(bob_priv, sizeof bob_priv); // if not, generate random
    }

    // compute public keys
    if (crypto_scalarmult_base(alice_pub, alice_priv) != 0) {   // Alice
        fprintf(stderr, "crypto_scalarmult_base failed (Alice)\n"); return 1;
    }
    if (crypto_scalarmult_base(bob_pub, bob_priv) != 0) {   // Bob
        fprintf(stderr, "crypto_scalarmult_base failed (Bob)\n"); return 1;
    }

    // arrays for shared secrets
    unsigned char shared_alice[crypto_scalarmult_BYTES];
    unsigned char shared_bob[crypto_scalarmult_BYTES];
    // compute shared secrets
    if (crypto_scalarmult(shared_alice, alice_priv, bob_pub) != 0) {    // Alice
        fprintf(stderr, "crypto_scalarmult failed (Alice)\n"); return 1;
    }
    if (crypto_scalarmult(shared_bob, bob_priv, alice_pub) != 0) {  // Bob
        fprintf(stderr, "crypto_scalarmult failed (Bob)\n"); return 1;
    }

    // derive two 32-byte keys from the shared secret using crypto_kdf_derive_from_key
    // arrays for encryption and MAC keys
    unsigned char encryption_key_alice[32];
    unsigned char mac_key_alice[32];
    unsigned char encryption_key_bob[32];
    unsigned char mac_key_bob[32];

    // a master key of crypto_kdf_KEYBYTES bytes is required for KDF
    // derive key for Alice (master: shared_alice)
    if (crypto_kdf_derive_from_key(encryption_key_alice, 32, 1, (const char*)context, shared_alice) != 0) {
        fprintf(stderr, "KDF derive (Alice encryption) failed\n"); return 1;
    }
    if (crypto_kdf_derive_from_key(mac_key_alice, 32, 2, (const char*)context, shared_alice) != 0) {
        fprintf(stderr, "KDF derive (Alice MAC) failed\n"); return 1;
    }

    // derive key for Bob (master: shared_bob)
    if (crypto_kdf_derive_from_key(encryption_key_bob, 32, 1, (const char*)context, shared_bob) != 0) {
        fprintf(stderr, "KDF derive (Bob encryption) failed\n"); return 1;
    }
    if (crypto_kdf_derive_from_key(mac_key_bob, 32, 2, (const char*)context, shared_bob) != 0) {
        fprintf(stderr, "KDF derive (Bob MAC) failed\n"); return 1;
    }

    // open output file and write hex lines
    FILE *f = fopen(output_path, "w");
    if (!f) { perror("fopen"); return 1; }  // error opening file

    // write all data to file
    write_hex_line(f, "Alice's Public Key:", alice_pub, sizeof alice_pub);
    write_hex_line(f, "Bob's Public Key:", bob_pub, sizeof bob_pub);
    write_hex_line(f, "Shared Secret (Alice):", shared_alice, sizeof shared_alice);
    write_hex_line(f, "Shared Secret (Bob):", shared_bob, sizeof shared_bob);

    // verify that shared secrets match
    if (sodium_memcmp(shared_alice, shared_bob, sizeof shared_alice) == 0) {
        fprintf(f, "Shared secrets match!\n\n");
    } else {
        fprintf(f, "Shared secrets DO NOT match!\n\n");
    }

    // write derived encryption keys and verify they match
    write_hex_line(f, "Derived Encryption Key (Alice):", encryption_key_alice, 32);
    write_hex_line(f, "Derived Encryption Key (Bob):", encryption_key_bob, 32);
    if (sodium_memcmp(encryption_key_alice, encryption_key_bob, 32) == 0) fprintf(f, "Encryption keys match!\n\n");
    else fprintf(f, "Encryption keys DO NOT match!\n\n");

    // write derived MAC keys and verify they match
    write_hex_line(f, "Derived MAC Key (Alice):", mac_key_alice, 32);
    write_hex_line(f, "Derived MAC Key (Bob):", mac_key_bob, 32);
    if (sodium_memcmp(mac_key_alice, mac_key_bob, 32) == 0) fprintf(f, "MAC keys match!\n\n");
    else fprintf(f, "MAC keys DO NOT match!\n\n");

    fclose(f);
    return 0;
}
