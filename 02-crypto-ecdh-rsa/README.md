**Assignment 2: Cryptographic Tools — ECDH and RSA - README**
Author Information
- Author: ΔΗΜΗΤΡΗΣ ΣΤΑΘΟΥΛΙΑΣ
- AM: 2018030109
- Institution: Technical University of Crete
- Department: School of Electrical & Computer Engineering
- Course: Ασφάλεια Συστημάτων και Υπηρεσιών
- Date: 09/11/2025
- Instructor: ΣΩΤΗΡΙΟΣ ΙΩΑΝΝΙΔΗΣ

**Tool Introduction**
This assignment implements two cryptographic methods in the C programming language using the libraries below:
1. Elliptic Curve Diffie–Hellman (ECDH) Key Exchange with Key Derivation Function (KDF) using libsodium.
2. RSA Encryption/Decryption and Digital Signatures using GMP and OpenSSL.

This project demonstrates the implementation of secure key exchange, encryption/decryption, and signing with the use of 2 different methods.

**Project files**
- ecdh_assign_2: ECDH key exchange and encryption (Task 1).
- rsa_assign_2: RSA key generation, encryption/decryption, signing, verification, and performance analysis (Task 2).
- Makefile: compiles both C programs using libsodium, GMP, and OpenSSL.s.
- README.md: this file.


**Tool 1: ECDH Key Exchange with Key Derivation (Task 1)**
This tool allows two parties (Alice and Bob) to:
1. Generate Curve25519 private and public key pairs.
2. Exchange public keys and compute a shared secret.
3. Derive two 32-byte keys (Encryption key & MAC key) using the shared secret and a KDF context.
4. Output all resulting keys as hexadecimal text in an output file.

**Libraries Used**
- libsodium — implementation of Curve25519 ECDH and KDF functions.

**Command-Line Options**
-o path: path to output file (required)
-a number: Alice's private key (optional, hexadecimal)
-b number: Bob's private key (optional, hexadecimal)
-c context: context string for key derivation (optional, default: "ECDH_KDF")
-h: help message

**How to run**
- build tool binaries (Makefile).
- execute with random keys: ./ecdh_assign_2 -o ecdh_output.txt
- execute with fixed keys: ./ecdh_assign_2 -o ecdh_output.txt -a 0x1a2b3c -b 0x1a2cb7
- execute with custom KDF context: ./ecdh_assign_2 -o ecdh_output.txt -c "koukou25"

**Tool 2: RSA Encryption and Digital Signatures (Task 2)**
This tool allows RSA key-pair generation, encryption/decryption and digital signature operations using teh GMP library in C. Performance analysis is also supported for measuring execution times and memory usages.
 
**Utility**
1. RSA key generation using GMP.
2. file encryption and decryption.
3. creation of digital signature creation verification using SHA-256.
4. performance analysis for key sizes 1024, 2048, and 4096 bits.

**Libraries Used**
- GMP — arbitrary precision arithmetic.
- OpenSSL — SHA-256 hash computation.

**Command-Line Options**
-g bits: generate RSA keys with specified key length
-i path: input file path
-o path: output file path
-k path: key file path
-e: encrypt input and save to output
-d: decrypt input and save to output
-s: sign input and save to output
-v path: verify signature using input file
-a path: run performance analysis and save results
-h: help message

**How to run**
- build tool binaries (Makefile).
- generate keys: ./rsa_assign_2 -g 2048
- encryption: ./rsa_assign_2 -i plaintext.txt -o ciphertext.txt -k public_2048.key -e
- decryption: ./rsa_assign_2 -i ciphertext.txt -o decrypted.txt -k private_2048.key -d
- signing: ./rsa_assign_2 -i input.txt -o signature.txt -k private_2048.key -s
- verification: ./rsa_assign_2 -i input.txt -k public_2048.key -v signature.txt
- performance analysis: ./rsa_assign_2 -a performance.txt