# **Assignment 1: Secure Server-Client Tool — README**

**Author Information**

- **Author:** ΔΗΜΗΤΡΗΣ ΣΤΑΘΟΥΛΙΑΣ
- **AM:** 2018030109
- **Institution:** Technical University of Crete
- **Department:** School of Electrical & Computer Engineering
- **Course:** Ασφάλεια Συστημάτων και Υπηρεσιών
- **Date:** 29/10/2025
- **Instructor:** ΣΩΤΗΡΙΟΣ ΙΩΑΝΝΙΔΗΣ


**Tool introduction**
This project demonstrates mutual TLS authentication between a client and server written in C using OpenSSL. 
Server and client verify each other's X.509 certificates. The trusted client is accepted after user authentication, while the rogue client, 
signed by an untrusted CA, is rejected. If the handshake is accepted, the server sends an XML response to the client.

There are two clients:
- client: trusted client, certificate signed by the trusted CA.
- rclient: rogue client, certificate signed by a different untrusted CA rejected by the server.


**Project files**
- server.c: TLS server (requires client certs).
- client.c: trusted client (cert signed by trusted CA).
- rclient.c: rogue client (cert signed by rogue CA).
- Makefile: creates certificates/keys and builds binaries.
- README.md: this file.


**Tool utility**
1. Creates a trusted CA (private key + self-signed certificate).
2. Creates a server key and signs it with the trusted CA: server.crt/server.key.
3. Creates a trusted client key and signs it with the trusted CA: client.crt/client.key.
4. Creates a rogue CA and signs a rogue client certificate: rogue_client.crt/rogue_client.key.
5. Compiles server, client, and rclient.
6. Running server + client demonstrates successful mutual TLS connection. rclient demonstrates server rejecting an untrusted CA.


**Openssl commands used (Makefile)**

1) Generate a CA private key
openssl genrsa -out ca.key 4096
- genrsa: generate an RSA private key
- -out ca.key: write private key to file ca.key
- 4096: key size in bits

2) Create a self-signed CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA" \
  -out ca.crt
- req: X.509 certificate request tool.
- -x509: produce a self-signed certificate
- -new: new request/certificate
- -nodes: do not encrypt the key
- -key ca.key: private key used to sign the certificate
- -sha256: use SHA-256 as signing digest.
- -days 365: cert lifetime in days
- -subj "..." : subject fields (Country, State, Locality, Organization, OU, CN)
- -out ca.crt: write cert to file

3) Generate server private key
openssl genrsa -out server.key 2048
- Generates a 2048-bit RSA private key for the server

4) Create server CSR (Certificate Signing Request)
openssl req -new -key server.key \
  -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost" \
  -out server.csr
- -subj uses CN=localhost for testing tool locally

5) Sign server CSR with the trusted CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256
- x509 -req: sign CSR to produce an X.509 certificate
- -CAcreateserial: create ca.srl to track the serial number

6) Generate trusted client key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key \
  -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=client" \
  -out client.csr

7) Sign trusted client CSR with trusted CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256

8) Create a rogue CA and rogue client
openssl genrsa -out rogue_ca.key 4096
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 365 \
  -subj "/C=GR/ST=Crete/L=Chania/O=RogueOrg/OU=RogueCA/CN=RogueLocalCA" \
  -out rogue_ca.crt

openssl genrsa -out rogue_client.key 2048
openssl req -new -key rogue_client.key \
  -subj "/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=rogueclient" \
  -out rogue_client.csr
openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
  -out rogue_client.crt -days 365 -sha256

**Compilation commands**
Build the C programs:
gcc -o server server.c -lssl -lcrypto
gcc -o client client.c -lssl -lcrypto
gcc -o rclient rclient.c -lssl -lcrypto
- -lssl -lcrypto: link OpenSSL libraries


**How to run**
1. Generate certs and build (Makefile):
- make: generate server, client, rclient certificates and build binaries
- make certs: only generate trusted client, server certificates
- make server: only generate server certificates
- make rogue: only generate rogue client certificates
- make client: only generate trusted client certificates
- make build: only compile binaries
- make clean: remove generated files and binaries

2. Start the server (port 8082):
./server 8082

3. In another terminal run trusted client:
./client 127.0.0.1 8082

4. Input username, password:
- username: 2018030109
- password: 123
If authenticated, client receives the XML response from server

5. Test rogue client:
./rclient 127.0.0.1 8082
Server should reject connection. User is still prompted to imput credentials but server has already declined handshake
