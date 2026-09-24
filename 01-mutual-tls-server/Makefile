# Makefile to create certs/keys and build server/client/rclient

# Variables
OPENSSL := openssl
CC      := gcc
LIBS    := -lssl -lcrypto

# Subjects
CLIENT_SUBJ       := /C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=client
SERVER_SUBJ       := /C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=localhost
ROGUE_CLIENT_SUBJ := /C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=rogueclient

# Targets
.PHONY: all certs rogue build server client server-bin client-bin rclient-bin clean

all: certs rogue build

# ---------------------------------
# Trusted certs
# ---------------------------------
certs: ca.crt server client

# CA
ca.key:
	$(OPENSSL) genrsa -out ca.key 4096
	@chmod 600 ca.key

ca.crt: ca.key
	$(OPENSSL) req -x509 -new -nodes -key ca.key -sha256 -days 365 \
		-subj '/C=GR/ST=Crete/L=Chania/O=TechnicalUniversityofCrete/OU=ECE Lab/CN=RootCA' \
		-out ca.crt

# ---------------------------------
# Server certs
# ---------------------------------
server: server.crt

server.key:
	$(OPENSSL) genrsa -out server.key 2048
	@chmod 600 server.key

server.csr: server.key
	$(OPENSSL) req -new -key server.key -subj '$(SERVER_SUBJ)' -out server.csr

server.crt: server.csr ca.crt ca.key
	$(OPENSSL) x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
		-out server.crt -days 365 -sha256

# ----------------
# Client certs
# ----------------
client: client.crt

client.key:
	$(OPENSSL) genrsa -out client.key 2048
	@chmod 600 client.key

client.csr: client.key
	$(OPENSSL) req -new -key client.key -subj '$(CLIENT_SUBJ)' -out client.csr

client.crt: client.csr ca.crt ca.key
	$(OPENSSL) x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
		-out client.crt -days 365 -sha256

# ----------------------------------
# Rogue certs
# ----------------------------------
rogue: rogue_ca.crt rogue_client.crt

rogue_ca.key:
	$(OPENSSL) genrsa -out rogue_ca.key 4096
	@chmod 600 rogue_ca.key

rogue_ca.crt: rogue_ca.key
	$(OPENSSL) req -x509 -new -nodes -key rogue_ca.key -sha256 -days 3650 \
		-subj '/C=GR/ST=Crete/L=Chania/O=RogueOrg/OU=RogueCA/CN=RogueLocalCA' \
		-out rogue_ca.crt

rogue_client.key:
	$(OPENSSL) genrsa -out rogue_client.key 2048
	@chmod 600 rogue_client.key

rogue_client.csr: rogue_client.key
	$(OPENSSL) req -new -key rogue_client.key -subj '$(ROGUE_CLIENT_SUBJ)' -out rogue_client.csr

rogue_client.crt: rogue_client.csr rogue_ca.crt rogue_ca.key
	$(OPENSSL) x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
		-out rogue_client.crt -days 365 -sha256

# --------------------------------------
# Compile binaries
# --------------------------------------
build: server-bin client-bin rclient-bin

server-bin: server.c
	$(CC) -o server server.c $(LIBS)

client-bin: client.c
	$(CC) -o client client.c $(LIBS)

rclient-bin: rclient.c
	$(CC) -o rclient rclient.c $(LIBS)

# ------------------------------
# Cleanup
# ------------------------------
clean:
	-rm -f server client rclient
	-rm -f ca.key ca.crt ca.srl
	-rm -f server.key server.csr server.crt
	-rm -f client.key client.csr client.crt
	-rm -f rogue_ca.key rogue_ca.crt rogue_ca.srl
	-rm -f rogue_client.key rogue_client.csr rogue_client.crt
