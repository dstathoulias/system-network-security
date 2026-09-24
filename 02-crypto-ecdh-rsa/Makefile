# Makefile to build ECDH (task 1) and RSA (task 2) tools
CC = gcc
CFLAGS = -Wall -Wextra -O2

# ECDH (libsodium)
ECDH_SRC = ecdh_assign_2.c
ECDH_BIN = ecdh_assign_2
ECDH_LIBS = -lsodium

# RSA (GMP + OpenSSL)
RSA_SRC = rsa_assign_2.c
RSA_BIN = rsa_assign_2
RSA_LIBS = -lgmp -lcrypto

# Targets
.PHONY: all clean

# Build both ECDH and RSA tools
all: $(ECDH_BIN) $(RSA_BIN)

# Rules
$(ECDH_BIN): $(ECDH_SRC)
	$(CC) $(CFLAGS) -o $@ $(ECDH_SRC) $(ECDH_LIBS)

$(RSA_BIN): $(RSA_SRC)
	$(CC) $(CFLAGS) -o $@ $(RSA_SRC) $(RSA_LIBS)

# Cleanup
clean:
	rm -f $(ECDH_BIN) $(RSA_BIN) *.o public_*.key private_*.key tmp* *.txt performance.txt
