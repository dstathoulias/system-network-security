CC = gcc
CFLAGS = -Wall -g

# Libraries needed for OpenSSL
LIBS = -lssl -lcrypto -ldl

all: audit_logger.so audit_monitor test_audit

# 1. Compile the Shared Library
audit_logger.so: audit_logger.c
	$(CC) $(CFLAGS) -fPIC -shared -o audit_logger.so audit_logger.c $(LIBS)

# 2. Compile the Monitor Tool
audit_monitor: audit_monitor.c
	$(CC) $(CFLAGS) -o audit_monitor audit_monitor.c

# 3. Compile the Test Program
test_audit: test_audit.c
	$(CC) $(CFLAGS) -o test_audit test_audit.c

# Helper to run the test with the logger loaded
run: audit_logger.so test_audit
	LD_PRELOAD=./audit_logger.so ./test_audit

clean:
	rm -f audit_logger.so audit_monitor test_audit /tmp/access_audit.log
	rm -f file_*.txt locked_file_*.txt
	rm -f access_audit.log