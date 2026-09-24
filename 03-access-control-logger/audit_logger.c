#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <limits.h>
#include <errno.h>

#define MAX_TRACKED 256

// Table to track opened files and their paths
static struct {
    FILE *fp;
    char path[PATH_MAX];
} file_table[MAX_TRACKED];

// custom variables to hold real file operation pointers
static FILE *(*real_fopen)(const char *, const char *) = NULL;
static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
static int (*real_fclose)(FILE *) = NULL;

// Initialize real function pointers
static void init_real_funcs(void) {
    if (!real_fopen)  real_fopen  = dlsym(RTLD_NEXT, "fopen");
    if (!real_fwrite)  real_fwrite  = dlsym(RTLD_NEXT, "fwrite");
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
}

// Track opened files
static void track_file(FILE *fp, const char *path) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (file_table[i].fp == NULL) {
            file_table[i].fp = fp;
            strncpy(file_table[i].path, path, PATH_MAX - 1);
            file_table[i].path[PATH_MAX - 1] = '\0';
            return;
        }
    }
}

// Untrack closed files
static void untrack_file(FILE *fp) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (file_table[i].fp == fp) {
            file_table[i].fp = NULL;
            file_table[i].path[0] = '\0';
            return;
        }
    }
}

// Lookup path by FILE*
static const char *lookup_path(FILE *fp) {
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (file_table[i].fp == fp) {
            return file_table[i].path;
        }
    }
    return NULL;
}

// Compute SHA-256 hash of a file
int compute_hash(const char *path, char *out_hex, size_t out_size) {
    init_real_funcs();
    FILE *f = real_fopen(path, "rb");
    EVP_MD_CTX *ctx;
    unsigned char buf[4096];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    size_t n;

    if (out_size < 65 || f == NULL) return -1;

    ctx = EVP_MD_CTX_new();
    if (!ctx) { real_fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); real_fclose(f); return -1;
    }

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx); real_fclose(f); return -1;
        }
    }

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx); real_fclose(f); return -1;
    }

    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[digest_len * 2] = '\0';

    EVP_MD_CTX_free(ctx);
    real_fclose(f);
    return 0;
}

// Log event to audit log
void log_event(const char *path, int operation, int op_status) {
    char abs_path[PATH_MAX];
    char hash_hex[65];
    uid_t uid = getuid();
    pid_t pid = getpid();
    time_t now = time(NULL);
    
    // Writes to local file
    FILE *log = real_fopen("access_audit.log", "a"); 

    if (realpath(path, abs_path) == NULL) {
        strncpy(abs_path, path, PATH_MAX - 1);
        abs_path[PATH_MAX - 1] = '\0';
    }

    // Don't log the audit log itself!
    if (strstr(abs_path, "access_audit.log") != NULL) {
        if (log) real_fclose(log);
        return;
    }

    if (compute_hash(abs_path, hash_hex, sizeof(hash_hex)) != 0) {
        strcpy(hash_hex, "-");
    }

    if (log) {
        fprintf(log, "%d|%d|%s|%ld|%d|%d|%s\n", uid, pid, abs_path, now, operation, op_status, hash_hex);
        real_fclose(log);
    }
}

FILE *fopen(const char *path, const char *mode) {
    init_real_funcs();
    struct stat st;
    int file_exists = (stat(path, &st) == 0);
    
    FILE *ret = real_fopen(path, mode);
    
    int saved_errno = errno; 

    if (ret == NULL) {
        if (saved_errno == EACCES) {
            log_event(path, file_exists ? 1 : 0, 1); // Denied
            errno = saved_errno;
        }
        return NULL;
    }

    log_event(path, file_exists ? 1 : 0, 0); // Success
    track_file(ret, path);
    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    init_real_funcs();
    size_t ret = real_fwrite(ptr, size, nmemb, stream);
    const char *path = lookup_path(stream);
    if (path != NULL && ret > 0) log_event(path, 2, 0);
    return ret;
}

int fclose(FILE *stream) {
    init_real_funcs();
    
    // save the path before closing
    const char *temp_path = lookup_path(stream);
    char safe_path[PATH_MAX];
    
	// make a safe copy of the path
	// this is required because after fclose, the stream may be invalidated
    if (temp_path != NULL) {
        strncpy(safe_path, temp_path, PATH_MAX - 1);
        safe_path[PATH_MAX - 1] = '\0';
    } else {
        safe_path[0] = '\0';
    }

    // close the file
    int ret = real_fclose(stream);

    // log the fclose event
    if (safe_path[0] != '\0' && ret == 0) {
        log_event(safe_path, 3, 0); // Log fclose
    }
    
    untrack_file(stream);
    return ret;
}