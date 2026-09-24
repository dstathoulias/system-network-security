#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define MAX_LOGS 1000
#define MAX_PATH 4096

// Structure to hold a log entry
typedef struct {
    int uid;
    char path[MAX_PATH];
    int operation;
    int denied;
    char hash[65];
} LogEntry;

LogEntry entries[MAX_LOGS];
int log_count = 0;

// Load logs from the audit log file
void load_logs(FILE *fp) {
    char line[MAX_PATH + 200];
    log_count = 0;
    rewind(fp);

    while (fgets(line, sizeof(line), fp) && log_count < MAX_LOGS) {
        char *token = strtok(line, "|");
        if (!token) continue;
        entries[log_count].uid = atoi(token);

        strtok(NULL, "|"); // PID
        token = strtok(NULL, "|");
        if (token) strcpy(entries[log_count].path, token);

        strtok(NULL, "|"); // Time
        token = strtok(NULL, "|");
        if (token) entries[log_count].operation = atoi(token);

        token = strtok(NULL, "|");
        if (token) entries[log_count].denied = atoi(token);

        token = strtok(NULL, "\n");
        if (token) {
            token[strcspn(token, "\r")] = 0; 
            strcpy(entries[log_count].hash, token);
        }
        log_count++;
    }
}

// List file modifications for a given file
void list_file_modifications(FILE *log, char *file_to_scan) {
    load_logs(log);
    int users[100], writes[100], user_count = 0;
    char distinct_hashes[100][65];
    int hash_count = 0;

    // Resolve absolute path of the input file for better matching
    char abs_search_path[PATH_MAX];
    if (realpath(file_to_scan, abs_search_path) == NULL) {
        // If file doesn't exist (e.g. deleted), fall back to input string
        strncpy(abs_search_path, file_to_scan, PATH_MAX);
    }

    printf("--- Analysis for %s ---\n", file_to_scan);

    for (int i = 0; i < log_count; i++) {
        // Improved Matching: Check exact match OR if path ends with filename
        int match = 0;
        if (strcmp(entries[i].path, file_to_scan) == 0) match = 1;
        else if (strstr(entries[i].path, file_to_scan) != NULL) match = 1; // Simple substring match
        
        if (!match) continue;

        // Track Users
        int u_idx = -1;
        for(int u=0; u<user_count; u++) if(users[u] == entries[i].uid) u_idx = u;
        if (u_idx == -1) { users[user_count] = entries[i].uid; writes[user_count] = 0; u_idx = user_count++; }
        
        if (entries[i].operation == 2 && entries[i].denied == 0) writes[u_idx]++;

        // Track Hashes
        if (strcmp(entries[i].hash, "-") != 0) {
            int h_seen = 0;
            for(int h=0; h<hash_count; h++) if(strcmp(distinct_hashes[h], entries[i].hash) == 0) h_seen = 1;
            if (!h_seen) {
                strcpy(distinct_hashes[hash_count++], entries[i].hash);
            }
        }
    }

    int unique_mods = (hash_count > 0) ? hash_count - 1 : 0;
    printf("Unique modifications: %d\n", unique_mods);
    
    for(int k=0; k<user_count; k++) {
        printf("User %d: %d writes\n", users[k], writes[k]);
    }
}

// List users with excessive unauthorized accesses
void list_unauthorized_accesses(FILE *log) {
    load_logs(log);
    int printed_uids[100], printed_count = 0;
    for (int i = 0; i < log_count; i++) {
        int uid = entries[i].uid;
        int checked = 0;
        for(int k=0; k<printed_count; k++) if(printed_uids[k] == uid) checked = 1;
        if (checked) continue;
        char denied_paths[100][MAX_PATH];
        int distinct = 0;
        for (int j = 0; j < log_count; j++) {
            if (entries[j].uid == uid && entries[j].denied == 1) {
                int seen = 0;
                for(int p=0; p<distinct; p++) if(strcmp(denied_paths[p], entries[j].path) == 0) seen = 1;
                if (!seen) strcpy(denied_paths[distinct++], entries[j].path);
            }
        }
        if (distinct > 5) printf("Suspicious User UID: %d (Denied on %d distinct files)\n", uid, distinct);
        printed_uids[printed_count++] = uid;
    }
}

void usage(void) {
    printf("usage: ./audit_monitor -i <file> | -s\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage();
    FILE *log = fopen("access_audit.log", "r"); 
    if (!log) { printf("Error: cannot open access_audit.log\n"); return 1; }
    int ch;
    while ((ch = getopt(argc, argv, "hi:s")) != -1) {
        switch (ch) {       
            case 'i': list_file_modifications(log, optarg); break;
            case 's': list_unauthorized_accesses(log); break;
            default: usage();
        }
    }
    fclose(log);
    return 0;
}