#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

int main() {
    int i;
    FILE *file;
    char filename[32];

    printf("=== Phase 1: Normal Operations (Should be allowed) ===\n");
    
    // Create and write to 5 files normally
    for (i = 0; i < 5; i++) {
        sprintf(filename, "file_%d.txt", i);
        file = fopen(filename, "w+");
        if (file) {
            fwrite("test", 4, 1, file);
            fclose(file);
            printf("[SUCCESS] Created/Wrote %s\n", filename);
        } else {
            printf("[ERROR] Failed to open %s\n", filename);
        }
    }

    printf("\n=== Phase 2: Generating Denied Accesses (Should be denied) ===\n");
    printf("Creating locked files and attempting to write to them...\n");

    // We need > 5 distinct files to trigger the suspicious user alert
    for (i = 0; i < 6; i++) {
        sprintf(filename, "locked_file_%d.txt", i);
        
        // Create the file first
        file = fopen(filename, "w");
        if (file) fclose(file);

        // Remove ALL permissions (chmod 000)
        chmod(filename, 0000);

        // Attempt to open for writing (This MUST fail and be logged as denied)
        file = fopen(filename, "w");
        if (file == NULL) {
            // Expected behavior
            if (errno == EACCES) {
                printf("[EXPECTED] Access DENIED for %s (EACCES)\n", filename);
            } else {
                printf("[ unexpected ] Failed with errno %d for %s\n", errno, filename);
            }
        } else {
            // Unexpected behavior (if running as root, this might happen)
            printf("[WARNING] Opened %s despite chmod 000! (Are you root?)\n", filename);
            fclose(file);
        }
        
        // Cleanup: Restore permissions so we can delete them later if needed
        chmod(filename, 0666); 
    }

    return 0;
}