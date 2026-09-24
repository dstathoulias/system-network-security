**Assignment 3: Access Control Logging - README**

**Author Information**
⦁	**Author**: ΔΗΜΗΤΡΗΣ ΣΤΑΘΟΥΛΙΑΣ
⦁	**AM**: 2018030109
⦁	**Institution**: Technical University of Crete
⦁	**Department**: School of Electrical & Computer Engineering
⦁	**Course**: Ασφάλεια Συστημάτων και Υπηρεσιών
⦁	**Date**: 19/11/2025
⦁	**Instructor**: ΣΩΤΗΡΙΟΣ ΙΩΑΝΝΙΔΗΣ

**Tool Introduction**
This assignment implements a complete access control auditing tool using C. It monitors file operations at runtime and records them into a structured audit file. Then, another tool analyzes the audit logs in order to detect suspicious, which in this implementation corresponds to access and edit files the user does not have permissions for.

**Project files**
⦁	audit_logger.c: File operations monitoring library using LD_PRELOAD to override default C at runtime (Task 1).
⦁	audit_logger.so: Compiled audit_logger.c library.
⦁	audit_monitor.c: Tool for analyzing log for suspicious activity and file changes (Task 2).
⦁	test_audit.c: Program that generates log entries used for testing the tool (Task 3).
⦁	access_audit.log: Log file for recording events. Generated inside program folder at runtime.
⦁	Makefile: Compiles the C programs of the tool.
⦁	README.md: this file.

**Task 1: Audit Logging Library**
This task was implemented inside audit_logger.c file. The key of this task is using LD_PRELOAD to load our custom library before the default ones, effectively overriding them. 

The following methods are included in the file:
⦁	init_real_funcs: Initializes the original operations we intend to override and saves them to custom variables. This is done because overriding the original operations prevents us from using them inside the file.
⦁	track_file, untrach_file, lookup_path: Helper methods for linking files to absolute filepaths. Used fro correct logging of fwrite and fclose operations.
⦁	compute_hash: Calculates the SHA-256 has of the file contents using OpenSSL EVP.
⦁	log_event: Method to add entries to the log file. 
Each entry is formated as such: UID|PID|ABS_PATH|TIME|OP_TYPE|OP_STATUS|HASH
Instead of tracking date and time individually we log current epoch using now() method.
⦁	fopen, fwrite, fclose: Overriden file operation functions. We check whether user has permission to access file (error EACCES: permission denied) and add log entry.

**Task 2: Audit Log Analyzer**
This task was implemented inside audit_monitor.c file. In this task we create a command-line analysis tool which is used to parse the log file and detect suspicious activity from users and display file modification history. 

The following methods are included in the file:
⦁	load_logs: Reads log file line by line and loads entries into an array of log entries.
⦁	list_unauthorized_accesses: Iterates through the logs and classifies a user as suspicious if their denied access count exceeds 5.
⦁	list_file_modifications: Filters logs for a specified file and calculated total modifications made.

**Task 3: Testing the Audit System**
This task was implemented inside test_audit.c file. In this task we generate several files both accessible and inaccessible by the users to test the tool. 
This is executed in 2 phases:
1. Create several files normally (permissions granted), write to each file and close it. This is done to ensure the correct predicted tool activity under normal usage.
2. Create files, remove permissions (cmod 000) and attempt to open them producing EACCES errors. This is done to test the tools use in logging suspicious behaviour.


How to run
⦁	make clean
⦁	make
⦁	make run
Expected output:
=== Phase 1: Normal Operations (Should be allowed) ===
[SUCCESS] Created/Wrote file_0.txt
[SUCCESS] Created/Wrote file_1.txt
[SUCCESS] Created/Wrote file_2.txt
[SUCCESS] Created/Wrote file_3.txt
[SUCCESS] Created/Wrote file_4.txt
=== Phase 2: Generating Denied Accesses (Should be denied) ===
Creating locked files and attempting to write to them...
[EXPECTED] Access DENIED for locked_file_0.txt (EACCES)
[EXPECTED] Access DENIED for locked_file_1.txt (EACCES)
[EXPECTED] Access DENIED for locked_file_2.txt (EACCES)
[EXPECTED] Access DENIED for locked_file_3.txt (EACCES)
[EXPECTED] Access DENIED for locked_file_4.txt (EACCES)
[EXPECTED] Access DENIED for locked_file_5.txt (EACCES)

⦁	./audit_monitor -s
Expected output:
Suspicious User UID: [UID] (Denied on 6 distinct files)
./audit_monitor -i file_0.txt
Expected output:
--- Analysis for file_0.txt ---
Unique modifications: 1
User [UID]: 1 writes