#!/bin/bash

#
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <target_directory> [number_of_files]"
    exit 1
fi

TARGET_DIR=$1
COUNT=$2

# Create the directory if it doesn't exist
mkdir -p "$TARGET_DIR"
if 

# Only generate files if a count (2nd argument) is provided
if [ -n "$COUNT" ]; then
    echo "Generating $COUNT files in $TARGET_DIR..."
    for ((i=1; i<=COUNT; i++)); do
        echo "This is dummy content for file $i" > "$TARGET_DIR/file_$i.txt"
    done
else
    echo "No file count provided. Skipping generation and targeting existing files..."
fi

echo "Starting encryption routine..."

# Iterate over the files in the directory
for file in "$TARGET_DIR"/*; do
    # Safety check: Ensure it is a regular file
    if [ ! -f "$file" ]; then
        continue
    fi

    # 1. Skip files that are already encrypted (end in .enc)
    if [[ "$file" == *.enc ]]; then
        continue
    fi

    # 2. Encrypt the file using OpenSSL
    # Note: Using -pbkdf2 is recommended for newer OpenSSL versions to avoid warnings
    if openssl enc -aes-256-cbc -salt -in "$file" -out "${file}.enc" -k "password" -pbkdf2; then
        
        # 3. Delete the original file ONLY if encryption succeeded
        rm "$file"
        echo "Encrypted and deleted: $file"
    else
        echo "Encryption failed for $file. Original not deleted."
    fi
done