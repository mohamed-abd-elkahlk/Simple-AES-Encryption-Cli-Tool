#!/bin/bash

# Define the base directory
BASE_DIR="./test_dir"
mkdir -p "$BASE_DIR"

# Define file extensions and directories
declare -A dirs_and_exts=(
    ["$BASE_DIR/text_files"]=".txt"
    ["$BASE_DIR/image_files"]=".jpg"
    ["$BASE_DIR/audio_files"]=".mp3"
    ["$BASE_DIR/video_files"]=".mp4"
    ["$BASE_DIR/archive_files"]=".zip"
)

# Function to generate a 1GB file
generate_1g_file() {
    local dir=$1
    local ext=$2
    local filename="file_$(date +%s)$ext"
    local filepath="$dir/$filename"
    
    echo "Generating 1GB file: $filepath"
    dd if=/dev/zero of="$filepath" bs=1M count=1
}

# Generate files in different directories with different extensions
for dir in "${!dirs_and_exts[@]}"; do
    mkdir -p "$dir"
    ext="${dirs_and_exts[$dir]}"
    generate_1g_file "$dir" "$ext"
done

echo "All files generated successfully in $BASE_DIR"