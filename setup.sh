#!/bin/bash
SOURCE_DIR="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS"
DEST_DIR="./remediators"
OUTPUT_DIR="./output"

if [ ! -d "$DEST_DIR" ]; then
    echo "Creating directory: $DEST_DIR"
    mkdir -p "$DEST_DIR"
fi

echo "Copying remediators..."
sudo cp "$SOURCE_DIR"/XProtectRemediator* "$DEST_DIR"
echo "Copy completed."

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

echo "[+] Extracting configs..."
for file in "$DEST_DIR"/*; do
    filename=$(basename "$file")
    echo "[+] Working on $filename..."
    python3 config.py "$DEST_DIR/$filename" > "$OUTPUT_DIR/${filename#XProtectRemediator}.txt"
    echo "[+] $filename extraction complete!"
done

echo "congratz u haxor!"
