#!/bin/bash
# Generate all types of signing keys by calling the gen-signing-keys.sh script
#
# This script generates various types of keys:
# - RSA keys with different sizes (2048, 3072, 4096)
# - EC keys with different curves (p256, p384, p521)
# - ED25519 keys
#
# The keys are stored in separate directories named after their types.

# Set the base directory where all keys will be stored
BASE_DIR="./signing-keys"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN_SCRIPT="${SCRIPT_DIR}/gen-signing-keys.sh"

# Make sure the base directory exists
mkdir -p "$BASE_DIR"

echo "=== Generating all types of signing keys ==="
echo "Using script: $GEN_SCRIPT"
echo "Output directory: $BASE_DIR"

# Function to generate keys and handle errors
generate_keys() {
    local key_type=$1
    local key_size=$2
    local output_dir="${BASE_DIR}/${key_type}"
    
    if [ -n "$key_size" ]; then
        output_dir="${output_dir}-${key_size}"
    fi
    
    echo "Generating $key_type keys${key_size:+ with size/curve $key_size}..."
    
    mkdir -p "$output_dir"
    
    if [ -n "$key_size" ]; then
        "$GEN_SCRIPT" --output-dir="$output_dir" --key-type="$key_type" --key-size="$key_size"
    else
        "$GEN_SCRIPT" --output-dir="$output_dir" --key-type="$key_type"
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully generated $key_type keys${key_size:+ with size/curve $key_size} in $output_dir"
    else
        echo "❌ Failed to generate $key_type keys${key_size:+ with size/curve $key_size}"
    fi
    
    echo ""
}

# Generate RSA keys with different sizes
generate_keys "rsa" "2048"
generate_keys "rsa" "3072"
generate_keys "rsa" "4096"

# Generate EC keys with different curves
generate_keys "ec" "p256"
generate_keys "ec" "p384"
generate_keys "ec" "p521"

# Generate ED25519 keys
generate_keys "ed25519"

echo "=== Key generation complete ==="
echo "All keys have been generated in $BASE_DIR"
echo "Summary of generated keys:"
find "$BASE_DIR" -maxdepth 1 -type d -not -path "$BASE_DIR" | sort | while read -r dir; do
    echo "- $(basename "$dir")"
done