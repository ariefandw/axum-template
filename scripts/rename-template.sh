#!/usr/bin/env bash
# =============================================================================
# scripts/rename-template.sh
# Robust, two-pass renaming of axum-template across the entire codebase.
# Usage: ./scripts/rename-template.sh <new-app-name>
# Example: ./scripts/rename-template.sh my-cool-saas
# =============================================================================
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-app-name>"
    echo "Example: $0 my-cool-saas"
    exit 1
fi

NEW_NAME="$1"
# Convert kebab-case to snake_case for Rust crate, module, and database names
NEW_SNAKE="${NEW_NAME//-/_}"

echo "==> Renaming template across all files:"
echo "    axum-template -> ${NEW_NAME}"
echo "    axum_template -> ${NEW_SNAKE}"

# Target files that contain crate/app names (excluding .git, target, scripts, etc.)
FILES_TO_REPLACE=(
    Cargo.toml
    docker-compose.yml
    .env.example
    .github/workflows/ci.yml
    README.md
    openapi.json
)

# 1. Replace in explicitly tracked configuration files
for file in "${FILES_TO_REPLACE[@]}"; do
    if [ -f "$file" ]; then
        sed -i.bak "s/axum_template/${NEW_SNAKE}/g" "$file"
        sed -i.bak "s/axum-template/${NEW_NAME}/g" "$file"
        rm -f "${file}.bak"
    fi
done

# 2. Replace in all Rust source files (src/**/*.rs, tests/**/*.rs)
find src tests -type f -name "*.rs" | while read -r file; do
    sed -i.bak "s/axum_template/${NEW_SNAKE}/g" "$file"
    sed -i.bak "s/axum-template/${NEW_NAME}/g" "$file"
    rm -f "${file}.bak"
done

echo "==> Re-exporting openapi.json and checking compilation..."
cargo check --all-targets --all-features
cargo run --bin export_openapi

echo "==> SUCCESS: Project successfully renamed to '${NEW_NAME}'!"
echo "    Verify with 'git diff' and commit your changes."
