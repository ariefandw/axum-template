#!/usr/bin/env bash
# =============================================================================
# scripts/rename-template.sh
# Rename axum-template to a new project name across the entire codebase.
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
# Rust crate identifier (kebab-case to snake_case for rust module/db names)
NEW_SNAKE="${NEW_NAME//-/_}"

echo "==> Renaming axum-template -> ${NEW_NAME} (${NEW_SNAKE})..."

# 1. Cargo.toml
sed -i.bak "s/name = \"axum-template\"/name = \"${NEW_NAME}\"/g" Cargo.toml
rm -f Cargo.toml.bak

# 2. docker-compose.yml
if [ -f docker-compose.yml ]; then
    sed -i.bak "s/axum_template_dev/${NEW_SNAKE}_dev/g" docker-compose.yml
    sed -i.bak "s/axum-template/${NEW_NAME}/g" docker-compose.yml
    rm -f docker-compose.yml.bak
fi

# 3. .env.example
if [ -f .env.example ]; then
    sed -i.bak "s/axum_template_dev/${NEW_SNAKE}_dev/g" .env.example
    rm -f .env.example.bak
fi

# 4. CI workflow
if [ -f .github/workflows/ci.yml ]; then
    sed -i.bak "s/axum_template_test/${NEW_SNAKE}_test/g" .github/workflows/ci.yml
    rm -f .github/workflows/ci.yml.bak
fi

# 5. Integration tests (replace axum_template:: with new_snake::)
find tests -type f -name "*.rs" | while read -r file; do
    sed -i.bak "s/axum_template::/${NEW_SNAKE}::/g" "$file"
    rm -f "${file}.bak"
done

# 6. src/main.rs (replace axum_template:: with new_snake::)
if [ -f src/main.rs ]; then
    sed -i.bak "s/axum_template::/${NEW_SNAKE}::/g" src/main.rs
    rm -f src/main.rs.bak
fi

# 7. src/bin/export_openapi.rs
if [ -f src/bin/export_openapi.rs ]; then
    sed -i.bak "s/axum_template::/${NEW_SNAKE}::/g" src/bin/export_openapi.rs
    rm -f src/bin/export_openapi.rs.bak
fi

echo "==> Successfully renamed template to '${NEW_NAME}'!"
echo "==> Re-exporting openapi.json and checking build..."
cargo check
cargo run --bin export_openapi
echo "==> All set! You're ready to build your app."
