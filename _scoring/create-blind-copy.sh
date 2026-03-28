#!/usr/bin/env bash
# create-blind-copy.sh  - Create a blind testing copy with BUG markers stripped
#
# Usage: ./create-blind-copy.sh [--target <dir>]
#
# Creates _blind/ directory with all project code but no BUG-XXXX or RH-XXX comments.
# Also excludes _manifests/*.json (only .enc files are copied).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$ROOT_DIR/_blind}"

echo "Creating blind testing copy at: $TARGET"

# Clean target if exists
rm -rf "$TARGET"
mkdir -p "$TARGET"

# Copy project directories from vaults/ folder
for dir in "$ROOT_DIR"/vaults/*/; do
  dirname="$(basename "$dir")"
  echo "  Copying $dirname..."
  cp -r "$dir" "$TARGET/$dirname"
done

# Copy scoring tools and encrypted manifests
mkdir -p "$TARGET/_scoring" "$TARGET/_manifests"
cp "$ROOT_DIR/_scoring/"*.ts "$TARGET/_scoring/" 2>/dev/null || true
cp "$ROOT_DIR/_scoring/"*.sh "$TARGET/_scoring/" 2>/dev/null || true
cp "$ROOT_DIR/_scoring/package.json" "$TARGET/_scoring/" 2>/dev/null || true

# Only copy .enc files (not .json plaintext!)
cp "$ROOT_DIR/_manifests/"*.enc "$TARGET/_manifests/" 2>/dev/null || true

# Copy CLAUDE.md
cp "$ROOT_DIR/CLAUDE.md" "$TARGET/" 2>/dev/null || true

# Now strip all BUG markers from the blind copy
echo ""
echo "Stripping BUG markers..."

TOTAL_STRIPPED=0

find "$TARGET" -type f \( \
  -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
  -o -name "*.py" -o -name "*.go" -o -name "*.rs" -o -name "*.java" \
  -o -name "*.kt" -o -name "*.scala" -o -name "*.rb" -o -name "*.erb" \
  -o -name "*.php" -o -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.hpp" \
  -o -name "*.cs" -o -name "*.swift" -o -name "*.ex" -o -name "*.exs" \
  -o -name "*.hs" -o -name "*.jl" -o -name "*.r" -o -name "*.R" \
  -o -name "*.pl" -o -name "*.pm" -o -name "*.ep" \
  -o -name "*.zig" -o -name "*.sol" -o -name "*.dart" \
  -o -name "*.html" -o -name "*.css" -o -name "*.svelte" -o -name "*.vue" \
  -o -name "*.sql" -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" \
  -o -name "*.tf" -o -name "*.hcl" -o -name "*.prisma" -o -name "*.proto" \
  -o -name "*.conf" -o -name "*.sh" -o -name "*.bash" \
\) -print0 | while IFS= read -r -d '' file; do
  if grep -q "BUG-[0-9]" "$file" 2>/dev/null || grep -q "RH-[0-9]" "$file" 2>/dev/null || grep -q "RED-HERRING-[0-9]" "$file" 2>/dev/null; then
    # Remove full-line BUG/RH comments
    sed -i '' \
      -e '/^[[:space:]]*\/\/[[:space:]]*BUG-[0-9]/d' \
      -e '/^[[:space:]]*\/\/[[:space:]]*RH-[0-9]/d' \
      -e '/^[[:space:]]*\/\/[[:space:]]*RED-HERRING-[0-9]/d' \
      -e '/^[[:space:]]*#[[:space:]]*BUG-[0-9]/d' \
      -e '/^[[:space:]]*#[[:space:]]*RH-[0-9]/d' \
      -e '/^[[:space:]]*#[[:space:]]*RED-HERRING-[0-9]/d' \
      -e '/^[[:space:]]*--[[:space:]]*BUG-[0-9]/d' \
      -e '/^[[:space:]]*--[[:space:]]*RH-[0-9]/d' \
      -e '/^[[:space:]]*--[[:space:]]*RED-HERRING-[0-9]/d' \
      -e '/^[[:space:]]*\/\*[[:space:]]*BUG-[0-9].*\*\//d' \
      -e '/^[[:space:]]*<!--[[:space:]]*BUG-[0-9].*-->/d' \
      -e 's/[[:space:]]*\/\/[[:space:]]*BUG-[0-9].*$//' \
      -e 's/[[:space:]]*\/\/[[:space:]]*RH-[0-9].*$//' \
      -e 's/[[:space:]]*\/\/[[:space:]]*RED-HERRING-[0-9].*$//' \
      -e 's/[[:space:]]*#[[:space:]]*BUG-[0-9].*$//' \
      -e 's/[[:space:]]*#[[:space:]]*RH-[0-9].*$//' \
      -e 's/[[:space:]]*#[[:space:]]*RED-HERRING-[0-9].*$//' \
      -e 's/[[:space:]]*--[[:space:]]*BUG-[0-9].*$//' \
      -e 's/[[:space:]]*--[[:space:]]*RH-[0-9].*$//' \
      -e 's/[[:space:]]*--[[:space:]]*RED-HERRING-[0-9].*$//' \
      -e 's/[[:space:]]*\/\*[[:space:]]*BUG-[0-9].*\*\///' \
      -e 's/[[:space:]]*\/\*[[:space:]]*RH-[0-9].*\*\///' \
      "$file"
    TOTAL_STRIPPED=$((TOTAL_STRIPPED + 1))
  fi
done

# Verify no markers remain
REMAINING=$(grep -r "BUG-[0-9]" "$TARGET" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.java" --include="*.kt" --include="*.scala" --include="*.rb" --include="*.php" --include="*.c" --include="*.cpp" --include="*.cs" --include="*.swift" --include="*.ex" --include="*.hs" --include="*.jl" --include="*.r" --include="*.R" --include="*.pl" --include="*.pm" --include="*.zig" --include="*.sol" --include="*.dart" --include="*.svelte" --include="*.vue" --include="*.sql" --include="*.tf" --include="*.yaml" --include="*.yml" --include="*.toml" --include="*.html" --include="*.conf" --include="*.sh" 2>/dev/null | grep -v "_scoring/" | grep -v "_manifests/" | grep -v "node_modules/" | wc -l || echo 0)

echo ""
if [ "$REMAINING" -gt 0 ]; then
  echo "WARNING: $REMAINING marker references remaining in blind copy!"
  grep -r "BUG-[0-9]" "$TARGET" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.java" --include="*.php" --include="*.c" --include="*.cpp" --include="*.sol" --include="*.zig" --include="*.dart" --include="*.sql" 2>/dev/null | grep -v "_scoring/" | grep -v "_manifests/" | grep -v "node_modules/" | head -20
else
  echo "All markers stripped successfully."
fi

# Count files in blind copy
FILE_COUNT=$(find "$TARGET" -type f | wc -l | tr -d ' ')
DIR_COUNT=$(find "$TARGET" -type d | wc -l | tr -d ' ')
echo ""
echo "Blind copy complete: $FILE_COUNT files in $DIR_COUNT directories"
echo "Location: $TARGET"
