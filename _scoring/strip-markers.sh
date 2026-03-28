#!/usr/bin/env bash
# strip-markers.sh  - Remove BUG-XXXX marker comments from source code for blind testing
#
# Usage: ./strip-markers.sh <project-dir> [--dry-run]
#
# Strips inline comments matching patterns like:
#   // BUG-0042: description
#   # BUG-0042: description
#   /* BUG-0042: description */
#   -- BUG-0042: description
#   <!-- BUG-0042: description -->

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <project-dir> [--dry-run]" >&2
  exit 1
fi

PROJECT_DIR="$1"
DRY_RUN=false

if [ "${2:-}" = "--dry-run" ]; then
  DRY_RUN=true
fi

if [ ! -d "$PROJECT_DIR" ]; then
  echo "Error: '$PROJECT_DIR' is not a directory" >&2
  exit 1
fi

# Count matches first
MATCH_COUNT=$(grep -rn "BUG-[0-9]\{3,4\}" "$PROJECT_DIR" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" --include="*.go" --include="*.rs" --include="*.java" --include="*.kt" --include="*.scala" --include="*.rb" --include="*.php" --include="*.c" --include="*.cpp" --include="*.h" --include="*.cs" --include="*.swift" --include="*.ex" --include="*.exs" --include="*.hs" --include="*.jl" --include="*.r" --include="*.R" --include="*.pl" --include="*.zig" --include="*.sol" --include="*.dart" --include="*.html" --include="*.css" --include="*.sql" --include="*.yaml" --include="*.yml" --include="*.toml" --include="*.tf" --include="*.hcl" --include="*.svelte" --include="*.vue" 2>/dev/null | wc -l || echo 0)

echo "Found $MATCH_COUNT BUG marker(s) in $PROJECT_DIR"

if [ "$DRY_RUN" = true ]; then
  echo "[DRY RUN] Would strip markers from:"
  grep -rln "BUG-[0-9]\{3,4\}" "$PROJECT_DIR" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" --include="*.py" --include="*.go" --include="*.rs" --include="*.java" --include="*.kt" --include="*.scala" --include="*.rb" --include="*.php" --include="*.c" --include="*.cpp" --include="*.h" --include="*.cs" --include="*.swift" --include="*.ex" --include="*.exs" --include="*.hs" --include="*.jl" --include="*.r" --include="*.R" --include="*.pl" --include="*.zig" --include="*.sol" --include="*.dart" --include="*.html" --include="*.css" --include="*.sql" --include="*.yaml" --include="*.yml" --include="*.toml" --include="*.tf" --include="*.hcl" --include="*.svelte" --include="*.vue" 2>/dev/null || true
  exit 0
fi

# Strip patterns:
# 1. Full-line // BUG-XXXX: ... comments → remove entire line
# 2. Full-line # BUG-XXXX: ... comments → remove entire line
# 3. Inline // BUG-XXXX: ... at end of code line → keep code, remove comment
# 4. /* BUG-XXXX: ... */ → remove
# 5. <!-- BUG-XXXX: ... --> → remove
# 6. -- BUG-XXXX: ... → remove

find "$PROJECT_DIR" -type f \( \
  -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
  -o -name "*.py" -o -name "*.go" -o -name "*.rs" -o -name "*.java" \
  -o -name "*.kt" -o -name "*.scala" -o -name "*.rb" -o -name "*.php" \
  -o -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.cs" \
  -o -name "*.swift" -o -name "*.ex" -o -name "*.exs" -o -name "*.hs" \
  -o -name "*.jl" -o -name "*.r" -o -name "*.R" -o -name "*.pl" \
  -o -name "*.zig" -o -name "*.sol" -o -name "*.dart" \
  -o -name "*.html" -o -name "*.css" -o -name "*.sql" \
  -o -name "*.yaml" -o -name "*.yml" -o -name "*.toml" \
  -o -name "*.tf" -o -name "*.hcl" -o -name "*.svelte" -o -name "*.vue" \
\) -print0 | while IFS= read -r -d '' file; do
  # Check if file contains any markers
  if grep -q "BUG-[0-9]\{3,4\}" "$file" 2>/dev/null; then
    # Remove full-line BUG comments (various comment styles)
    # Then remove inline trailing BUG comments
    sed -i '' \
      -e '/^[[:space:]]*\/\/[[:space:]]*BUG-[0-9]\{3,4\}/d' \
      -e '/^[[:space:]]*#[[:space:]]*BUG-[0-9]\{3,4\}/d' \
      -e '/^[[:space:]]*--[[:space:]]*BUG-[0-9]\{3,4\}/d' \
      -e '/^[[:space:]]*\/\*[[:space:]]*BUG-[0-9]\{3,4\}.*\*\//d' \
      -e '/^[[:space:]]*<!--[[:space:]]*BUG-[0-9]\{3,4\}.*-->/d' \
      -e 's/[[:space:]]*\/\/[[:space:]]*BUG-[0-9]\{3,4\}.*$//' \
      -e 's/[[:space:]]*#[[:space:]]*BUG-[0-9]\{3,4\}.*$//' \
      -e 's/[[:space:]]*\/\*[[:space:]]*BUG-[0-9]\{3,4\}.*\*\///' \
      "$file"
    echo "  Stripped: $file"
  fi
done

# Verify
REMAINING=$(grep -rn "BUG-[0-9]\{3,4\}" "$PROJECT_DIR" --include="*.ts" --include="*.js" --include="*.py" --include="*.go" --include="*.rs" --include="*.java" --include="*.php" --include="*.c" --include="*.cpp" --include="*.h" 2>/dev/null | wc -l || echo 0)

if [ "$REMAINING" -gt 0 ]; then
  echo "WARNING: $REMAINING marker(s) remaining (may need manual review)" >&2
else
  echo "All markers stripped successfully."
fi
