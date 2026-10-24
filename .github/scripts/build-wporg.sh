#!/usr/bin/env bash
# Build the WordPress.org edition of the plugin from the current commit.
#
#   bash .github/scripts/build-wporg.sh [output-dir]
#
# Writes <output-dir>/anderson-shell-scanner/ (the folder that goes into
# SVN trunk) and <output-dir>/anderson-shell-scanner.zip (for the first
# submission at wordpress.org/plugins/developers/add/).
#
# Differences from the GitHub release zip:
#   * no includes/class-updater.php — WordPress.org plugins may only update
#     through WordPress.org (guideline 8); the plugin notices the file is
#     missing and checks itself against WordPress.org's checksums instead;
#   * no "Update URI" header, which would stop WordPress.org updates;
#   * no manifest.json.
set -euo pipefail

SLUG=anderson-shell-scanner
ROOT=$(git rev-parse --show-toplevel)
OUT=$(realpath -m "${1:-$ROOT/build}")
DEST="$OUT/$SLUG"

rm -rf "$DEST" "$OUT/$SLUG.zip"
mkdir -p "$DEST"
git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$DEST"

rm -f "$DEST/includes/class-updater.php" "$DEST/manifest.json"
sed -i '/^ \* Update URI:/d' "$DEST/wp2shell-scanner.php"

# Sanity checks: nothing that talks to GitHub or replaces WordPress updates may remain.
if grep -rnE "Update URI|pre_set_site_transient_update_plugins|api\.github\.com" "$DEST" --include='*.php'; then
	echo "error: GitHub update code left in the WordPress.org build" >&2
	exit 1
fi
V_HEADER=$(sed -n 's/^ \* Version: *//p' "$DEST/wp2shell-scanner.php" | tr -d '[:space:]')
V_README=$(sed -n 's/^Stable tag: *//p' "$DEST/readme.txt" | tr -d '[:space:]')
[ "$V_HEADER" = "$V_README" ] || { echo "error: version $V_HEADER vs Stable tag $V_README" >&2; exit 1; }

(cd "$OUT" && zip -qr "$SLUG.zip" "$SLUG")
echo "Built $SLUG $V_HEADER → $OUT/$SLUG.zip"
