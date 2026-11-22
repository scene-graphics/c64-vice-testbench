#!/bin/sh
# Verify the signed website WASM. Requires Node.js 22+, Python 3 and curl.
set -eu
umask 077
if [ "$#" -eq 0 ]; then
    echo "Usage: sh scene-c64-live-vice.sh OUTPUT_DIR [ORIGINAL_INDEX ...]" >&2
    exit 2
fi
output=$1
shift
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ -e "$output/run" ]; then
    echo "An emulator run already exists in $output/run. Choose a different output directory." >&2
    exit 2
fi
mkdir -p -- "$output"
python3 "$here/fetch-live-vice-corpus.py" "$here/authoring-plan.json" "$output/corpus" "$@"
C64_LIVE_PREVIEW="${C64_LIVE_PREVIEW:-1}" \
C64_BALANCED28_SOURCE="$here/glyph_probe_codes.py" sh "$here/run-live-vice.sh" \
    "$output/corpus" "$here/authoring-plan.json" "$output/run" "$@"
