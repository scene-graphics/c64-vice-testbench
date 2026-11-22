#!/bin/sh
# Run case observations against the signed C64 WASM that scene.graphics serves.
set -eu
umask 077

if [ "$#" -lt 3 ]; then
    echo "Usage: sh run-live-vice.sh VICE_CORPUS PLAN_JSON OUTPUT_DIR [ORIGINAL_INDEX ...]" >&2
    exit 2
fi
corpus=$1
plan=$2
output=$3
shift 3
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$output"
node "$here/src/showcase.mjs" --verify-engine --output "$output/website"
python3 "$here/run-live-vice-batch.py" "$output/website" "$corpus" "$plan" "$output" "$@"
python3 "$here/reconcile-live-vice.py" "$plan" "$output/receipts" > "$output/qualification.json"
python3 - "$output/qualification.json" <<'C64_WEBSITE_SUMMARY'
import json
import sys

with open(sys.argv[1]) as handle:
    report = json.load(handle)
if report["score_ready"]:
    print("Website VICE compatibility {:.1f}% ({}/{} applicable)".format(
        report["percent"], report["counts"]["pass"], report["applicable"]))
else:
    print("Verified website passes so far: {}. Final score pending for {} original outcomes.".format(
        report["verified_passes"], report["unresolved_originals"]))
C64_WEBSITE_SUMMARY
printf 'Saved qualification to %s\n' "$output/qualification.json"
