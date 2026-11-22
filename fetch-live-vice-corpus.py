#!/usr/bin/env python3
"""Fetch the original VICE programs and references pinned by the website case plan."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("indices", type=int, nargs="*")
    args = parser.parse_args()
    data = args.plan.read_bytes()
    if hashlib.sha256(data).hexdigest() != "a3c2663899bd07187da90345a5a77c2bae5b2a0b3a57058ca7bdce743356f05d":
        parser.error("Wrong frozen case plan")
    plan = json.loads(data)
    suite = plan["policy_context"]["suite"]
    base = f"https://raw.githubusercontent.com/{suite['repository']}/{suite['revision']}/"
    cases = plan["cases"]
    selected = set(args.indices or range(len(cases)))
    if not selected <= set(range(len(cases))):
        parser.error("Original index out of range")
    selected.update((0, 1))
    asset_ids = set()
    for index in selected:
        row = cases[index]
        asset_ids.update(slot["asset"] for slot in row["slots"])
        if row["comparison"]:
            asset_ids.add(row["comparison"]["reference"])
    paths = {"testbench/x64sc-testlist.txt": suite["testlist"]}
    for asset in plan["assets"]:
        if asset["id"] in asset_ids and asset["state"] == "available" and asset["source"]["kind"] == "upstream":
            paths[asset["source"]["path"]] = asset

    def fetch(item):
        relative, descriptor = item
        filename = args.corpus / relative
        size = descriptor["bytes"]
        if filename.exists():
            payload = filename.read_bytes()
        else:
            with urlopen(base + quote(relative, safe="/"), timeout=30) as response:
                payload = response.read(size + 1)
        if len(payload) != size or hashlib.sha256(payload).hexdigest() != descriptor["sha256"]:
            raise ValueError(f"Upstream bytes changed for {relative}")
        if not filename.exists():
            filename.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=filename.parent, delete=False) as handle:
                pending = Path(handle.name)
                try:
                    handle.write(payload)
                    handle.close()
                    pending.replace(filename)
                finally:
                    pending.unlink(missing_ok=True)
            return True
        return False

    total = len(paths)
    print(f"Preparing {total} VICE input files. The C64 preview opens after setup.", flush=True)
    downloaded = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch, item): item[0] for item in paths.items()}
        for count, future in enumerate(as_completed(futures), 1):
            try:
                downloaded += future.result()
            except (OSError, ValueError) as error:
                for job in futures:
                    job.cancel()
                print(f"Could not verify {futures[future]}: {error}", file=sys.stderr, flush=True)
                print("Run the same command again to reuse the completed downloads.", file=sys.stderr)
                return 1
            if count == 1 or count % 25 == 0 or count == total:
                print(f"Verified {count}/{total} VICE input files ({downloaded} downloaded)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
