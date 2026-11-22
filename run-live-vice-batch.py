#!/usr/bin/env python3
"""Run disjoint original VICE cases in independent Node processes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import runpy
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("website", type=Path)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("indices", type=int, nargs="*")
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    args = parser.parse_args()
    indices = sorted(args.indices or range(1544))
    if not 1 <= args.jobs <= 16 or len(set(indices)) != len(indices) or not all(0 <= i < 1544 for i in indices):
        parser.error("Use 1–16 jobs and unique original indices in the range 0–1543")
    reuse = os.environ.get("C64_WEBSITE_REUSE")
    if reuse and os.environ.get("C64_NATIVE_SCREENSHOTS") == "1":
        parser.error("Native screenshot capture requires fresh receipts")
    receipts = args.output / "receipts"
    receipts.mkdir()
    probe = Path(__file__).resolve().with_name("probe-live-vice.mjs")
    pending = indices
    if reuse:
        audit = runpy.run_path(probe.with_name("reconcile-live-vice.py"))
        plan_bytes = args.plan.read_bytes()
        if audit["hashlib"].sha256(plan_bytes).hexdigest() != audit["PLAN_SHA"]:
            raise ValueError("Wrong frozen case plan")
        plan = json.loads(plan_bytes)
        assets = {entry["id"]: entry for entry in plan["assets"]}
        pending = []
        for index in indices:
            name = f"{index:04d}.json"
            prior = Path(reuse) / name
            row = plan["cases"][index]
            if prior.is_file():
                observed = json.loads(prior.read_bytes())
                if (observed["index"], observed["line"], observed["build"], observed["wasmSha256"]) != (
                    index, row["line"], audit["WEBSITE_BUILD"], audit["WEBSITE_WASM"]
                ):
                    raise ValueError(f"Prior receipt identity mismatch for original {index}")
                if audit["verdict"](row, observed, assets) not in audit["UNRESOLVED"]:
                    os.link(prior, receipts / name)
                    continue
            pending.append(index)
    workers = min(args.jobs, len(pending))
    queue = args.output / "claims"
    queue.mkdir()
    command = ["node", str(probe), str(args.website), str(args.corpus), str(args.plan),
               "--queue-v1", *(str(index) for index in pending)]
    worker_env = {**os.environ, "C64_WEBSITE_RECEIPTS": str(receipts), "C64_WEBSITE_QUEUE": str(queue)}
    children = []
    preview = None
    if workers and os.environ.get("C64_LIVE_PREVIEW") == "1":
        try:
            from live_vice_preview import start_preview
            preview = start_preview(args.output, workers)
        except OSError as error:
            print(f"Live preview unavailable: {error}", file=sys.stderr, flush=True)
    try:
        for worker in range(workers):
            with (args.output / f"shard-{worker}.json").open("x") as observations, \
                 (args.output / f"shard-{worker}.stderr").open("x") as errors:
                env = worker_env.copy()
                if preview:
                    env["C64_PREVIEW_FRAME"] = str((args.output / "preview" / f"{worker}.frame").resolve())
                child = subprocess.Popen(command, stdout=observations, stderr=errors, env=env)
            children.append(child)
        previous = None
        while active := [child for child in children if child.poll() is None]:
            finished = {int(file.stem) for file in receipts.glob("[0-9][0-9][0-9][0-9].json")}
            claimed = {int(file.stem) for file in queue.glob("*.claim")}
            progress = (len(finished), tuple(sorted(claimed - finished)))
            if progress != previous:
                message = f"Recorded {progress[0]}/{len(indices)} original VICE receipts"
                if progress[1]:
                    message += " (running " + ", ".join(map(str, progress[1])) + ")"
                print(message, file=sys.stderr, flush=True)
                previous = progress
            try:
                active[0].wait(timeout=5)
            except subprocess.TimeoutExpired:
                continue
        failure = any(child.returncode != 0 for child in children)
        if failure:
            raise SystemExit("A website worker failed. Completed receipts are retained.")
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait()
        if preview:
            if children and all(child.returncode == 0 for child in children):
                time.sleep(1)
            preview.shutdown()
            preview.server_close()
    with (args.output / "observations.json").open("x") as result:
        json.dump([json.loads((receipts / f"{index:04d}.json").read_bytes())
                   for index in indices], result, indent=2)
        result.write("\n")


if __name__ == "__main__":
    main()
