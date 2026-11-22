#!/usr/bin/env python3
"""Validate original identities and reconcile live observations with the native baseline."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PLAN_SHA = "a3c2663899bd07187da90345a5a77c2bae5b2a0b3a57058ca7bdce743356f05d"
WEBSITE_BUILD = "4549ce4f3-1795286606"
WEBSITE_WASM = "1d769f456528d328bb8b2b6b740a1f273565a8526cad8d80f674ba26cfca5c6c"
GLYPH_SOURCE_SHA = "ad9a7173a17518d201216d75ffa02f3577efd58bc7826b5dae7007fc4139bcad"
UNRESOLVED = {"unsupported-by-probe", "input-unavailable", "observation-failed",
              "no-exit-observed", "screenshot-differs", "frame-boundary-unresolved"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verdict(original, observed, assets):
    status = observed["status"]
    frozen = original["preexecution_status"]
    if frozen:
        require(status == frozen, "Preexecution status changed")
        return status
    require(status not in {"not_applicable", "missing_reference"}, "Applicable case was skipped")
    if status == "website-disk-rejected":
        require(original["dispatch"] == "prg"
                and observed["programSha256"] == assets[original["slots"][4]["asset"]]["sha256"],
                "Wrong program in disk setup receipt")
        rejected = observed["rejectedDisk"]
        slot = rejected["slot"]
        require(type(slot) is int and 5 <= slot < len(original["slots"]), "Wrong disk slot")
        item = original["slots"][slot]
        require(item["role"] == 6 and item["format"] in (2, 4)
                and rejected["sha256"] == assets[item["asset"]]["sha256"], "Wrong disk image")
        return "website-setup-unavailable"
    if status == "unsupported-by-probe":
        profile = original["profile"]
        # These limitations belong to the pinned website release. Generic
        # observer limitations remain unresolved.
        if (original["dispatch"] == "crt"
                or any(slot["format"] == 3 for slot in original["slots"][4:])
                or profile["machine"] == "ntscold"
                or profile["native_flags"] & 4
                or profile["reu_kib"] not in (0, 16384)):
            return "website-setup-unavailable"
    glyphs = observed.get("glyphDiagnostics")
    if status in UNRESOLVED and not (status == "screenshot-differs" and glyphs):
        return status
    require(observed["expected"] == original["expected"], "Expectation changed")
    require(observed["programSha256"] == assets[original["slots"][4]["asset"]]["sha256"],
            "Wrong guest program")
    if original["type"] == "exitcode":
        require(observed["limitCycle"] - observed["bootCycle"] == int(original["cycles"]),
                "Guest budget changed")
        event = observed["exit"]
        if status == "guest-timeout":
            require(event is None and observed["observedThrough"] >= observed["limitCycle"],
                    "Guest did not reach the full cycle budget")
            actual = "timeout"
        else:
            require(status in {"guest-ok", "guest-error"} and event is not None,
                    "Unknown exitcode observation")
            require(event["address"] == 0xD7FF and 0 <= event["value"] <= 255, "Invalid exit write")
            require(observed["bootCycle"] < event["cycle"] <= observed["limitCycle"],
                    "Exit outside budget")
            actual = "ok" if event["value"] == 0 else "error"
        require(status == "guest-" + actual, "Exit status disagrees with byte")
    else:
        if not observed.get("screenshot", {}).get("frameVerified"):
            return "frame-boundary-unresolved"
        differences = observed["screenshot"]["different"]
        require(status == ("screenshot-differs" if differences else "screenshot-matches"),
                "Screenshot status disagrees with pixel count")
        if glyphs:
            variants = ("ones", "zeros", *(f"id{i:02d}" for i in range(28)))
            expected_fonts = [assets[f"release-balanced28-{name}"]["sha256"] for name in variants]
            require(len(original["policy_ids"]) == 31 and glyphs["sourceSha256"] == GLYPH_SOURCE_SHA
                    and glyphs["fonts"] == expected_fonts and glyphs["rawDifferent"] > 0,
                    "Unqualified glyph diagnostics")
        else:
            require(differences == 0, "Unqualified screenshot mismatch")
        geometry = original["comparison"]["geometry"]
        require(observed["referenceSha256"] == assets[original["comparison"]["reference"]]["sha256"],
                "Wrong comparison reference")
        require(observed["screenshot"]["total"] == geometry["width"] * geometry["height"],
                "Screenshot crop changed")
        actual = "error" if differences else "ok"
    return "pass" if actual == original["expected"] else "fail"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("receipt_dir", type=Path)
    parser.add_argument("--native-baseline", type=Path)
    parser.add_argument("--supplement", type=Path, action="append", default=[])
    args = parser.parse_args()
    plan_bytes = args.plan.read_bytes()
    require(hashlib.sha256(plan_bytes).hexdigest() == PLAN_SHA, "Wrong frozen case plan")
    plan = json.loads(plan_bytes)
    originals = plan["cases"]
    assets = {row["id"]: row for row in plan["assets"]}
    require([row["index"] for row in originals] == list(range(1544)), "Wrong original inventory")
    baseline = json.loads(args.native_baseline.read_bytes()) if args.native_baseline else None
    if baseline is not None:
        require([row["line"] for row in originals] == [row["line"] for row in baseline],
                "Native baseline original identities differ")
    counts = Counter()
    regressed = []
    build = None
    wasm = None
    verdicts = {}
    capture_protocol = None
    for receipt in (file for directory in [args.receipt_dir, *args.supplement]
                    for file in sorted(directory.iterdir())):
        if len(receipt.stem) != 4 or not receipt.stem.isascii() or not receipt.stem.isdecimal() or receipt.suffix != ".json":
            continue
        index = int(receipt.stem)
        require(index < len(originals), f"Unexpected original index {index}")
        observed = json.loads(receipt.read_bytes())
        original = originals[index]
        require(observed["index"] == index and observed["line"] == original["line"],
                f"Receipt identity mismatch for original {index}")
        build = build or observed["build"]
        wasm = wasm or observed["wasmSha256"]
        require(bool(build) and observed["build"] == build
                and observed["wasmSha256"] == WEBSITE_WASM,
                "Receipt belongs to an unqualified website release")
        if "screenshot" in observed:
            protocol = observed["screenshot"].get("capture", "at-stop")
            require(protocol in {"at-stop", "native-two-frames-after-stop"},
                    "Unknown screenshot capture protocol")
            require(capture_protocol in (None, protocol), "Mixed screenshot capture protocols")
            capture_protocol = protocol
        try:
            outcome = verdict(original, observed, assets)
        except (KeyError, ValueError) as error:
            raise ValueError(f"Original {index}: {error}") from error
        if index in verdicts:
            previous = verdicts[index]
            if previous not in UNRESOLVED:
                require(previous == outcome, f"Conflicting resolved receipts for original {index}")
                continue
            counts[previous] -= 1
        verdicts[index] = outcome
        counts[outcome] += 1
        if outcome == "fail" and baseline and baseline[index]["result"] == "pass":
            regressed.append(index)

    seen = sum(counts.values())
    applicable = sum(row["applicability"] == "applicable" for row in originals)
    inventory_complete = seen == len(originals)
    score_ready = inventory_complete and not any(counts[key] for key in UNRESOLVED)
    report = {"build": build, "wasmSha256": wasm, "originals": len(originals),
              "applicable": applicable, "receipts": seen, "counts": {key: value for key, value in counts.items() if value},
              "lostNativePasses": sorted(regressed), "score_ready": score_ready}
    unresolved = sum(counts[key] for key in UNRESOLVED) + len(originals) - seen
    if capture_protocol == "native-two-frames-after-stop":
        report["screenshot_capture"] = capture_protocol
    report["verified_passes"] = counts["pass"]
    report["unresolved_originals"] = unresolved
    if score_ready:
        require(counts["not_applicable"] == 152 and counts["missing_reference"] == 45,
                "Original scope changed")
        report["percent"] = round(100 * counts["pass"] / applicable, 1)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
