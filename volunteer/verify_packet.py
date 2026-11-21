"""Verify a downloaded volunteer receipt against its bundle and public tracker."""
import argparse
import gzip
import hashlib
import json
import tarfile
import re
from pathlib import Path

args = argparse.ArgumentParser()
args.add_argument("tracker", type=Path)
args.add_argument("packet")
args.add_argument("evidence", type=Path)
opt = args.parse_args()

def digest(stream):
    h = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        h.update(chunk)
    return h.hexdigest()

def file_hash(path):
    with path.open("rb") as f:
        return digest(f)

def check(condition, message):
    if not condition:
        raise SystemExit(message)

with gzip.open(opt.tracker / "tracker/modules.jsonl.gz", "rt") as src:
    rows = [r for r in map(json.loads, src) if opt.packet in (r["packet"], r["id"])]
check(rows, "Unknown packet")
receipt = json.loads((opt.evidence / "receipt.json").read_text())
summary = json.loads((opt.tracker / "tracker/summary.json").read_text())
check(receipt["exit_code"] == 0, "Build did not succeed")
check(receipt["mathlib"] == summary["mathlib_commit"], "Mathlib mismatch")
check(summary["lean"] in receipt["toolchain"], "Lean toolchain mismatch")
check(receipt["inputs_manifest_sha256"] == file_hash(opt.tracker / "parts.sha256"), "Wrong manifest")
check(receipt["log_sha256"] == file_hash(opt.evidence / "build.log"), "Log checksum mismatch")
bundle = opt.evidence / "targets.tar.gz"
check(receipt["bundle_sha256"] == file_hash(bundle), "Bundle checksum mismatch")
expected = {r["id"] for r in rows}
check(set(receipt["tasks"]) == expected == set(receipt["objects"]), "Incomplete task coverage")
with tarfile.open(bundle) as tar:
    for row in rows:
        name = "lib/lean/" + row["module"].replace(".", "/") + ".olean"
        with tar.extractfile(name) as obj:
            check(digest(obj) == receipt["objects"][row["id"]], "Object mismatch: " + name)
print(f'{opt.packet}: {len(rows)} objects match. Bundle SHA-256 {receipt["bundle_sha256"]}')

check(int((opt.evidence/'elapsed-seconds.txt').read_text()) >= 0, 'Invalid elapsed time')
for name in ('receipt.json','build.log','resources.txt'):
    text = (opt.evidence/name).read_text(errors='replace')
    check(not re.search(r'(/Users/|gh[pousr]_[A-Za-z0-9]{18}|github_pat_|PRIVATE KEY|Authorization:|/home/work/)',text), 'Review public evidence for private data')
