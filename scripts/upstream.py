#!/usr/bin/env python3
"""Report substantive Go changes after normalizing mechanical module imports."""
import argparse
import difflib
import json
import re
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "upstream.json").read_text())


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def normalize(name, source):
    source = source.replace("github.com/quic-go/quic-go", PIN["module"])
    if name.startswith(("http3/", "integrationtests/", "interop/", "example/")):
        for suffix in ("", "/httptest", "/httptrace", "/httputil"):
            source = source.replace('"net/http' + suffix + '"',
                                    '"github.com/enetx/http' + suffix + '"')
    # Source links remain upstream links, not fork import paths.
    source = source.replace("https://" + PIN["module"], PIN["source"])
    source = re.sub(r"import \(\n(.*?)\n\)",
                    lambda m: "import (\n" + "\n".join(line for line in m[1].splitlines() if line.strip()) + "\n)",
                    source, flags=re.S)
    return subprocess.check_output(["gofmt"], input=source.encode()).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["audit"])
    parser.add_argument("--patch", action="store_true", help="print normalized patch")
    args = parser.parse_args()
    baseline = git("ls-tree", "-r", "--name-only", PIN["commit"]).decode().splitlines()
    baseline = {name for name in baseline if name.endswith(".go")}
    current = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*.go")
               if ".git" not in p.parts}
    result = {"baseline": PIN["version"], "commit": PIN["commit"],
              "changed": [], "added": sorted(current - baseline),
              "removed": sorted(baseline - current)}
    patches = []
    for name in sorted(baseline & current):
        old = normalize(name, git("show", f'{PIN["commit"]}:{name}').decode())
        new = normalize(name, (ROOT / name).read_text())
        if old != new:
            result["changed"].append(name)
            patches.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                               fromfile="upstream/" + name,
                                               tofile="fork/" + name))
    if args.patch:
        print("".join(patches), end="")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
