#!/usr/bin/env python3
"""
nuclei_index — map CVE IDs to your local nuclei-templates, and emit a runnable,
rate-limited nuclei command for a matched CVE.

Vulnerability intel tells you *what* is exploitable on a target; this hands you
the firing pin — the concrete `nuclei` check to run. It indexes a local
nuclei-templates checkout by CVE ID and caches the result, so "CVE-X applies"
becomes "run this".

The index is cached under $XDG_CACHE_HOME/nuclei-index (or ~/.cache/nuclei-index)
and rebuilt automatically when the templates directory changes (or on rebuild).

SECURITY NOTE
-------------
nuclei-templates are thousands of third-party YAML files, and the on-disk cache
may live in a shared cache dir. Every value pulled from a template or the cache
is therefore treated as untrusted:
  - emitted commands are assembled with shlex.join, so a poisoned `id:`/`path`
    cannot inject shell metacharacters even if the output is piped to a shell;
  - template ids are validated against a safe charset, and suspicious ones are
    flagged in the output;
  - fields printed to the terminal are stripped of control/escape characters
    (no ANSI / title-bar injection);
  - template paths that escape the templates root are rejected.

Importable API:
    templates_dir() -> Path | None
    build_index(force=False) -> dict
    templates_for_cve("CVE-2021-44228") -> list[dict]
    runnable_cmd("CVE-2021-44228", host, rate=20, by_path=False) -> str | None
    runnable_cmds("CVE-2021-44228", host, rate=20, by_path=False) -> list[str]

CLI:
    nuclei-index --rebuild
    nuclei-index --cve CVE-2021-44228 [--host https://t] [--by-path] [--json]
    nuclei-index --stats [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

__version__ = "0.1.0"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# A legitimate nuclei template id is lowercase-ish slug; anything else is suspect.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
# C0 + DEL + C1 control characters — stripped before anything is printed.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Severity rank for choosing a single "best" template when a CVE has several.
_SEV_RANK = {
    "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0,
}


def cache_dir() -> Path:
    """Where the index is cached. Honors $XDG_CACHE_HOME, else ~/.cache."""
    base = os.getenv("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "nuclei-index"


def _cache_file() -> Path:
    return cache_dir() / "nuclei_cve_index.json"


def _candidate_dirs() -> list[str]:
    """Likely nuclei-templates locations, $NUCLEI_TEMPLATES taking priority."""
    return [
        os.getenv("NUCLEI_TEMPLATES", ""),
        str(Path.home() / "nuclei-templates"),
        str(Path.home() / ".local" / "nuclei-templates"),
        str(Path.home() / ".config" / "nuclei" / "templates"),
    ]


def templates_dir() -> Path | None:
    for c in _candidate_dirs():
        if c and Path(c).is_dir():
            return Path(c)
    return None


def _clean(s: object) -> str:
    """Strip control/escape chars — safe to print untrusted template fields."""
    return _CTRL_RE.sub("", str(s))


def _safe_rel(rel: str) -> bool:
    """True if `rel` is a plain relative path that stays under the root."""
    p = Path(rel)
    return not p.is_absolute() and ".." not in p.parts


def _freshness_sig(root: Path) -> list:
    """Cheap freshness signal covering *every* cves/ subtree (http, network, dns,
    code, ...), matching what build_index() actually rglob-indexes.

    Only stats directories — never reads or rglob's template files — so the
    cache-hit path stays cheap. Catches templates added or removed (a cves dir's
    mtime and its year-subdir listing change) and brand-new year dirs (the year
    count changes even when a coarse parent mtime doesn't). Will not notice an
    in-place edit to an existing file — use --rebuild if you hand-edit templates.

    Returned as a JSON-serializable list so it round-trips through the cache and
    compares equal next run: a tuple would deserialize to a list and never match,
    forcing a rebuild on every call.
    """
    parts: list = [["", root.stat().st_mtime]]
    for cves in root.rglob("cves"):
        if not cves.is_dir() or ".git" in cves.parts:
            continue
        years = sorted(y for y in cves.iterdir() if y.is_dir())
        entry: list = [str(cves.relative_to(root)), cves.stat().st_mtime, len(years)]
        for y in years:
            entry.append([y.name, y.stat().st_mtime])
        parts.append(entry)
    parts.sort()
    return parts


def _parse_template(path: Path) -> dict | None:
    """Lightweight parse — no yaml dep; pull id/name/severity by line."""
    cid = name = sev = ""
    try:
        with path.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not cid and s.startswith("id:"):
                    cid = s.split(":", 1)[1].strip()
                elif not name and s.startswith("name:"):
                    name = s.split(":", 1)[1].strip().strip('"')
                elif not sev and s.startswith("severity:"):
                    sev = s.split(":", 1)[1].split("#", 1)[0].strip()
                if cid and name and sev:
                    break
    except Exception:
        return None
    m = _CVE_RE.search(path.name) or (_CVE_RE.search(cid) if cid else None)
    if not m:
        return None
    rid = cid or path.stem
    return {
        "cve": m.group(0).upper(),
        "id": rid,
        "path": str(path),
        "name": name,
        "severity": sev or "unknown",
        # Flagged (not dropped) so a tampered template is visible, not silent.
        "suspicious": not bool(_SAFE_ID_RE.match(rid)),
    }


def build_index(force: bool = False) -> dict:
    root = templates_dir()
    if root is None:
        return {"_meta": {"templates_dir": None, "count": 0, "cves": 0}, "map": {}}

    sig = _freshness_sig(root)
    cache = _cache_file()
    if not force and cache.exists():
        try:
            cached = json.loads(cache.read_text())
            if cached.get("_meta", {}).get("sig") == sig and \
               cached.get("_meta", {}).get("templates_dir") == str(root):
                return cached
        except Exception:
            pass

    mapping: dict[str, list] = {}
    n = 0
    for path in root.rglob("CVE-*.yaml"):
        if ".git" in path.parts:
            continue
        rec = _parse_template(path)
        if not rec:
            continue
        try:
            rel = Path(rec["path"]).relative_to(root)
        except ValueError:
            continue  # symlink/path escaping the templates root — skip
        rec["path"] = str(rel)
        mapping.setdefault(rec["cve"], []).append(rec)
        n += 1

    # Stable, useful ordering within a CVE: highest severity first.
    for recs in mapping.values():
        recs.sort(key=lambda r: _SEV_RANK.get(r["severity"].lower(), 0), reverse=True)

    index = {
        "_meta": {"templates_dir": str(root), "sig": sig, "count": n,
                  "cves": len(mapping)},
        "map": mapping,
    }
    # Atomic, owner-only write — avoids torn reads under concurrency and keeps
    # the cache out of other local users' reach.
    cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = cache.with_name(cache.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(index))
    os.chmod(tmp, 0o600)
    os.replace(tmp, cache)
    return index


def templates_for_cve(cve: str) -> list[dict]:
    cve = cve.strip().upper()
    return build_index().get("map", {}).get(cve, [])


def _cmd_for(rec: dict, host: str, rate: int, by_path: bool) -> str:
    rate = max(1, int(rate))
    parts = ["nuclei"]
    if by_path and _safe_rel(rec.get("path", "")):
        root = build_index().get("_meta", {}).get("templates_dir", "")
        target = str(Path(root) / rec["path"]) if root else rec["path"]
        parts += ["-t", target]
    else:
        # -id is stable across template relocation but scans the whole set.
        parts += ["-id", rec["id"]]
    parts += ["-u", host, "-rl", str(rate), "-timeout", "10"]
    # shlex.join quotes every field, so untrusted id/path/host can't inject.
    return shlex.join(parts)


def runnable_cmds(cve: str, host: str = "<host>", rate: int = 20,
                  by_path: bool = False) -> list[str]:
    """A rate-limited nuclei command for every template matching the CVE."""
    return [_cmd_for(r, host, rate, by_path) for r in templates_for_cve(cve)]


def runnable_cmd(cve: str, host: str = "<host>", rate: int = 20,
                 by_path: bool = False) -> str | None:
    """The single highest-severity nuclei command for a CVE, or None."""
    recs = templates_for_cve(cve)
    if not recs:
        return None
    return _cmd_for(recs[0], host, rate, by_path)  # recs sorted severity-desc


def _pos_int(v: str) -> int:
    i = int(v)
    if i <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return i


def cli(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="nuclei-index",
        description="CVE -> local nuclei template index")
    p.add_argument("--rebuild", action="store_true", help="force rebuild the index")
    p.add_argument("--cve", help="look up templates for a CVE id")
    p.add_argument("--host", default="<host>", help="host to embed in the command")
    p.add_argument("--rate", type=_pos_int, default=20,
                   help="nuclei rate-limit (default 20)")
    p.add_argument("--by-path", action="store_true",
                   help="emit `nuclei -t <path>` (faster) instead of `-id`")
    p.add_argument("--stats", action="store_true", help="print index stats")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    root = templates_dir()
    if root is None:
        msg = ("nuclei-templates dir not found. Set $NUCLEI_TEMPLATES or run "
               "`nuclei -update-templates`.")
        if args.json:
            print(json.dumps({"error": msg}))
        else:
            print(f"[!] {msg}", file=sys.stderr)
        sys.exit(1)

    idx = build_index(force=args.rebuild)
    meta = idx["_meta"]

    if args.cve:
        recs = templates_for_cve(args.cve)
        cmds = runnable_cmds(args.cve, args.host, args.rate, args.by_path)
        if args.json:
            # json.dumps escapes control chars, so raw values are safe here.
            print(json.dumps({"cve": args.cve.strip().upper(),
                              "templates": recs, "commands": cmds}))
            return
        if not recs:
            print(f"\n[{_clean(args.cve).upper()}] no local nuclei template.")
            print("  Try: nuclei -update-templates   (or check a newer CVE)")
            return
        print(f"\n[{_clean(args.cve).upper()}] {len(recs)} template(s):")
        for r in recs:
            flag = "  [!] SUSPICIOUS ID — verify before running" if r.get("suspicious") else ""
            print(f"  - {_clean(r['id'])}  ({_clean(r['severity'])})  {_clean(r['name'])}{flag}")
            print(f"    {_clean(meta['templates_dir'])}/{_clean(r['path'])}")
        print("\n  Run (rate-limited, authorized hosts only):")
        for c in cmds:
            print(f"    {c}")
        return

    if args.json:
        print(json.dumps(meta))
    else:
        print(f"templates_dir : {_clean(meta['templates_dir'])}")
        print(f"CVE templates : {meta['count']}")
        print(f"unique CVEs   : {meta['cves']}")
        print(f"cache         : {_cache_file()}")


if __name__ == "__main__":
    cli()
