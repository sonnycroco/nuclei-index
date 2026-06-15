"""Smoke + unit tests that build a tiny fake nuclei-templates tree.

No network, no real nuclei install, no dependency on the user's templates.
"""
import json
import subprocess
import sys
from pathlib import Path

import nuclei_index as ni


def _make_template(path: Path, tid: str, name: str, severity: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"id: {tid}\n"
        "info:\n"
        f"  name: {name}\n"
        f"  severity: {severity}\n"
    )


def _fake_templates(tmp_path: Path) -> Path:
    root = tmp_path / "nuclei-templates"
    cves = root / "http" / "cves" / "2021"
    _make_template(cves / "CVE-2021-44228.yaml", "CVE-2021-44228",
                   "Apache Log4j RCE", "critical")
    # Same CVE, second (lower-severity) template — must not be dropped.
    _make_template(cves / "CVE-2021-44228-info.yaml", "CVE-2021-44228-detect",
                   "Log4j detection", "info")
    _make_template(root / "http" / "cves" / "2020" / "CVE-2020-5902.yaml",
                   "CVE-2020-5902", "F5 BIG-IP RCE", "critical")
    # A non-CVE template must be ignored.
    _make_template(root / "http" / "misc" / "robots.yaml", "robots-txt",
                   "robots.txt", "info")
    return root


def _isolate(monkeypatch, tmp_path: Path, templates: Path) -> None:
    monkeypatch.setenv("NUCLEI_TEMPLATES", str(templates))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))


def test_index_finds_cves(monkeypatch, tmp_path):
    templates = _fake_templates(tmp_path)
    _isolate(monkeypatch, tmp_path, templates)

    idx = ni.build_index(force=True)
    assert idx["_meta"]["cves"] == 2          # 44228 + 5902, robots ignored
    assert idx["_meta"]["count"] == 3         # 3 CVE templates total

    recs = ni.templates_for_cve("cve-2021-44228")  # case-insensitive
    assert len(recs) == 2
    # Highest severity first.
    assert recs[0]["severity"] == "critical"
    assert recs[1]["severity"] == "info"


def test_runnable_cmd_picks_highest_severity(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.build_index(force=True)

    cmd = ni.runnable_cmd("CVE-2021-44228", "https://t.example", rate=10)
    assert cmd == "nuclei -id CVE-2021-44228 -u https://t.example -rl 10 -timeout 10"

    all_cmds = ni.runnable_cmds("CVE-2021-44228", "https://t.example")
    assert len(all_cmds) == 2

    by_path = ni.runnable_cmd("CVE-2021-44228", "https://t.example", by_path=True)
    assert "nuclei -t " in by_path
    assert "CVE-2021-44228.yaml" in by_path


def test_unknown_cve_returns_empty(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    assert ni.templates_for_cve("CVE-1999-0001") == []
    assert ni.runnable_cmd("CVE-1999-0001") is None


def test_cache_is_reused(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.build_index(force=True)
    assert ni._cache_file().exists()
    # Second call without force should load from cache and match.
    assert ni.build_index()["_meta"]["cves"] == 2


def test_cli_json(monkeypatch, tmp_path, capsys):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.cli(["--cve", "CVE-2021-44228", "--host", "https://t", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["cve"] == "CVE-2021-44228"
    assert len(out["templates"]) == 2
    assert len(out["commands"]) == 2


def _poisoned_templates(tmp_path: Path) -> Path:
    root = tmp_path / "evil-templates"
    _make_template(root / "http" / "cves" / "2024" / "CVE-2024-00001.yaml",
                   "CVE-2024-00001$(touch /tmp/ni_should_not_exist)",
                   "ev\x1b[31mil\x1b]0;hijack\x07", "critical")
    _make_template(root / "http" / "cves" / "2024" / "CVE-2024-00002.yaml",
                   "x; rm -rf ~ #", "name; $(whoami)", "high")
    return root


def test_command_injection_is_neutralized(monkeypatch, tmp_path):
    """F1/F3/F4: untrusted id/host must never break out of one shell argument."""
    import shlex
    _isolate(monkeypatch, tmp_path, _poisoned_templates(tmp_path))
    ni.build_index(force=True)

    cmd = ni.runnable_cmd("CVE-2024-00001",
                          host="https://t$(touch /tmp/host_pwn)", rate=20)
    # The whole command must tokenize to exactly the args we intended — the
    # injection payload survives only as inert data inside single tokens.
    toks = shlex.split(cmd)
    assert toks[0] == "nuclei"
    assert "-id" in toks and "-u" in toks
    assert "CVE-2024-00001$(touch /tmp/ni_should_not_exist)" in toks  # one token
    assert "https://t$(touch /tmp/host_pwn)" in toks                  # one token
    # No metacharacter escaped quoting:
    assert "$(touch /tmp/ni_should_not_exist)" not in shlex.split(cmd.replace("'", ""))[0:1]


def test_suspicious_ids_flagged(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _poisoned_templates(tmp_path))
    ni.build_index(force=True)
    assert ni.templates_for_cve("CVE-2024-00001")[0]["suspicious"] is True
    # A normal CVE template is not flagged.
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.build_index(force=True)
    assert ni.templates_for_cve("CVE-2021-44228")[0]["suspicious"] is False


def test_terminal_escapes_stripped_from_output(monkeypatch, tmp_path, capsys):
    """F2: no ESC/BEL/control bytes reach the terminal."""
    _isolate(monkeypatch, tmp_path, _poisoned_templates(tmp_path))
    ni.cli(["--cve", "CVE-2024-00001"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "SUSPICIOUS" in out


def test_negative_rate_rejected(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    import pytest
    with pytest.raises(SystemExit):
        ni.cli(["--cve", "CVE-2021-44228", "--rate", "-5"])
    # API clamps rather than emits a negative flag value.
    ni.build_index(force=True)
    assert "-rl -5" not in ni.runnable_cmd("CVE-2021-44228", "h", rate=-5)


def test_path_traversal_in_by_path_blocked(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.build_index(force=True)
    # Forge a rec whose path escapes root; _cmd_for must fall back to -id form.
    bad = {"id": "CVE-2021-44228", "path": "../../../../etc/passwd"}
    cmd = ni._cmd_for(bad, "h", 20, by_path=True)
    assert "/etc/passwd" not in cmd
    assert "-id" in cmd


def test_cache_file_is_owner_only(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, _fake_templates(tmp_path))
    ni.build_index(force=True)
    import stat
    mode = stat.S_IMODE(ni._cache_file().stat().st_mode)
    assert mode & 0o077 == 0  # no group/other access


def test_module_entrypoint(monkeypatch, tmp_path):
    templates = _fake_templates(tmp_path)
    env = {"NUCLEI_TEMPLATES": str(templates),
           "XDG_CACHE_HOME": str(tmp_path / "cache"),
           "PATH": ""}
    src = str(Path(ni.__file__).resolve().parent.parent)
    r = subprocess.run([sys.executable, "-m", "nuclei_index", "--stats", "--json"],
                       capture_output=True, text=True,
                       env={**env, "PYTHONPATH": src})
    assert r.returncode == 0
    assert json.loads(r.stdout)["cves"] == 2
