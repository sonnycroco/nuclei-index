# nuclei-index

Map **CVE IDs → your local [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)** and get back a runnable, rate-limited `nuclei` command.

Vulnerability intel tells you *what* is exploitable on a target. `nuclei-index` hands you the firing pin: the exact `nuclei` invocation to verify it. It indexes a local nuclei-templates checkout by CVE, caches the result, and bridges "CVE-X applies" → "run this".

- **Zero dependencies.** Pure standard-library Python (≥3.9). No YAML parser, no network calls.
- **Fast.** Builds an on-disk index once and reuses it until your templates change.
- **Scriptable.** Clean importable API + `--json` output to wire into other tooling.

## Install

```bash
pip install nuclei-index
# or from source:
pip install .
```

You also need a local nuclei-templates checkout. If you run nuclei, you already have one:

```bash
nuclei -update-templates
```

`nuclei-index` looks for templates in (first match wins):

1. `$NUCLEI_TEMPLATES`
2. `~/nuclei-templates`
3. `~/.local/nuclei-templates`
4. `~/.config/nuclei/templates`

## Usage

```bash
# Look up a CVE and get the command(s) to run
$ nuclei-index --cve CVE-2021-44228 --host https://target.example

[CVE-2021-44228] 2 template(s):
  - CVE-2021-44228  (critical)  Apache Log4j RCE (Log4Shell)
    /home/you/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml
  - ...

  Run (rate-limited, authorized hosts only):
    nuclei -id CVE-2021-44228 -u https://target.example -rl 20 -timeout 10

# Emit `nuclei -t <path>` form (faster — skips loading the whole template set)
$ nuclei-index --cve CVE-2021-44228 --host https://target.example --by-path

# Machine-readable
$ nuclei-index --cve CVE-2021-44228 --json
{"cve": "CVE-2021-44228", "templates": [...], "commands": [...]}

# Index stats / force a rebuild
$ nuclei-index --stats
$ nuclei-index --rebuild
```

The index is cached at `$XDG_CACHE_HOME/nuclei-index/` (default `~/.cache/nuclei-index/`) and refreshed automatically when CVE templates are added or removed under any `cves/` directory. The freshness check is a cheap signal over those directories — their modification times and year-subdir listings — so a clean run never has to re-scan every template to confirm the cache is current. It can't see two things on its own: an edit made *in place* to an existing template (filename and directory unchanged), or a CVE template dropped outside a `cves/` directory. Run `--rebuild` to force a full re-scan in those cases.

## As a library

```python
import nuclei_index as ni

ni.templates_for_cve("CVE-2021-44228")
# [{'cve': 'CVE-2021-44228', 'id': 'CVE-2021-44228',
#   'path': 'http/cves/2021/CVE-2021-44228.yaml',
#   'name': 'Apache Log4j RCE', 'severity': 'critical'}, ...]

ni.runnable_cmd("CVE-2021-44228", "https://target.example", rate=20)
# 'nuclei -id CVE-2021-44228 -u https://target.example -rl 20 -timeout 10'

ni.runnable_cmds("CVE-2021-44228", "https://target.example")  # every match
```

Templates for a CVE are returned highest-severity first; `runnable_cmd` picks that top one, `runnable_cmds` returns all of them.

## Responsible use

This tool only *constructs* commands — it never scans anything itself. The emitted `nuclei` commands are rate-limited by default. **Only run them against hosts you are authorized to test.**

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite builds a throwaway fake templates tree — it needs neither a real nuclei install nor your templates.

## License

[Apache-2.0](LICENSE).
