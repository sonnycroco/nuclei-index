# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via GitHub's
[private vulnerability reporting](https://github.com/sonnycroco/nuclei-index/security/advisories/new)
(Security → Report a vulnerability). Do not open a public issue for a security
report.

I'll acknowledge reports as soon as I can and aim to ship a fix or mitigation
promptly.

## Scope and threat model

`nuclei-index` reads a local [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
checkout (thousands of third-party YAML files) and an on-disk cache, then
*prints* `nuclei` commands. It never executes scans itself.

Template and cache content is treated as **untrusted**:

- emitted commands are assembled with `shlex.join`, so a malicious `id:`/`path`
  cannot inject shell metacharacters even if the output is piped to a shell;
- all fields printed to the terminal are stripped of control/escape characters;
- template ids are validated and suspicious ones are flagged;
- template paths that escape the templates root are rejected;
- the cache is written atomically with owner-only (`0600`) permissions.

If you find a way to make this tool execute attacker-controlled code, emit an
unsafe command, or write outside its cache directory, that's in scope.

## Responsible use

The commands this tool prints run a real vulnerability scanner. **Only run them
against systems you are authorized to test.**
