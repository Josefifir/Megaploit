---
name: Exploit / Auxiliary Module Request
about: Request a new CVE exploit, scanner, or post-exploitation module
title: '[MODULE] '
labels: 'module-request'
assignees: ''
---

## Module type

- [ ] Exploit module
- [ ] Auxiliary / scanner module
- [ ] Post-exploitation module

## CVE / vulnerability

| Field | Value |
|---|---|
| CVE ID | e.g. CVE-2024-XXXXX |
| NVD link | https://nvd.nist.gov/vuln/detail/CVE-... |
| Affected software | e.g. Apache HTTP Server 2.4.x |
| Platform | Windows / Linux / Multi |
| Severity (CVSS) | e.g. 9.8 Critical |

## Public PoC / references

Links to any public proof-of-concept code, blog posts, or writeups.

```
- https://github.com/...
- https://...
```

## Why this module matters

A brief explanation of why this CVE is worth adding — active exploitation in the wild, common in CTF/lab environments, useful for compliance assessments, etc.

## Would you like to write this module?

See [CONTRIBUTING.md](../../CONTRIBUTING.md) and the module template at
[`megaploit/modules/exploits/_template.py`](../../megaploit/modules/exploits/_template.py).

- [ ] Yes — I'll open a PR
- [ ] I can help with testing once it's written
- [ ] Submitting for someone else to implement
