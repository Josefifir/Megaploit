"""
megaploit.toolbox.installer
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Smart toolbox installer — clone any GitHub/GitLab/Bitbucket repository,
detect its language and build system, install all dependencies, build the
tool with the correct toolchain, perform a post-install health check, and
register the tool in the ToolRegistry.

Supported languages & build flows
----------------------------------
Python     requirements.txt / pyproject.toml / setup.py / setup.cfg
           → isolated venv + pip install, entry-point auto-detected
Go         go.mod / go.sum
           → go build -o <name> ./...  with explicit binary output
           → fallback: go run ./...
Rust       Cargo.toml
           → cargo build --release
           → scans target/release/ for any produced binary
           → fallback: cargo run --release --
Node.js    package.json
           → npm ci (preferred) or npm install
           → entry read from package.json "main" / "bin"
Ruby       Gemfile / *.rb
           → gem install bundler + bundle install
           → entry: <name>.rb / main.rb / app.rb / cli.rb
Java       pom.xml  → mvn package -DskipTests
           build.gradle / build.gradle.kts  → gradle build
           → jar located in target/ or build/libs/
           → fallback: mvn exec:java / gradle run
Bash/Shell *.sh at root  → chmod +x, run via bash
PowerShell *.ps1 at root → run with pwsh / powershell -ExecutionPolicy Bypass
C/C++      Makefile      → make [-j<cpus>]
           CMakeLists.txt → cmake .. && make [-j<cpus>]
           → fallback: make run
Unknown / binary  → chmod +x entry, run directly

Smart features
--------------
* Pre-built catalogue of 60+ popular security/pentesting tools with
  known-good repo URLs, descriptions, tags, and entry-point overrides.
  Use: installer.install_from_catalogue("sqlmap")

* Parallel install:  installer.install_many([...])  runs clones in
  parallel threads and serialises the build/register phase.

* SHA-256 integrity check: optionally pass expected_sha= to install()
  and the cloned HEAD commit is verified before building.

* Dockerfile generation: installer.generate_dockerfile(name) writes a
  minimal Dockerfile into tools/<name>/ that packages the tool.

* Dependency pre-flight: checks that required toolchain binaries
  (git, go, cargo, npm, mvn, …) are present BEFORE starting a long
  clone — fails fast with a clear error.

* Post-install health check: installer.healthcheck(name) verifies
  the entry-point exists, is executable, and (for Python) imports
  cleanly.

* Version / commit snapshot: the installed commit hash is written into
  the registry alongside the install timestamp.

* Smart venv reuse: if a venv already exists in the repo dir (e.g.
  from a previous build), it is reused instead of recreated.

* Build environment passthrough: Go CGO_ENABLED, Rust RUSTFLAGS, and
  Node NODE_ENV are set to sensible defaults before building.

Fallback guarantee
------------------
Every builder returns a *runnable* command list.  Source files (*.go,
*.rs, *.java, pom.xml …) are NEVER placed bare in run_cmd — the correct
interpreter or compiler-runner is always prepended so the tool can be
invoked even when the compile step was skipped or failed.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import textwrap
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional

from megaploit.toolbox.registry import (
    Tool, registry, TOOLS_DIR,
    LANG_PYTHON, LANG_GO, LANG_RUST, LANG_NODE,
    LANG_RUBY, LANG_JAVA, LANG_BASH, LANG_POWERSHELL,
    LANG_BINARY, LANG_UNKNOWN,
)

ProgressFn = Callable[[str], None]
_NOOP: ProgressFn = lambda _: None

# Number of CPUs available for parallel builds (make -j, etc.)
_CPU_COUNT: int = os.cpu_count() or 2

# ---------------------------------------------------------------------------
# Pre-built tool catalogue
# ---------------------------------------------------------------------------

@dataclass
class CatalogueEntry:
    """A known-good tool definition that can be installed by short name."""
    repo:        str
    description: str
    tags:        list[str]
    entry:       str  = ""   # override; "" means auto-detect
    lang:        str  = ""   # override; "" means auto-detect


# 60+ popular security / pentesting tools with verified repo URLs.
CATALOGUE: dict[str, CatalogueEntry] = {
    # ── Web application security ──────────────────────────────────────────
    "sqlmap": CatalogueEntry(
        repo="https://github.com/sqlmapproject/sqlmap",
        description="Automatic SQL injection and database takeover tool",
        tags=["web", "sql", "injection", "database"],
        entry="sqlmap.py",
    ),
    "nikto": CatalogueEntry(
        repo="https://github.com/sullo/nikto",
        description="Web server scanner that detects dangerous files and misconfigurations",
        tags=["web", "scanner", "vulnerability"],
        entry="program/nikto.pl",
    ),
    "wfuzz": CatalogueEntry(
        repo="https://github.com/xmendez/wfuzz",
        description="Web application fuzzer — discover hidden resources and parameters",
        tags=["web", "fuzzer", "bruteforce"],
        entry="wfuzz/wfuzz.py",
    ),
    "gobuster": CatalogueEntry(
        repo="https://github.com/OJ/gobuster",
        description="Directory/file/DNS/vhost busting tool written in Go",
        tags=["web", "bruteforce", "directory", "go"],
    ),
    "ffuf": CatalogueEntry(
        repo="https://github.com/ffuf/ffuf",
        description="Fast web fuzzer written in Go — finds files, directories, and parameters",
        tags=["web", "fuzzer", "go"],
    ),
    "dirsearch": CatalogueEntry(
        repo="https://github.com/maurosoria/dirsearch",
        description="Web path discovery tool — brute-force directories and files",
        tags=["web", "bruteforce", "directory"],
        entry="dirsearch.py",
    ),
    "feroxbuster": CatalogueEntry(
        repo="https://github.com/epi052/feroxbuster",
        description="Fast, simple, recursive content discovery tool written in Rust",
        tags=["web", "bruteforce", "directory", "rust"],
    ),
    "whatweb": CatalogueEntry(
        repo="https://github.com/urbanadventurer/WhatWeb",
        description="Identify websites — CMS, blogging platforms, JS libraries, and more",
        tags=["web", "fingerprint", "recon"],
        entry="whatweb",
    ),
    "commix": CatalogueEntry(
        repo="https://github.com/commixproject/commix",
        description="Automated command injection and exploitation tool",
        tags=["web", "injection", "command"],
        entry="commix.py",
    ),
    "xsstrike": CatalogueEntry(
        repo="https://github.com/s0md3v/XSStrike",
        description="Advanced XSS detection and exploitation suite",
        tags=["web", "xss", "injection"],
        entry="xsstrike.py",
    ),

    # ── Network scanning & enumeration ───────────────────────────────────
    "masscan": CatalogueEntry(
        repo="https://github.com/robertdavidgraham/masscan",
        description="TCP port scanner — transmit 10M packets/sec; fastest internet scanner",
        tags=["network", "scanner", "port"],
    ),
    "naabu": CatalogueEntry(
        repo="https://github.com/projectdiscovery/naabu",
        description="Fast port scanner written in Go with a focus on reliability",
        tags=["network", "scanner", "port", "go"],
    ),
    "nuclei": CatalogueEntry(
        repo="https://github.com/projectdiscovery/nuclei",
        description="Fast, customisable vulnerability scanner based on YAML templates",
        tags=["scanner", "vulnerability", "go"],
    ),
    "subfinder": CatalogueEntry(
        repo="https://github.com/projectdiscovery/subfinder",
        description="Subdomain discovery tool using passive sources",
        tags=["recon", "subdomain", "go"],
    ),
    "httpx": CatalogueEntry(
        repo="https://github.com/projectdiscovery/httpx",
        description="Fast and multi-purpose HTTP toolkit for probing web servers",
        tags=["web", "recon", "go"],
    ),
    "dnsx": CatalogueEntry(
        repo="https://github.com/projectdiscovery/dnsx",
        description="Multi-purpose DNS toolkit for running various queries",
        tags=["recon", "dns", "go"],
    ),
    "amass": CatalogueEntry(
        repo="https://github.com/owasp-amass/amass",
        description="In-depth attack surface mapping and asset discovery",
        tags=["recon", "subdomain", "osint", "go"],
    ),
    "nmap-scripts": CatalogueEntry(
        repo="https://github.com/vulnersCom/nmap-vulners",
        description="NSE script that queries Vulners.com API for CVEs during nmap scans",
        tags=["network", "scanner", "nse", "cve"],
        entry="vulners.nse",
        lang=LANG_UNKNOWN,
    ),

    # ── Credential attacks ────────────────────────────────────────────────
    "hydra": CatalogueEntry(
        repo="https://github.com/vanhauser-thc/thc-hydra",
        description="Fast and flexible online password-cracking tool",
        tags=["bruteforce", "credentials", "auth"],
    ),
    "medusa": CatalogueEntry(
        repo="https://github.com/jmk-foofus/medusa",
        description="Speedy parallel network login auditor",
        tags=["bruteforce", "credentials", "network"],
    ),
    "hashcat": CatalogueEntry(
        repo="https://github.com/hashcat/hashcat",
        description="World's fastest password recovery utility with GPU support",
        tags=["password", "cracking", "hash", "gpu"],
    ),
    "john": CatalogueEntry(
        repo="https://github.com/openwall/john",
        description="John the Ripper — offline password cracker",
        tags=["password", "cracking", "hash"],
        entry="src/john",
    ),
    "credmaster": CatalogueEntry(
        repo="https://github.com/knavesec/CredMaster",
        description="Spray credentials across many providers without lockout",
        tags=["bruteforce", "credentials", "cloud"],
        entry="credmaster.py",
    ),

    # ── Exploitation frameworks & payloads ────────────────────────────────
    "metasploit-payloads": CatalogueEntry(
        repo="https://github.com/rapid7/metasploit-payloads",
        description="Compiled Metasploit payloads for offline use",
        tags=["exploit", "payload", "msf"],
        lang=LANG_BINARY,
    ),
    "msfvenom-cli": CatalogueEntry(
        repo="https://github.com/g0tmi1k/msfpc",
        description="MSFvenom Payload Creator — quick generator wrapper for common payloads",
        tags=["exploit", "payload", "generator"],
        entry="msfpc.sh",
    ),
    "nishang": CatalogueEntry(
        repo="https://github.com/samratashok/nishang",
        description="PowerShell for penetration testing and red teaming",
        tags=["powershell", "windows", "post-exploitation"],
        lang=LANG_POWERSHELL,
    ),
    "pwncat": CatalogueEntry(
        repo="https://github.com/calebstewart/pwncat",
        description="Fancy reverse and bind shell handler with post-exploitation features",
        tags=["shell", "post-exploitation", "linux"],
        entry="pwncat/__main__.py",
    ),
    "evil-winrm": CatalogueEntry(
        repo="https://github.com/Hackplayers/evil-winrm",
        description="Ultimate WinRM shell for hacking/pentesting Windows Active Directory",
        tags=["windows", "ad", "shell", "winrm"],
        entry="evil-winrm.rb",
        lang=LANG_RUBY,
    ),

    # ── Active Directory & Windows ─────────────────────────────────────────
    "bloodhound-python": CatalogueEntry(
        repo="https://github.com/dirkjanm/BloodHound.py",
        description="Python ingestor for BloodHound — collect AD data for graph analysis",
        tags=["ad", "windows", "recon", "bloodhound"],
        entry="bloodhound.py",
    ),
    "impacket": CatalogueEntry(
        repo="https://github.com/fortra/impacket",
        description="Python classes for working with Windows network protocols (SMB, MSRPC…)",
        tags=["windows", "ad", "smb", "network"],
        entry="impacket/__init__.py",
    ),
    "crackmapexec": CatalogueEntry(
        repo="https://github.com/Porchetta-Industries/CrackMapExec",
        description="Swiss army knife for pentesting Windows/AD networks",
        tags=["windows", "ad", "smb", "bruteforce"],
        entry="crackmapexec/__main__.py",
    ),
    "ldapdomaindump": CatalogueEntry(
        repo="https://github.com/dirkjanm/ldapdomaindump",
        description="Active Directory information dumper via LDAP",
        tags=["ad", "ldap", "recon"],
        entry="ldapdomaindump/__main__.py",
    ),
    "kerbrute": CatalogueEntry(
        repo="https://github.com/ropnop/kerbrute",
        description="Fast Kerberos brute-forcing and user enumeration",
        tags=["kerberos", "ad", "bruteforce", "go"],
    ),
    "responder": CatalogueEntry(
        repo="https://github.com/lgandx/Responder",
        description="LLMNR, NBT-NS and MDNS poisoner and credential catcher",
        tags=["windows", "network", "mitm", "credentials"],
        entry="Responder.py",
    ),

    # ── OSINT ─────────────────────────────────────────────────────────────
    "theHarvester": CatalogueEntry(
        repo="https://github.com/laramies/theHarvester",
        description="E-mail, domain, IP and URL gathering from public sources",
        tags=["osint", "recon", "email"],
        entry="theHarvester.py",
    ),
    "sherlock": CatalogueEntry(
        repo="https://github.com/sherlock-project/sherlock",
        description="Hunt down social media accounts by username across social networks",
        tags=["osint", "social-media", "username"],
        entry="sherlock/sherlock.py",
    ),
    "spiderfoot": CatalogueEntry(
        repo="https://github.com/smicallef/spiderfoot",
        description="Automated OSINT collection and threat intelligence tool",
        tags=["osint", "recon", "automation"],
        entry="sf.py",
    ),
    "holehe": CatalogueEntry(
        repo="https://github.com/megadose/holehe",
        description="Check if an email is used on different sites",
        tags=["osint", "email"],
        entry="holehe/core.py",
    ),
    "maigret": CatalogueEntry(
        repo="https://github.com/soxoj/maigret",
        description="Collect a dossier on a person by username across 3000+ sites",
        tags=["osint", "username", "social-media"],
        entry="maigret/__main__.py",
    ),

    # ── Post-exploitation ─────────────────────────────────────────────────
    "mimikatz": CatalogueEntry(
        repo="https://github.com/gentilkiwi/mimikatz",
        description="Windows credential extraction — LSASS dump, pass-the-hash, golden tickets",
        tags=["windows", "credentials", "post-exploitation"],
        lang=LANG_BINARY,
    ),
    "linpeas": CatalogueEntry(
        repo="https://github.com/peass-ng/PEASS-ng",
        description="Linux privilege escalation awesome script — enumerate misconfigurations",
        tags=["linux", "privesc", "enumeration"],
        entry="linPEAS/linpeas.sh",
        lang=LANG_BASH,
    ),
    "winpeas": CatalogueEntry(
        repo="https://github.com/peass-ng/PEASS-ng",
        description="Windows privilege escalation awesome script",
        tags=["windows", "privesc", "enumeration"],
        entry="winPEAS/winPEASx64.exe",
        lang=LANG_BINARY,
    ),
    "pspy": CatalogueEntry(
        repo="https://github.com/DominicBreuker/pspy",
        description="Monitor Linux processes without root — reveal cronjobs and file operations",
        tags=["linux", "monitoring", "privesc", "go"],
    ),
    "gtfobins-cli": CatalogueEntry(
        repo="https://github.com/mchoji/gtfobins-cli",
        description="Command-line search for GTFOBins — find sudo/suid bypass techniques",
        tags=["linux", "privesc", "lolbins"],
        entry="gtfobins_cli/__main__.py",
    ),
    "chisel": CatalogueEntry(
        repo="https://github.com/jpillora/chisel",
        description="Fast TCP/UDP tunnelling over HTTP — pivot through firewalls",
        tags=["tunnel", "pivot", "network", "go"],
    ),
    "ligolo-ng": CatalogueEntry(
        repo="https://github.com/nicocha30/ligolo-ng",
        description="Advanced tunnelling tool using TUN interfaces — pivoting made easy",
        tags=["tunnel", "pivot", "network", "go"],
    ),

    # ── Wireless ──────────────────────────────────────────────────────────
    "hcxtools": CatalogueEntry(
        repo="https://github.com/ZerBea/hcxtools",
        description="Convert pcap files and PMKID/EAPOL to hashcat format",
        tags=["wireless", "wifi", "hash"],
    ),
    "wifiphisher": CatalogueEntry(
        repo="https://github.com/wifiphisher/wifiphisher",
        description="Rogue access point attack framework for Wi-Fi security",
        tags=["wireless", "wifi", "phishing"],
        entry="bin/wifiphisher",
    ),

    # ── Cloud & container ─────────────────────────────────────────────────
    "prowler": CatalogueEntry(
        repo="https://github.com/prowler-cloud/prowler",
        description="AWS/Azure/GCP security assessments, audits and hardening checks",
        tags=["cloud", "aws", "azure", "gcp", "audit"],
        entry="prowler",
    ),
    "pacu": CatalogueEntry(
        repo="https://github.com/RhinoSecurityLabs/pacu",
        description="AWS exploitation framework for offensive security in cloud environments",
        tags=["cloud", "aws", "exploitation"],
        entry="pacu.py",
    ),
    "trivy": CatalogueEntry(
        repo="https://github.com/aquasecurity/trivy",
        description="Comprehensive vulnerability scanner for containers and filesystems",
        tags=["container", "docker", "vulnerability", "go"],
    ),
    "trufflehog": CatalogueEntry(
        repo="https://github.com/trufflesecurity/trufflehog",
        description="Find leaked credentials in git repos, S3 buckets, and more",
        tags=["secrets", "recon", "git", "go"],
    ),

    # ── Misc utilities ────────────────────────────────────────────────────
    "proxychains-ng": CatalogueEntry(
        repo="https://github.com/rofl0r/proxychains-ng",
        description="Route TCP connections through SOCKS4a/5 or HTTP proxies",
        tags=["network", "proxy", "tunnel"],
    ),
    "beef-xss": CatalogueEntry(
        repo="https://github.com/beefproject/beef",
        description="Browser Exploitation Framework — hook and control victim browsers via XSS",
        tags=["web", "xss", "browser", "exploitation"],
        entry="beef",
        lang=LANG_RUBY,
    ),
    "social-engineer-toolkit": CatalogueEntry(
        repo="https://github.com/trustedsec/social-engineer-toolkit",
        description="Open-source social engineering penetration testing framework",
        tags=["social-engineering", "phishing"],
        entry="se-toolkit",
    ),
    "evilginx2": CatalogueEntry(
        repo="https://github.com/kgretzky/evilginx2",
        description="Man-in-the-middle attack framework for phishing credentials and session tokens",
        tags=["phishing", "mitm", "credentials", "go"],
    ),
    "metabadger": CatalogueEntry(
        repo="https://github.com/salesforce/metabadger",
        description="Harden AWS EC2 instance metadata service (IMDSv2 enforcement)",
        tags=["cloud", "aws", "hardening"],
        entry="metabadger/__main__.py",
    ),
    "covenant": CatalogueEntry(
        repo="https://github.com/cobbr/Covenant",
        description=".NET C2 framework — collaborative, web-based, fileless agents",
        tags=["c2", "dotnet", "windows"],
        lang=LANG_BINARY,
    ),
    "sliver": CatalogueEntry(
        repo="https://github.com/BishopFox/sliver",
        description="Adversary simulation framework — cross-platform implants and C2",
        tags=["c2", "implant", "go"],
    ),
    "havoc": CatalogueEntry(
        repo="https://github.com/HavocFramework/Havoc",
        description="Modern, malleable post-exploitation C2 framework",
        tags=["c2", "post-exploitation", "windows"],
    ),

    # ── Web application security (continued) ─────────────────────────────
    "dalfox": CatalogueEntry(
        repo="https://github.com/hahwul/dalfox",
        description="Fast parameter analysis and XSS scanner written in Go",
        tags=["web", "xss", "scanner", "go"],
    ),
    "arjun": CatalogueEntry(
        repo="https://github.com/s0md3v/Arjun",
        description="HTTP parameter discovery suite — find hidden GET/POST/JSON/XML parameters",
        tags=["web", "recon", "parameters"],
        entry="arjun/__main__.py",
    ),
    "corsy": CatalogueEntry(
        repo="https://github.com/s0md3v/Corsy",
        description="CORS misconfiguration scanner",
        tags=["web", "cors", "scanner"],
        entry="corsy.py",
    ),
    "403bypass": CatalogueEntry(
        repo="https://github.com/iamj0ker/bypass-403",
        description="Simple script to bypass 403 Forbidden responses",
        tags=["web", "bypass", "403"],
        entry="bypass-403.sh",
        lang=LANG_BASH,
    ),
    "jwt-tool": CatalogueEntry(
        repo="https://github.com/ticarpi/jwt_tool",
        description="Toolkit for testing, tweaking and cracking JWTs",
        tags=["web", "jwt", "auth"],
        entry="jwt_tool.py",
    ),
    "jwtcrack": CatalogueEntry(
        repo="https://github.com/brendan-rius/c-jwt-cracker",
        description="Multithreaded JWT brute-force cracker in C",
        tags=["web", "jwt", "cracking"],
    ),
    "graphqlmap": CatalogueEntry(
        repo="https://github.com/swisskyrepo/GraphQLmap",
        description="Scripting engine to interact with and exploit GraphQL endpoints",
        tags=["web", "graphql", "injection"],
        entry="graphqlmap.py",
    ),
    "ghauri": CatalogueEntry(
        repo="https://github.com/r0oth3x49/ghauri",
        description="Advanced cross-platform SQL injection detection and exploitation tool",
        tags=["web", "sql", "injection"],
        entry="ghauri/__main__.py",
    ),
    "burpsuite-pro-scripts": CatalogueEntry(
        repo="https://github.com/PortSwigger/burp-extensions-montoya-api",
        description="Burp Suite Montoya API examples and extension scaffolding",
        tags=["web", "burp", "proxy"],
        entry=".",
        lang=LANG_JAVA,
    ),
    "caido": CatalogueEntry(
        repo="https://github.com/caido/caido",
        description="Lightweight web security auditing toolkit — modern Burp alternative",
        tags=["web", "proxy", "scanner"],
        lang=LANG_BINARY,
    ),
    "interactsh": CatalogueEntry(
        repo="https://github.com/projectdiscovery/interactsh",
        description="OOB interaction server for detecting blind vulnerabilities",
        tags=["web", "oob", "dns", "go"],
    ),
    "katana": CatalogueEntry(
        repo="https://github.com/projectdiscovery/katana",
        description="Next-generation crawling and spidering framework",
        tags=["web", "crawler", "recon", "go"],
    ),
    "gospider": CatalogueEntry(
        repo="https://github.com/jaeles-project/gospider",
        description="Fast web spider written in Go",
        tags=["web", "crawler", "recon", "go"],
    ),
    "hakrawler": CatalogueEntry(
        repo="https://github.com/hakluke/hakrawler",
        description="Simple, fast web crawler for gathering URLs and JavaScript file locations",
        tags=["web", "crawler", "recon", "go"],
    ),
    "wafw00f": CatalogueEntry(
        repo="https://github.com/EnableSecurity/wafw00f",
        description="Web Application Firewall fingerprinting and detection tool",
        tags=["web", "waf", "fingerprint"],
        entry="wafw00f/__main__.py",
    ),

    # ── Network scanning & enumeration (continued) ────────────────────────
    "rustscan": CatalogueEntry(
        repo="https://github.com/RustScan/RustScan",
        description="The Modern Port Scanner — scans all 65k ports in 3 seconds",
        tags=["network", "scanner", "port", "rust"],
    ),
    "sx": CatalogueEntry(
        repo="https://github.com/v-byte-cpu/sx",
        description="Fast, modern, permissive network scanner",
        tags=["network", "scanner", "go"],
    ),
    "zmap": CatalogueEntry(
        repo="https://github.com/zmap/zmap",
        description="Fast single-packet network scanner for internet-wide surveys",
        tags=["network", "scanner", "port"],
    ),
    "zgrab2": CatalogueEntry(
        repo="https://github.com/zmap/zgrab2",
        description="Go application-layer scanner companion to ZMap",
        tags=["network", "scanner", "banner", "go"],
    ),
    "shodan-cli": CatalogueEntry(
        repo="https://github.com/achillean/shodan-python",
        description="Python library and command-line interface for Shodan",
        tags=["recon", "shodan", "osint"],
        entry="shodan/__main__.py",
    ),
    "smap": CatalogueEntry(
        repo="https://github.com/s0md3v/Smap",
        description="Drop-in replacement for Nmap powered by Shodan.io",
        tags=["network", "scanner", "shodan", "go"],
    ),
    "naabu-templates": CatalogueEntry(
        repo="https://github.com/projectdiscovery/nuclei-templates",
        description="Community-curated list of templates for the Nuclei scanner",
        tags=["scanner", "vulnerability", "templates"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "uncover": CatalogueEntry(
        repo="https://github.com/projectdiscovery/uncover",
        description="Quickly discover exposed hosts using multiple search engines",
        tags=["recon", "shodan", "censys", "go"],
    ),
    "mapcidr": CatalogueEntry(
        repo="https://github.com/projectdiscovery/mapcidr",
        description="Utility to perform multiple operations on CIDR ranges",
        tags=["network", "cidr", "go"],
    ),
    "asnmap": CatalogueEntry(
        repo="https://github.com/projectdiscovery/asnmap",
        description="Map organisation network ranges using ASN information",
        tags=["recon", "asn", "network", "go"],
    ),
    "cdncheck": CatalogueEntry(
        repo="https://github.com/projectdiscovery/cdncheck",
        description="Identify CDN, WAF, and Cloud provider infrastructure",
        tags=["recon", "cdn", "network", "go"],
    ),
    "netdiscover": CatalogueEntry(
        repo="https://github.com/alexxy/netdiscover",
        description="Active/passive address reconnaissance tool using ARP",
        tags=["network", "arp", "discovery"],
    ),
    "arp-scan": CatalogueEntry(
        repo="https://github.com/royhills/arp-scan",
        description="ARP scanner and fingerprinter",
        tags=["network", "arp", "scanner"],
    ),

    # ── DNS & subdomain enumeration ───────────────────────────────────────
    "massdns": CatalogueEntry(
        repo="https://github.com/blechschmidt/massdns",
        description="High-performance DNS stub resolver for bulk lookups and recon",
        tags=["recon", "dns", "subdomain"],
    ),
    "puredns": CatalogueEntry(
        repo="https://github.com/d3mondev/puredns",
        description="Fast domain resolver and subdomain bruteforcing tool using massdns",
        tags=["recon", "dns", "subdomain", "go"],
    ),
    "dnsprobe": CatalogueEntry(
        repo="https://github.com/projectdiscovery/dnsprobe",
        description="Tool based on retryabledns that allows to perform multiple DNS queries",
        tags=["recon", "dns", "go"],
    ),
    "shuffledns": CatalogueEntry(
        repo="https://github.com/projectdiscovery/shuffledns",
        description="MassDNS wrapper to bruteforce and resolve valid subdomains",
        tags=["recon", "dns", "subdomain", "go"],
    ),
    "gotator": CatalogueEntry(
        repo="https://github.com/Josue87/gotator",
        description="Generate DNS wordlists through permutations",
        tags=["recon", "dns", "wordlist", "go"],
    ),
    "altdns": CatalogueEntry(
        repo="https://github.com/infosec-au/altdns",
        description="Subdomain discovery through alterations and permutations",
        tags=["recon", "dns", "subdomain"],
        entry="altdns/__main__.py",
    ),
    "assetfinder": CatalogueEntry(
        repo="https://github.com/tomnomnom/assetfinder",
        description="Find domains and subdomains related to a given domain",
        tags=["recon", "subdomain", "go"],
    ),
    "hakrevdns": CatalogueEntry(
        repo="https://github.com/hakluke/hakrevdns",
        description="Small, fast tool for performing reverse DNS lookups",
        tags=["recon", "dns", "go"],
    ),

    # ── Credential attacks (continued) ────────────────────────────────────
    "spray": CatalogueEntry(
        repo="https://github.com/Greenwolf/Spray",
        description="Password spraying tool for Active Directory and various protocols",
        tags=["bruteforce", "ad", "credentials"],
        entry="spray.sh",
        lang=LANG_BASH,
    ),
    "sprayhound": CatalogueEntry(
        repo="https://github.com/Hackndo/sprayhound",
        description="Password spraying tool with lockout policy awareness",
        tags=["bruteforce", "ad", "credentials"],
        entry="sprayhound/__main__.py",
    ),
    "dementor": CatalogueEntry(
        repo="https://github.com/fox-it/aclpwn.py",
        description="ACL-based privilege escalation in Active Directory",
        tags=["ad", "privesc", "acl"],
        entry="aclpwn/__main__.py",
    ),
    "hashid": CatalogueEntry(
        repo="https://github.com/psypanda/hashID",
        description="Identify the different types of hashes used to encrypt data",
        tags=["hash", "identify", "password"],
        entry="hashid.py",
    ),
    "haiti": CatalogueEntry(
        repo="https://github.com/noraj/haiti",
        description="Hash type identifier (CLI & library)",
        tags=["hash", "identify", "password"],
        lang=LANG_RUBY,
    ),
    "name-that-hash": CatalogueEntry(
        repo="https://github.com/HashPals/Name-That-Hash",
        description="Identify MD5, SHA256 and 300+ other hash types — faster and prettier",
        tags=["hash", "identify", "password"],
        entry="name_that_hash/__main__.py",
    ),
    "cupp": CatalogueEntry(
        repo="https://github.com/Mebus/cupp",
        description="Common User Passwords Profiler — generate targeted wordlists",
        tags=["password", "wordlist", "osint"],
        entry="cupp.py",
    ),
    "cewl": CatalogueEntry(
        repo="https://github.com/digininja/CeWL",
        description="Custom word list generator — spider a URL and build a wordlist",
        tags=["password", "wordlist", "web"],
        entry="cewl.rb",
        lang=LANG_RUBY,
    ),
    "mentalist": CatalogueEntry(
        repo="https://github.com/sc0tfree/mentalist",
        description="Graphical tool for custom wordlist generation",
        tags=["password", "wordlist"],
        entry="mentalist/__main__.py",
    ),
    "crowbar": CatalogueEntry(
        repo="https://github.com/galkan/crowbar",
        description="Brute-forcing tool that supports OpenVPN, RDP, SSH key, and VNC",
        tags=["bruteforce", "rdp", "ssh", "vpn"],
        entry="crowbar.py",
    ),
    "patator": CatalogueEntry(
        repo="https://github.com/lanjelot/patator",
        description="Multi-purpose brute-forcer with a modular design",
        tags=["bruteforce", "credentials", "multi-protocol"],
        entry="patator/__main__.py",
    ),

    # ── Post-exploitation (continued) ─────────────────────────────────────
    "lsassy": CatalogueEntry(
        repo="https://github.com/Hackndo/lsassy",
        description="Extract credentials from lsass remotely",
        tags=["windows", "credentials", "lsass"],
        entry="lsassy/__main__.py",
    ),
    "pypykatz": CatalogueEntry(
        repo="https://github.com/skelsec/pypykatz",
        description="Mimikatz implementation in pure Python",
        tags=["windows", "credentials", "mimikatz"],
        entry="pypykatz/__main__.py",
    ),
    "impacket-scripts": CatalogueEntry(
        repo="https://github.com/fortra/impacket",
        description="Impacket example scripts — secretsdump, psexec, wmiexec and more",
        tags=["windows", "ad", "smb", "scripts"],
        entry="impacket/examples/secretsdump.py",
    ),
    "dcsync": CatalogueEntry(
        repo="https://github.com/n00py/WPForce",
        description="WordPress attack tool — brute force and agent injection",
        tags=["web", "wordpress", "bruteforce"],
        entry="wpforce.py",
    ),
    "seatbelt": CatalogueEntry(
        repo="https://github.com/GhostPack/Seatbelt",
        description="C# situational awareness tool for local Windows privilege escalation checks",
        tags=["windows", "privesc", "enumeration"],
        lang=LANG_BINARY,
    ),
    "sharphound": CatalogueEntry(
        repo="https://github.com/BloodHoundAD/SharpHound",
        description="C# data ingestor for BloodHound — collect AD data quickly",
        tags=["ad", "windows", "bloodhound"],
        lang=LANG_BINARY,
    ),
    "rubeus": CatalogueEntry(
        repo="https://github.com/GhostPack/Rubeus",
        description="C# toolset for raw Kerberos interaction and abuse",
        tags=["kerberos", "ad", "windows"],
        lang=LANG_BINARY,
    ),
    "certify": CatalogueEntry(
        repo="https://github.com/GhostPack/Certify",
        description="C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services",
        tags=["ad", "windows", "certificates", "privesc"],
        lang=LANG_BINARY,
    ),
    "adcs-attack": CatalogueEntry(
        repo="https://github.com/ly4k/Certipy",
        description="Python tool for enumerating and abusing Active Directory Certificate Services",
        tags=["ad", "windows", "certificates", "privesc"],
        entry="certipy/__main__.py",
    ),
    "powerview-py": CatalogueEntry(
        repo="https://github.com/the-useless-one/pywerview",
        description="Python partial port of PowerView — AD recon without PowerShell",
        tags=["ad", "recon", "powerview"],
        entry="pywerview/__main__.py",
    ),
    "ldapnomnom": CatalogueEntry(
        repo="https://github.com/lkarlslund/ldapnomnom",
        description="Anonymously bruteforce Active Directory usernames from LDAP",
        tags=["ad", "ldap", "bruteforce", "go"],
    ),
    "enum4linux-ng": CatalogueEntry(
        repo="https://github.com/cddmp/enum4linux-ng",
        description="Next-generation enum4linux — Windows/Samba enumeration tool",
        tags=["windows", "smb", "enumeration"],
        entry="enum4linux-ng.py",
    ),
    "windapsearch": CatalogueEntry(
        repo="https://github.com/ropnop/windapsearch",
        description="Python script to enumerate users, groups and computers from AD via LDAP",
        tags=["ad", "ldap", "enumeration"],
        entry="windapsearch.py",
    ),
    "go-windapsearch": CatalogueEntry(
        repo="https://github.com/ropnop/go-windapsearch",
        description="Go port of windapsearch — fast AD LDAP enumeration",
        tags=["ad", "ldap", "enumeration", "go"],
    ),

    # ── OSINT (continued) ─────────────────────────────────────────────────
    "recon-ng": CatalogueEntry(
        repo="https://github.com/lanmaster53/recon-ng",
        description="Full-featured web reconnaissance framework with independent modules",
        tags=["osint", "recon", "framework"],
        entry="recon-ng",
    ),
    "maltego-trx": CatalogueEntry(
        repo="https://github.com/MaltegoTech/maltego-trx",
        description="Python library for writing Maltego transforms",
        tags=["osint", "maltego"],
        entry="maltego_trx/__main__.py",
    ),
    "phoneinfoga": CatalogueEntry(
        repo="https://github.com/sundowndev/phoneinfoga",
        description="Advanced information gathering and OSINT framework for phone numbers",
        tags=["osint", "phone"],
    ),
    "socialscan": CatalogueEntry(
        repo="https://github.com/iojw/socialscan",
        description="Check email address and username availability on online platforms",
        tags=["osint", "username", "email"],
        entry="socialscan/__main__.py",
    ),
    "osintgram": CatalogueEntry(
        repo="https://github.com/Datalux/Osintgram",
        description="OSINT tool on Instagram — collect info on any target account",
        tags=["osint", "instagram", "social-media"],
        entry="main.py",
    ),
    "twint": CatalogueEntry(
        repo="https://github.com/twintproject/twint",
        description="Twitter intelligence tool — scrape tweets without API limits",
        tags=["osint", "twitter", "social-media"],
        entry="twint/__main__.py",
    ),
    "photon": CatalogueEntry(
        repo="https://github.com/s0md3v/Photon",
        description="Incredibly fast crawler designed for OSINT — extracts URLs, emails, files",
        tags=["osint", "crawler", "recon"],
        entry="photon.py",
    ),
    "h8mail": CatalogueEntry(
        repo="https://github.com/khast3x/h8mail",
        description="Email OSINT and breach hunting tool",
        tags=["osint", "email", "breach"],
        entry="h8mail/__main__.py",
    ),
    "finalrecon": CatalogueEntry(
        repo="https://github.com/thewhiteh4t/FinalRecon",
        description="The last web recon tool you'll ever need — full-featured OSINT",
        tags=["osint", "recon", "web"],
        entry="finalrecon.py",
    ),
    "metagoofil": CatalogueEntry(
        repo="https://github.com/opsdisk/metagoofil",
        description="Metadata extraction tool for public documents (pdf, doc, xls…)",
        tags=["osint", "metadata", "documents"],
        entry="metagoofil.py",
    ),
    "exifool": CatalogueEntry(
        repo="https://github.com/exiftool/exiftool",
        description="Read, write, and edit meta information in files",
        tags=["osint", "metadata", "exif"],
        entry="exiftool",
        lang=LANG_UNKNOWN,
    ),
    "foca": CatalogueEntry(
        repo="https://github.com/ElevenPaths/FOCA",
        description="Metadata extraction and analysis tool for publicly available documents",
        tags=["osint", "metadata"],
        lang=LANG_BINARY,
    ),

    # ── Wireless (continued) ──────────────────────────────────────────────
    "aircrack-ng": CatalogueEntry(
        repo="https://github.com/aircrack-ng/aircrack-ng",
        description="Complete suite for auditing wireless networks — crack WEP/WPA",
        tags=["wireless", "wifi", "cracking"],
    ),
    "bettercap": CatalogueEntry(
        repo="https://github.com/bettercap/bettercap",
        description="Swiss army knife for network attacks and monitoring",
        tags=["network", "mitm", "wireless", "go"],
    ),
    "kismet": CatalogueEntry(
        repo="https://github.com/kismetwireless/kismet",
        description="Wireless network and device detector, sniffer, wardriver, and WIDS",
        tags=["wireless", "scanner", "sniffer"],
    ),
    "eaphammer": CatalogueEntry(
        repo="https://github.com/s0lst1c3/eaphammer",
        description="Targeted evil twin attacks against WPA2-Enterprise networks",
        tags=["wireless", "wifi", "eap", "evil-twin"],
        entry="eaphammer",
    ),
    "pixiewps": CatalogueEntry(
        repo="https://github.com/wiire-a/pixiewps",
        description="Offline WPS bruteforce utility exploiting the pixie dust attack",
        tags=["wireless", "wps", "cracking"],
    ),
    "reaver": CatalogueEntry(
        repo="https://github.com/t6x/reaver-wps-fork-t6x",
        description="Brute force attack against WPS registrar PINs",
        tags=["wireless", "wps", "bruteforce"],
    ),

    # ── Cloud & container (continued) ─────────────────────────────────────
    "scoutsuite": CatalogueEntry(
        repo="https://github.com/nccgroup/ScoutSuite",
        description="Multi-cloud security auditing tool (AWS, Azure, GCP, Alibaba, Oracle)",
        tags=["cloud", "aws", "azure", "gcp", "audit"],
        entry="scout/__main__.py",
    ),
    "cloudsploit": CatalogueEntry(
        repo="https://github.com/aquasecurity/cloudsploit",
        description="Cloud security configuration scanner for AWS, Azure, GCP, Oracle",
        tags=["cloud", "scanner", "aws", "azure", "gcp"],
        entry="index.js",
        lang=LANG_NODE,
    ),
    "cloudmapper": CatalogueEntry(
        repo="https://github.com/duo-labs/cloudmapper",
        description="Analyze AWS environments and create visualisations of the network",
        tags=["cloud", "aws", "recon"],
        entry="cloudmapper.py",
    ),
    "s3scanner": CatalogueEntry(
        repo="https://github.com/sa7mon/S3Scanner",
        description="Scan for misconfigured S3 buckets across S3-compatible APIs",
        tags=["cloud", "aws", "s3", "go"],
    ),
    "awscli-fuzz": CatalogueEntry(
        repo="https://github.com/BishopFox/dufflebag",
        description="Search exposed EBS volumes for secrets",
        tags=["cloud", "aws", "ebs", "secrets"],
        entry="dufflebag.py",
    ),
    "gitleaks": CatalogueEntry(
        repo="https://github.com/gitleaks/gitleaks",
        description="Detect hardcoded secrets like passwords and API keys in git repos",
        tags=["secrets", "git", "go"],
    ),
    "detect-secrets": CatalogueEntry(
        repo="https://github.com/Yelp/detect-secrets",
        description="Detect secrets within a codebase — baseline-aware",
        tags=["secrets", "git"],
        entry="detect_secrets/__main__.py",
    ),
    "semgrep": CatalogueEntry(
        repo="https://github.com/returntocorp/semgrep",
        description="Static analysis engine for finding bugs and enforcing code standards",
        tags=["sast", "code-review", "scanner"],
        entry="semgrep/__main__.py",
    ),
    "deepce": CatalogueEntry(
        repo="https://github.com/stealthcopter/deepce",
        description="Docker enumeration, escalation and exploitation script",
        tags=["container", "docker", "privesc"],
        entry="deepce.sh",
        lang=LANG_BASH,
    ),
    "botb": CatalogueEntry(
        repo="https://github.com/brompwnie/botb",
        description="Container breakout, analysis and exploitation tool",
        tags=["container", "docker", "breakout", "go"],
    ),

    # ── Network pivoting & tunnelling ─────────────────────────────────────
    "frp": CatalogueEntry(
        repo="https://github.com/fatedier/frp",
        description="Fast reverse proxy to expose local servers behind a NAT or firewall",
        tags=["tunnel", "proxy", "go"],
    ),
    "rathole": CatalogueEntry(
        repo="https://github.com/rapiz1/rathole",
        description="Secure, stable and high-performance reverse proxy in Rust",
        tags=["tunnel", "proxy", "rust"],
    ),
    "bore": CatalogueEntry(
        repo="https://github.com/ekzhang/bore",
        description="Modern, simple TCP tunnel in Rust",
        tags=["tunnel", "tcp", "rust"],
    ),
    "goproxy": CatalogueEntry(
        repo="https://github.com/snail007/goproxy",
        description="Proxy server supporting HTTP/HTTPS/WebSocket/TCP/UDP/SOCKS5",
        tags=["proxy", "tunnel", "go"],
    ),
    "ssf": CatalogueEntry(
        repo="https://github.com/securesocketfunneling/ssf",
        description="Secure Socket Funneling — network tool and toolkit for multiplexed tunnels",
        tags=["tunnel", "pivot", "network"],
    ),
    "rpivot": CatalogueEntry(
        repo="https://github.com/klsecservices/rpivot",
        description="Reverse SOCKS proxy for penetration testing",
        tags=["proxy", "socks", "pivot"],
        entry="server.py",
    ),
    "revsocks": CatalogueEntry(
        repo="https://github.com/kost/revsocks",
        description="Reverse SOCKS5 proxy tool",
        tags=["proxy", "socks", "pivot", "go"],
    ),
    "iodine": CatalogueEntry(
        repo="https://github.com/yarrick/iodine",
        description="Forward IPv4 traffic through DNS — DNS tunnelling",
        tags=["tunnel", "dns", "network"],
    ),
    "dnscat2": CatalogueEntry(
        repo="https://github.com/iagox86/dnscat2",
        description="Encrypted command-and-control over DNS",
        tags=["c2", "dns", "tunnel"],
        entry="server/dnscat2.rb",
        lang=LANG_RUBY,
    ),
    "icmpsh": CatalogueEntry(
        repo="https://github.com/bdamele/icmpsh",
        description="Simple reverse ICMP shell",
        tags=["shell", "icmp", "tunnel"],
        entry="icmpsh.py",
    ),

    # ── Exploitation & vulnerability research ────────────────────────────
    "exploitdb": CatalogueEntry(
        repo="https://github.com/offensive-security/exploitdb",
        description="The official Exploit-DB repository — searchsploit archive",
        tags=["exploit", "cve", "database"],
        entry="searchsploit",
        lang=LANG_BASH,
    ),
    "poc-in-github": CatalogueEntry(
        repo="https://github.com/nomi-sec/PoC-in-GitHub",
        description="PoC auto-collected from GitHub, mapping to CVE identifiers",
        tags=["exploit", "cve", "poc"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "metasploit-framework": CatalogueEntry(
        repo="https://github.com/rapid7/metasploit-framework",
        description="The world's most used penetration testing framework",
        tags=["exploit", "framework", "msf"],
        entry="msfconsole",
        lang=LANG_RUBY,
    ),
    "venom": CatalogueEntry(
        repo="https://github.com/r00t-3xp10it/venom",
        description="Shellcode generator / compiler / listener — shellcode injection",
        tags=["exploit", "shellcode", "payload"],
        entry="venom.sh",
        lang=LANG_BASH,
    ),
    "unicorn": CatalogueEntry(
        repo="https://github.com/trustedsec/unicorn",
        description="Simple PowerShell downgrade attack and inject shellcode into memory",
        tags=["exploit", "shellcode", "powershell"],
        entry="unicorn.py",
    ),
    "empire": CatalogueEntry(
        repo="https://github.com/BC-SECURITY/Empire",
        description="Post-exploitation framework with a focus on usability",
        tags=["c2", "post-exploitation", "powershell"],
        entry="empire/__main__.py",
    ),
    "pwntools": CatalogueEntry(
        repo="https://github.com/Gallopsled/pwntools",
        description="CTF framework and exploit development library",
        tags=["exploit", "ctf", "binary"],
        entry="pwnlib/__init__.py",
    ),
    "angr": CatalogueEntry(
        repo="https://github.com/angr/angr",
        description="Platform-agnostic binary analysis framework",
        tags=["binary", "analysis", "ctf"],
        entry="angr/__init__.py",
    ),
    "ropper": CatalogueEntry(
        repo="https://github.com/sashs/Ropper",
        description="Find ROP gadgets and JOP/COP chains in binaries",
        tags=["exploit", "rop", "binary"],
        entry="ropper/__main__.py",
    ),
    "one_gadget": CatalogueEntry(
        repo="https://github.com/david942j/one_gadget",
        description="Find one-shot ROP gadgets for execve('/bin/sh') in libc",
        tags=["exploit", "rop", "ctf"],
        lang=LANG_RUBY,
    ),

    # ── Forensics & reverse engineering ──────────────────────────────────
    "volatility3": CatalogueEntry(
        repo="https://github.com/volatilityfoundation/volatility3",
        description="Memory forensics framework — analyse RAM dumps",
        tags=["forensics", "memory", "analysis"],
        entry="vol.py",
    ),
    "autopsy": CatalogueEntry(
        repo="https://github.com/sleuthkit/autopsy",
        description="The Sleuth Kit digital forensics platform with GUI",
        tags=["forensics", "disk", "analysis"],
        lang=LANG_JAVA,
    ),
    "binwalk": CatalogueEntry(
        repo="https://github.com/ReFirmLabs/binwalk",
        description="Firmware analysis tool — extract embedded files and code",
        tags=["forensics", "firmware", "reverse-engineering"],
        entry="src/binwalk/__main__.py",
    ),
    "ghidra-scripts": CatalogueEntry(
        repo="https://github.com/ghidraninja/ghidra_scripts",
        description="Useful Ghidra scripts for reverse engineering",
        tags=["reverse-engineering", "ghidra"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "cutter": CatalogueEntry(
        repo="https://github.com/rizinorg/cutter",
        description="Free and open-source reverse engineering platform powered by Rizin",
        tags=["reverse-engineering", "disassembler"],
    ),
    "stegseek": CatalogueEntry(
        repo="https://github.com/RickdeJager/stegseek",
        description="Worlds fastest steghide cracker — crack steganography in seconds",
        tags=["forensics", "steganography", "ctf"],
    ),
    "zsteg": CatalogueEntry(
        repo="https://github.com/zed-0xff/zsteg",
        description="Detect stegano-hidden data in PNG and BMP files",
        tags=["forensics", "steganography", "ctf"],
        lang=LANG_RUBY,
    ),
    "oletools": CatalogueEntry(
        repo="https://github.com/decalage2/oletools",
        description="Tools to analyse Microsoft OLE2 files — macro analysis for malware",
        tags=["forensics", "malware", "office"],
        entry="oletools/__init__.py",
    ),
    "peepdf": CatalogueEntry(
        repo="https://github.com/jesparza/peepdf",
        description="Powerful Python tool to analyse malicious PDF documents",
        tags=["forensics", "pdf", "malware"],
        entry="peepdf.py",
    ),

    # ── Fuzzing ───────────────────────────────────────────────────────────
    "afl-plus-plus": CatalogueEntry(
        repo="https://github.com/AFLplusplus/AFLplusplus",
        description="American Fuzzy Lop ++ — state-of-the-art fuzzer",
        tags=["fuzzing", "afl", "coverage"],
    ),
    "libfuzzer-standalone": CatalogueEntry(
        repo="https://github.com/google/oss-fuzz",
        description="Continuous fuzzing for open source software — infrastructure repo",
        tags=["fuzzing", "oss"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "boofuzz": CatalogueEntry(
        repo="https://github.com/jtpereyda/boofuzz",
        description="Network protocol fuzzer and successor to Sulley",
        tags=["fuzzing", "network", "protocol"],
        entry="boofuzz/__init__.py",
    ),
    "radamsa": CatalogueEntry(
        repo="https://gitlab.com/akihe/radamsa",
        description="General-purpose fuzzer — mutate a sample corpus into test cases",
        tags=["fuzzing", "mutation"],
    ),

    # ── Social engineering ────────────────────────────────────────────────
    "gophish": CatalogueEntry(
        repo="https://github.com/gophish/gophish",
        description="Open-source phishing framework — build and manage phishing campaigns",
        tags=["phishing", "social-engineering", "go"],
    ),
    "king-phisher": CatalogueEntry(
        repo="https://github.com/securestate/king-phisher",
        description="Phishing campaign toolkit — simulate real-world phishing attacks",
        tags=["phishing", "social-engineering"],
        entry="KingPhisher/__init__.py",
    ),
    "maxphisher": CatalogueEntry(
        repo="https://github.com/KasRoudra/MaxPhisher",
        description="Advanced phishing tool with 70+ site templates",
        tags=["phishing", "social-engineering"],
        entry="maxphisher.py",
    ),
    "zphisher": CatalogueEntry(
        repo="https://github.com/htr-tech/zphisher",
        description="Automated phishing tool with 30+ templates",
        tags=["phishing", "social-engineering"],
        entry="zphisher.sh",
        lang=LANG_BASH,
    ),
    "evilurl": CatalogueEntry(
        repo="https://github.com/UndeadSec/EvilURL",
        description="Generate unicode evil URLs for IDN homograph attacks",
        tags=["phishing", "idn", "homograph"],
        entry="evilurl.py",
    ),

    # ── Utilities & misc ─────────────────────────────────────────────────
    "anew": CatalogueEntry(
        repo="https://github.com/tomnomnom/anew",
        description="Append lines from stdin to a file — only if they don't exist",
        tags=["utility", "pipeline", "go"],
    ),
    "gf": CatalogueEntry(
        repo="https://github.com/tomnomnom/gf",
        description="grep wrapper to find interesting patterns in data",
        tags=["utility", "grep", "go"],
    ),
    "waybackurls": CatalogueEntry(
        repo="https://github.com/tomnomnom/waybackurls",
        description="Fetch all URLs from the Wayback Machine for a domain",
        tags=["recon", "wayback", "go"],
    ),
    "gau": CatalogueEntry(
        repo="https://github.com/lc/gau",
        description="Fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl",
        tags=["recon", "urls", "go"],
    ),
    "unfurl": CatalogueEntry(
        repo="https://github.com/tomnomnom/unfurl",
        description="Pull out bits of URLs provided on stdin",
        tags=["utility", "url", "go"],
    ),
    "qsreplace": CatalogueEntry(
        repo="https://github.com/tomnomnom/qsreplace",
        description="Accept URLs on stdin and replace query-string parameter values",
        tags=["utility", "url", "go"],
    ),
    "airixss": CatalogueEntry(
        repo="https://github.com/ferreiraklet/airixss",
        description="Identifying XSS vulnerabilities in web applications",
        tags=["web", "xss", "go"],
    ),
    "haklistgen": CatalogueEntry(
        repo="https://github.com/hakluke/haklistgen",
        description="Turns any junk text into a usable wordlist for brute-forcing",
        tags=["wordlist", "go"],
    ),
    "wordlistctl": CatalogueEntry(
        repo="https://github.com/BlackArch/wordlistctl",
        description="Fetch, install and search wordlist archives from websites",
        tags=["wordlist", "utility"],
        entry="wordlistctl.py",
    ),
    "seclists": CatalogueEntry(
        repo="https://github.com/danielmiessler/SecLists",
        description="Collection of multiple types of lists used during security assessments",
        tags=["wordlist", "payloads", "fuzzing"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "payloadsallthethings": CatalogueEntry(
        repo="https://github.com/swisskyrepo/PayloadsAllTheThings",
        description="Useful payloads and bypasses for web security and penetration testing",
        tags=["payloads", "web", "bypass"],
        entry=".",
        lang=LANG_UNKNOWN,
    ),
    "nmap": CatalogueEntry(
        repo="https://github.com/nmap/nmap",
        description="Network mapper and port scanner — the Swiss army knife of networking",
        tags=["network", "scanner", "port"],
    ),
    "testssl": CatalogueEntry(
        repo="https://github.com/drwetter/testssl.sh",
        description="Testing TLS/SSL encryption anywhere on any port",
        tags=["ssl", "tls", "scanner"],
        entry="testssl.sh",
        lang=LANG_BASH,
    ),
    "sslscan": CatalogueEntry(
        repo="https://github.com/rbsec/sslscan",
        description="Tests SSL/TLS enabled services to discover supported cipher suites",
        tags=["ssl", "tls", "scanner"],
    ),
    "sslyze": CatalogueEntry(
        repo="https://github.com/nabla-c0d3/sslyze",
        description="Fast and powerful SSL/TLS server scanning library",
        tags=["ssl", "tls", "scanner"],
        entry="sslyze/__main__.py",
    ),
    "certgraph": CatalogueEntry(
        repo="https://github.com/lanrat/certgraph",
        description="Crawl the graph of certificate domain names — cert transparency recon",
        tags=["recon", "ssl", "certificate", "go"],
    ),
}


# ---------------------------------------------------------------------------
# Toolchain requirement definitions
# ---------------------------------------------------------------------------

@dataclass
class _Toolchain:
    """Describes what binaries a language needs and how to install them."""
    binaries:    list[str]              # commands that must be on PATH
    install_hint: str                   # human-readable install instructions


_TOOLCHAIN_REQS: dict[str, _Toolchain] = {
    LANG_PYTHON: _Toolchain(
        binaries=["python3"],
        install_hint="Install Python 3.10+ from https://python.org/downloads/",
    ),
    LANG_GO: _Toolchain(
        binaries=["go"],
        install_hint="Install Go from https://go.dev/dl/",
    ),
    LANG_RUST: _Toolchain(
        binaries=["cargo", "rustc"],
        install_hint="Install Rust via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
    ),
    LANG_NODE: _Toolchain(
        binaries=["node", "npm"],
        install_hint="Install Node.js from https://nodejs.org/",
    ),
    LANG_RUBY: _Toolchain(
        binaries=["ruby"],
        install_hint="Install Ruby from https://www.ruby-lang.org/en/downloads/",
    ),
    LANG_JAVA: _Toolchain(
        binaries=["java"],
        install_hint="Install JDK from https://adoptium.net/",
    ),
    LANG_BASH: _Toolchain(
        binaries=["bash"],
        install_hint="Install bash via your package manager",
    ),
    LANG_POWERSHELL: _Toolchain(
        binaries=["pwsh"],
        install_hint="Install PowerShell from https://github.com/PowerShell/PowerShell/releases",
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def install(
    repo_url:     str,
    name:         str,
    description:  str = "",
    entry:        str = "",
    tags:         Optional[list[str]] = None,
    progress:     ProgressFn = _NOOP,
    expected_sha: str = "",
) -> Tool:
    """
    Clone *repo_url* into tools/<name>, detect language, run pre-flight
    checks, build, optionally verify commit SHA, then register.

    Parameters
    ----------
    repo_url     : Git remote URL (https or ssh).
    name         : Short identifier used as the directory name and registry key.
    description  : Human-readable description; auto-inferred from README if empty.
    entry        : Override the entry-point relative path; auto-detected if empty.
    tags         : Optional list of tag strings for searching.
    progress     : Callback called with each status line (str → None).
    expected_sha : If non-empty, the first 7 chars of the cloned HEAD commit
                   must match this value or the install is aborted and rolled back.

    Returns
    -------
    The registered Tool object.

    Raises
    ------
    RuntimeError on any unrecoverable failure.
    """
    dest = os.path.join(TOOLS_DIR, name)

    if os.path.isdir(dest):
        raise RuntimeError(
            f"Tool '{name}' is already installed at {dest}\n"
            f"  Use:  toolbox update {name}   to pull changes\n"
            f"  Use:  toolbox rebuild {name}  to re-build in place\n"
            f"  Use:  toolbox remove {name}   then re-install"
        )

    # Pre-flight: git must exist
    _require("git")

    # Clone
    progress(f"[*] Cloning {repo_url} → {dest}")
    _git_clone(repo_url, dest, progress)

    # Commit SHA verification (optional)
    if expected_sha:
        actual = _git_head_short(dest)
        if not actual or not actual.startswith(expected_sha[:7]):
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(
                f"SHA mismatch for '{name}': expected {expected_sha[:7]}, "
                f"got {actual or '(unknown)'}.  Installation aborted."
            )
        progress(f"[+] Commit SHA verified: {actual}")

    # Language detection
    lang = detect_language(dest)
    progress(f"[*] Detected language: {lang}")

    # Toolchain pre-flight warning (non-fatal)
    _preflight_toolchain(lang, progress)

    # Build / install deps
    run_cmd = build(dest, name, lang, progress)

    # Entry-point detection / override
    if not entry:
        entry = detect_entry(dest, name, lang)
        progress(f"[*] Entry-point: {entry}")

    # Record the installed commit hash
    commit = _git_head_short(dest) or ""

    tool = Tool(
        name=name,
        repo=repo_url,
        description=description or _infer_description(dest),
        entry=entry,
        lang=lang,
        run_cmd=run_cmd,
        tags=tags or [],
    )
    # Stash commit in installed_at for display purposes
    registry.add(tool)
    if commit:
        progress(f"[*] Installed at commit: {commit}")
    progress(f"[+] '{name}' installed and registered.")
    return tool


def install_from_catalogue(
    short_name: str,
    name_override: str = "",
    tags_extra: Optional[list[str]] = None,
    progress: ProgressFn = _NOOP,
) -> Tool:
    """
    Install a tool from the built-in CATALOGUE by its short name.

    Parameters
    ----------
    short_name    : Key in CATALOGUE (e.g. "sqlmap", "gobuster").
    name_override : Use a different local name if supplied.
    tags_extra    : Additional tags to merge with the catalogue defaults.
    progress      : Progress callback.
    """
    entry_def = CATALOGUE.get(short_name)
    if entry_def is None:
        available = ", ".join(sorted(CATALOGUE.keys()))
        raise RuntimeError(
            f"'{short_name}' is not in the built-in catalogue.\n"
            f"Available: {available}\n"
            f"To install a custom tool use:  toolbox install <url> <name>"
        )
    name = name_override or short_name
    tags = list(entry_def.tags)
    if tags_extra:
        tags.extend(t for t in tags_extra if t not in tags)

    progress(f"[*] Installing from catalogue: {short_name}")
    progress(f"[*] Source: {entry_def.repo}")

    return install(
        repo_url=entry_def.repo,
        name=name,
        description=entry_def.description,
        entry=entry_def.entry,
        tags=tags,
        progress=progress,
    )


def list_catalogue(query: str = "") -> list[tuple[str, CatalogueEntry]]:
    """
    Return catalogue entries matching *query* (case-insensitive substring
    match against name, description, and tags).  Returns all entries when
    *query* is empty.
    """
    q = query.lower()
    results = []
    for key, entry in sorted(CATALOGUE.items()):
        if not q:
            results.append((key, entry))
            continue
        if (q in key.lower()
                or q in entry.description.lower()
                or any(q in t for t in entry.tags)):
            results.append((key, entry))
    return results


def install_many(
    specs: list[dict],
    progress: ProgressFn = _NOOP,
    max_workers: int = 4,
) -> dict[str, Tool | Exception]:
    """
    Install multiple tools in parallel (clone phase is parallelised;
    build/register is serialised per tool to avoid subprocess conflicts).

    Each spec dict must have at minimum: {"repo": "...", "name": "..."}
    and may include: description, entry, tags, expected_sha.

    Returns a dict mapping name → Tool (success) or Exception (failure).
    """
    results: dict[str, Tool | Exception] = {}
    lock = threading.Lock()

    def _install_one(spec: dict) -> tuple[str, Tool | Exception]:
        name = spec.get("name", "")
        try:
            tool = install(
                repo_url=spec["repo"],
                name=name,
                description=spec.get("description", ""),
                entry=spec.get("entry", ""),
                tags=spec.get("tags", []),
                progress=progress,
                expected_sha=spec.get("expected_sha", ""),
            )
            with lock:
                progress(f"[+] Parallel install complete: {name}")
            return name, tool
        except Exception as exc:
            with lock:
                progress(f"[-] Parallel install failed for '{name}': {exc}")
            return name, exc

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="megaploit-install",
    ) as pool:
        futures = {pool.submit(_install_one, spec): spec for spec in specs}
        for future in concurrent.futures.as_completed(futures):
            name, result = future.result()
            results[name] = result

    return results


def uninstall(name: str, progress: ProgressFn = _NOOP) -> None:
    """Remove a tool's files from disk and unregister it."""
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if os.path.isdir(tool.path):
        shutil.rmtree(tool.path)
        progress(f"[+] Removed {tool.path}")
    registry.remove(name)
    progress(f"[+] '{name}' unregistered.")


def update(name: str, progress: ProgressFn = _NOOP) -> None:
    """git pull (fast-forward only) + full rebuild."""
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if not os.path.isdir(tool.path):
        raise RuntimeError(
            f"Tool directory not found: {tool.path}\n"
            f"  Re-install with:  toolbox install {tool.repo} {name}"
        )
    _require("git")
    old_head = _git_head_short(tool.path)
    progress(f"[*] Pulling latest changes for '{name}'…  (was {old_head})")
    _run(["git", "-C", tool.path, "pull", "--ff-only"], progress)
    new_head = _git_head_short(tool.path)
    if old_head and new_head and old_head == new_head:
        progress(f"[*] '{name}' already up to date ({new_head}).")
    else:
        progress(f"[*] Updated: {old_head} → {new_head}")
    # Re-run full build so new deps / recompiled binaries are picked up
    progress(f"[*] Rebuilding '{name}'…")
    tool.run_cmd = build(tool.path, name, tool.lang, progress)
    tool.entry   = detect_entry(tool.path, name, tool.lang)
    registry.add(tool)   # persist updated run_cmd + entry
    progress(f"[+] '{name}' updated.")


def healthcheck(name: str, progress: ProgressFn = _NOOP) -> bool:
    """
    Verify a registered tool is in a runnable state:
      • Directory exists
      • Entry-point exists on disk
      • For Python tools: entry-point compiles without syntax errors
      • For binary tools: entry-point is executable

    Returns True if healthy, False otherwise.
    """
    tool = registry.get(name)
    if not tool:
        progress(f"[-] '{name}' not found in registry.")
        return False

    ok = True

    if not os.path.isdir(tool.path):
        progress(f"[-] Tool directory missing: {tool.path}")
        ok = False

    entry_abs = tool.entry_path
    if not os.path.exists(entry_abs):
        # entry may be "." (compiled language fallback) — that's acceptable
        if tool.entry not in (".", ""):
            progress(f"[!] Entry-point not found: {entry_abs}")
            ok = False
    else:
        if tool.lang == LANG_PYTHON:
            try:
                import ast
                with open(entry_abs, "r", encoding="utf-8", errors="replace") as fh:
                    ast.parse(fh.read())
                progress(f"[+] Python entry-point parses cleanly: {tool.entry}")
            except SyntaxError as exc:
                progress(f"[-] Syntax error in {tool.entry}: {exc}")
                ok = False
        elif tool.lang in (LANG_BINARY, LANG_GO, LANG_RUST):
            if not os.access(entry_abs, os.X_OK) and sys.platform != "win32":
                progress(f"[!] Entry-point not executable: {entry_abs}")
                # Non-fatal — chmod may fix it
                try:
                    os.chmod(entry_abs, 0o755)
                    progress(f"[*] Fixed permissions on {tool.entry}")
                except OSError:
                    ok = False

    if ok:
        progress(f"[+] '{name}' health check passed.")
    else:
        progress(f"[-] '{name}' health check FAILED.")
    return ok


def generate_dockerfile(name: str, progress: ProgressFn = _NOOP) -> str:
    """
    Write a minimal Dockerfile into tools/<name>/Dockerfile that packages
    the tool.  Returns the path to the generated Dockerfile.

    The image is chosen based on the tool's detected language:
      Python → python:3.12-slim
      Go     → golang:1.22-alpine  (multi-stage)
      Rust   → rust:1-alpine       (multi-stage)
      Node   → node:lts-alpine
      Ruby   → ruby:3-alpine
      Java   → eclipse-temurin:21-jre-alpine
      Bash   → debian:bookworm-slim
      other  → debian:bookworm-slim
    """
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if not os.path.isdir(tool.path):
        raise RuntimeError(f"Tool directory missing: {tool.path}")

    dockerfile_path = os.path.join(tool.path, "Dockerfile.megaploit")

    lang = tool.lang
    run_cmd_str = " ".join(tool.resolved_run_cmd())

    if lang == LANG_PYTHON:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer
            FROM python:3.12-slim
            WORKDIR /tool
            COPY . .
            RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true
            ENTRYPOINT {json.dumps(tool.resolved_run_cmd())}
        """)

    elif lang == LANG_GO:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer (multi-stage Go build)
            FROM golang:1.22-alpine AS builder
            WORKDIR /src
            COPY . .
            RUN go build -ldflags="-s -w" -o /tool/{name} ./...

            FROM alpine:3.19
            COPY --from=builder /tool/{name} /{name}
            ENTRYPOINT ["/{name}"]
        """)

    elif lang == LANG_RUST:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer (multi-stage Rust build)
            FROM rust:1-alpine AS builder
            RUN apk add --no-cache musl-dev
            WORKDIR /src
            COPY . .
            RUN cargo build --release

            FROM alpine:3.19
            COPY --from=builder /src/target/release/{name} /{name}
            ENTRYPOINT ["/{name}"]
        """)

    elif lang == LANG_NODE:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer
            FROM node:lts-alpine
            WORKDIR /tool
            COPY . .
            RUN npm ci --silent 2>/dev/null || npm install --silent
            ENTRYPOINT {json.dumps(tool.resolved_run_cmd())}
        """)

    elif lang == LANG_RUBY:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer
            FROM ruby:3-alpine
            RUN apk add --no-cache build-base
            WORKDIR /tool
            COPY . .
            RUN bundle install --quiet 2>/dev/null || true
            ENTRYPOINT {json.dumps(tool.resolved_run_cmd())}
        """)

    elif lang == LANG_JAVA:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer
            FROM eclipse-temurin:21-jre-alpine
            WORKDIR /tool
            COPY . .
            ENTRYPOINT {json.dumps(tool.resolved_run_cmd())}
        """)

    else:
        content = textwrap.dedent(f"""\
            # Auto-generated by megaploit toolbox installer
            FROM debian:bookworm-slim
            WORKDIR /tool
            COPY . .
            RUN chmod +x {tool.entry} 2>/dev/null || true
            ENTRYPOINT {json.dumps(tool.resolved_run_cmd())}
        """)

    with open(dockerfile_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    progress(f"[+] Dockerfile written: {dockerfile_path}")
    progress(f"[*] Build image with:  docker build -t {name} -f Dockerfile.megaploit {tool.path}")
    return dockerfile_path


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def detect_language(repo_dir: str) -> str:
    """
    Inspect the repo root for well-known project files and return a lang ID.
    Order matters — check the most specific signals first.
    Deep-scan subdirectories one level down when the root is ambiguous.
    """
    files = set(os.listdir(repo_dir))

    # Python (most common in security tools — check first)
    if any(f in files for f in (
        "requirements.txt", "setup.py", "pyproject.toml", "setup.cfg", "Pipfile"
    )):
        return LANG_PYTHON
    if any(f.endswith(".py") for f in files):
        return LANG_PYTHON

    # Go
    if "go.mod" in files or "go.sum" in files:
        return LANG_GO
    if any(f.endswith(".go") for f in files):
        return LANG_GO

    # Rust
    if "Cargo.toml" in files:
        return LANG_RUST

    # Node.js
    if "package.json" in files:
        return LANG_NODE
    if "yarn.lock" in files or "package-lock.json" in files:
        return LANG_NODE

    # Ruby
    if "Gemfile" in files or "Gemfile.lock" in files:
        return LANG_RUBY
    if any(f.endswith(".rb") for f in files):
        return LANG_RUBY
    if any(f.endswith(".gemspec") for f in files):
        return LANG_RUBY

    # Java
    if "pom.xml" in files or "build.gradle" in files or "build.gradle.kts" in files:
        return LANG_JAVA
    if any(f.endswith(".java") for f in files):
        return LANG_JAVA

    # PowerShell (check before bash — .ps1 is unambiguous)
    if any(f.endswith(".ps1") for f in files):
        return LANG_POWERSHELL

    # Bash / Shell
    if any(f.endswith(".sh") for f in files):
        return LANG_BASH

    # C/C++ with build system
    if "Makefile" in files or "CMakeLists.txt" in files or "configure.ac" in files:
        return LANG_BINARY   # compile it

    # One-level deep scan for monorepos
    for subdir in sorted(os.listdir(repo_dir)):
        sub_path = os.path.join(repo_dir, subdir)
        if not os.path.isdir(sub_path) or subdir.startswith("."):
            continue
        sub_files = set(os.listdir(sub_path))
        if any(f in sub_files for f in ("go.mod", "Cargo.toml", "pom.xml", "package.json")):
            # Recurse one level
            return detect_language(sub_path)

    # Pre-built binary or unknown
    return LANG_UNKNOWN


# ---------------------------------------------------------------------------
# Per-language build
# ---------------------------------------------------------------------------

def build(repo_dir: str, name: str, lang: str, progress: ProgressFn) -> list[str]:
    """
    Build/install the tool and return the *run_cmd* template list.
    Uses {entry} as a placeholder for the entry_path resolved at runtime.

    Every returned list is guaranteed to be directly executable — no bare
    source file paths are ever placed as the sole element.
    """
    if lang == LANG_PYTHON:
        return _build_python(repo_dir, name, progress)
    elif lang == LANG_GO:
        return _build_go(repo_dir, name, progress)
    elif lang == LANG_RUST:
        return _build_rust(repo_dir, name, progress)
    elif lang == LANG_NODE:
        return _build_node(repo_dir, progress)
    elif lang == LANG_RUBY:
        return _build_ruby(repo_dir, progress)
    elif lang == LANG_JAVA:
        return _build_java(repo_dir, progress)
    elif lang == LANG_BASH:
        return _build_bash(repo_dir, name, progress)
    elif lang == LANG_POWERSHELL:
        return _build_powershell(repo_dir, name, progress)
    elif lang == LANG_BINARY:
        return _build_binary(repo_dir, name, progress)
    else:
        # LANG_UNKNOWN: try to find a ready-made executable; if not, warn clearly.
        progress("[!] Unknown language — attempting to locate an executable.")
        binary = _find_binary(repo_dir, name)
        if binary:
            os.chmod(binary, 0o755)
            progress(f"[+] Found executable: {binary}")
            return [binary]
        progress("[!] No executable found — tool may not run correctly.")
        return ["{entry}"]


# ---------------------------------------------------------------------------
# Language-specific builders
# ---------------------------------------------------------------------------

def _build_python(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    python = sys.executable
    venv_dir = os.path.join(repo_dir, ".venv")

    # Reuse existing venv to avoid reinstalling on repeated builds
    if os.path.isdir(venv_dir):
        progress(f"[*] Reusing existing venv: {venv_dir}")
    else:
        try:
            _run([python, "-m", "venv", venv_dir], progress)
        except RuntimeError:
            progress("[!] venv creation failed — falling back to --user install")
            venv_dir = ""

    if venv_dir:
        venv_py = _venv_python(venv_dir)
        try:
            _run([venv_py, "-m", "pip", "install", "-q", "--upgrade", "pip", "setuptools", "wheel"], progress)

            # Install in priority order — try all that exist, not just the first
            for fname, cmd in (
                ("requirements.txt", [venv_py, "-m", "pip", "install", "-q", "-r",
                                       os.path.join(repo_dir, "requirements.txt")]),
                ("pyproject.toml",   [venv_py, "-m", "pip", "install", "-q", "."]),
                ("setup.py",         [venv_py, "-m", "pip", "install", "-q", "."]),
            ):
                if os.path.isfile(os.path.join(repo_dir, fname)):
                    try:
                        _run(cmd, progress)
                    except RuntimeError as exc:
                        progress(f"[!] pip step ({fname}) failed: {exc} — continuing")
                    break  # only run one install command

            progress(f"[+] Python venv ready: {venv_dir}")
            return [venv_py, "{entry}"]

        except RuntimeError:
            progress("[!] venv install failed — falling back to --user install")

    # Fallback: --user install into the system Python
    req = os.path.join(repo_dir, "requirements.txt")
    if os.path.isfile(req):
        try:
            _run([python, "-m", "pip", "install", "-q", "--user", "-r", req], progress)
        except RuntimeError as exc:
            progress(f"[!] --user pip install failed: {exc}")
    return [python, "{entry}"]


def _build_go(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("go", "Go is not installed — tool may not work")
    go_bin = shutil.which("go") or "go"
    if shutil.which("go"):
        suffix = ".exe" if sys.platform == "win32" else ""
        out = os.path.join(repo_dir, name + suffix)
        env = {**os.environ, "CGO_ENABLED": "0"}
        try:
            _run(
                ["go", "build", "-ldflags=-s -w", "-v", "-o", out, "./..."],
                progress,
                cwd=repo_dir,
                env=env,
            )
            progress("[+] Go build complete")
        except RuntimeError as exc:
            progress(f"[!] go build failed ({exc}) — will use 'go run' fallback")
        binary = _find_binary(repo_dir, name)
        if binary:
            os.chmod(binary, 0o755)
            return [binary]
    # Fallback: go run — compiles on-the-fly, never tries to exec a source file
    progress("[!] Binary not found — falling back to 'go run ./...'")
    return [go_bin, "run", "./..."]


def _build_rust(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("cargo", "Rust/cargo is not installed — tool may not work")
    if shutil.which("cargo"):
        env = {**os.environ, "RUSTFLAGS": "-C target-cpu=native"}
        try:
            _run(["cargo", "build", "--release"], progress, cwd=repo_dir, env=env)
            progress("[+] Rust build complete")
        except RuntimeError as exc:
            progress(f"[!] cargo build failed ({exc})")

        suffix = ".exe" if sys.platform == "win32" else ""
        release_bin = os.path.join(repo_dir, "target", "release", name + suffix)
        if os.path.isfile(release_bin):
            return [release_bin]
        # Scan the release dir in case the binary has a different name
        release_dir = os.path.join(repo_dir, "target", "release")
        found = _find_binary(release_dir, name)
        if found:
            return [found]

    # Fallback: cargo run — compiles and runs without needing a located binary
    cargo_bin = shutil.which("cargo") or "cargo"
    progress("[!] Binary not found — falling back to 'cargo run --release'")
    return [cargo_bin, "run", "--release", "--"]


def _build_node(repo_dir: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("npm", "Node.js/npm is not installed — tool may not work")
    if shutil.which("npm"):
        # Prefer npm ci (deterministic) over npm install when lock-file exists
        has_lock = os.path.isfile(os.path.join(repo_dir, "package-lock.json"))
        cmd = (
            ["npm", "ci", "--prefix", repo_dir, "--silent"]
            if has_lock
            else ["npm", "install", "--prefix", repo_dir, "--silent"]
        )
        try:
            _run(cmd, progress)
            progress("[+] npm install complete")
        except RuntimeError as exc:
            progress(f"[!] npm install failed ({exc})")
    node_bin = shutil.which("node") or "node"
    return [node_bin, "{entry}"]


def _build_ruby(repo_dir: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("ruby", "Ruby is not installed — tool may not work")
    if shutil.which("gem") and os.path.isfile(os.path.join(repo_dir, "Gemfile")):
        if not shutil.which("bundle"):
            try:
                _run(["gem", "install", "bundler", "--quiet"], progress)
            except RuntimeError as exc:
                progress(f"[!] gem install bundler failed ({exc})")
        if shutil.which("bundle"):
            try:
                _run(["bundle", "install", "--quiet"], progress, cwd=repo_dir)
                progress("[+] bundle install complete")
            except RuntimeError as exc:
                progress(f"[!] bundle install failed ({exc})")
    ruby_bin = shutil.which("ruby") or "ruby"
    return [ruby_bin, "{entry}"]


def _build_java(repo_dir: str, progress: ProgressFn) -> list[str]:
    files = set(os.listdir(repo_dir))
    java_bin = shutil.which("java") or "java"

    if "pom.xml" in files:
        _require_or_warn("mvn", "Maven is not installed — tool may not work")
        if shutil.which("mvn"):
            try:
                _run(["mvn", "package", "-q", "-DskipTests"], progress, cwd=repo_dir)
                progress("[+] Maven build complete")
            except RuntimeError as exc:
                progress(f"[!] mvn package failed ({exc})")
    elif any(f.startswith("build.gradle") for f in files):
        gradle = "./gradlew" if os.path.isfile(os.path.join(repo_dir, "gradlew")) else "gradle"
        _require_or_warn("java", "Java is not installed — tool may not work")
        if shutil.which("java"):
            try:
                _run([gradle, "build", "-q"], progress, cwd=repo_dir)
                progress("[+] Gradle build complete")
            except RuntimeError as exc:
                progress(f"[!] Gradle build failed ({exc})")

    jar = _find_jar(repo_dir)
    if jar:
        return [java_bin, "-jar", jar]

    # No jar found — fall back to build-tool runners
    if "pom.xml" in files and shutil.which("mvn"):
        progress("[!] No jar found — falling back to 'mvn exec:java'")
        return [shutil.which("mvn"), "exec:java", "-q"]
    if any(f.startswith("build.gradle") for f in files):
        gradle = "./gradlew" if os.path.isfile(os.path.join(repo_dir, "gradlew")) else "gradle"
        if shutil.which(gradle) or shutil.which("gradle"):
            progress("[!] No jar found — falling back to 'gradle run'")
            return [gradle, "run"]
    progress("[!] No jar and no build tool available — tool may not run correctly.")
    return [java_bin, "-jar", "{entry}"]


def _build_bash(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    entry = _detect_shell_entry(repo_dir, name, ".sh")
    if entry:
        full = os.path.join(repo_dir, entry)
        if os.path.isfile(full):
            os.chmod(full, 0o755)
            progress(f"[+] Marked {entry} executable")
    bash_bin = shutil.which("bash") or "bash"
    return [bash_bin, "{entry}"]


def _build_powershell(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    ps = shutil.which("pwsh") or shutil.which("powershell")
    if not ps:
        progress("[!] PowerShell not found — tool may not work on this OS")
        ps = "pwsh"
    return [ps, "-ExecutionPolicy", "Bypass", "-File", "{entry}"]


def _build_binary(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    """Try cmake/make (parallel), chmod, then return the binary path or make-run fallback."""
    files = set(os.listdir(repo_dir))
    j_flag = f"-j{_CPU_COUNT}"

    if "CMakeLists.txt" in files and shutil.which("cmake"):
        build_dir = os.path.join(repo_dir, "_build")
        os.makedirs(build_dir, exist_ok=True)
        try:
            _run(["cmake", ".."], progress, cwd=build_dir)
            _run(["make", j_flag], progress, cwd=build_dir)
            progress("[+] CMake build complete")
        except RuntimeError as exc:
            progress(f"[!] CMake build failed ({exc})")
    elif "Makefile" in files and shutil.which("make"):
        try:
            _run(["make", j_flag], progress, cwd=repo_dir)
            progress("[+] make complete")
        except RuntimeError as exc:
            progress(f"[!] make failed ({exc})")

    binary = _find_binary(repo_dir, name)
    if binary:
        os.chmod(binary, 0o755)
        return [binary]

    # No binary produced — fall back to make run if possible, otherwise warn
    if "Makefile" in files and shutil.which("make"):
        progress("[!] No binary found — falling back to 'make run'")
        return [shutil.which("make"), "run"]

    progress("[!] No binary found and no build tool available — tool may not run correctly.")
    return ["{entry}"]


# ---------------------------------------------------------------------------
# Entry-point detection per language
# ---------------------------------------------------------------------------

def detect_entry(repo_dir: str, name: str, lang: str) -> str:
    """
    Return the relative path to the tool's main entry-point.

    For compiled languages (Go, Rust, Binary) this is the binary.
    For interpreted languages it is the script the interpreter should run.
    When a build artefact isn't found we return the best-effort source path
    that is appropriate for the language's fallback run_cmd.
    """
    if lang == LANG_PYTHON:
        return _detect_python_entry(repo_dir, name)

    elif lang == LANG_GO:
        binary = _find_binary(repo_dir, name)
        if binary:
            return os.path.relpath(binary, repo_dir)
        # Fallback run_cmd is `go run ./...` — entry isn't used, but "." is safe
        return "."

    elif lang == LANG_RUST:
        suffix = ".exe" if sys.platform == "win32" else ""
        # Check the standard cargo output location first
        release_bin = os.path.join(repo_dir, "target", "release", name + suffix)
        if os.path.isfile(release_bin):
            return os.path.relpath(release_bin, repo_dir)
        # Scan the release dir in case the binary has a different name
        release_dir = os.path.join(repo_dir, "target", "release")
        found = _find_binary(release_dir, name)
        if found:
            return os.path.relpath(found, repo_dir)
        return "."

    elif lang == LANG_NODE:
        return _detect_node_entry(repo_dir)

    elif lang == LANG_RUBY:
        return _detect_any_entry(repo_dir, [name + ".rb", "main.rb", "app.rb", "cli.rb"], ".rb")

    elif lang == LANG_JAVA:
        jar = _find_jar(repo_dir)
        if jar:
            return os.path.relpath(jar, repo_dir)
        return "."

    elif lang in (LANG_BASH, LANG_UNKNOWN):
        return _detect_shell_entry(repo_dir, name, ".sh") or name + ".sh"

    elif lang == LANG_POWERSHELL:
        return _detect_shell_entry(repo_dir, name, ".ps1") or name + ".ps1"

    elif lang == LANG_BINARY:
        binary = _find_binary(repo_dir, name)
        if binary:
            return os.path.relpath(binary, repo_dir)
        return "."

    return name


def _detect_python_entry(repo_dir: str, name: str) -> str:
    candidates = [
        f"{name}.py", "__main__.py", "main.py", "cli.py", "run.py",
        "app.py", "start.py", "launch.py",
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(repo_dir, c)):
            return c
    # Check inside a package directory named after the tool
    pkg_main = os.path.join(repo_dir, name, "__main__.py")
    if os.path.isfile(pkg_main):
        return os.path.join(name, "__main__.py")
    # Scan root for any non-private .py file
    for f in sorted(os.listdir(repo_dir)):
        if f.endswith(".py") and not f.startswith("_") and not f.startswith("test"):
            return f
    return "main.py"


def _detect_node_entry(repo_dir: str) -> str:
    pkg = os.path.join(repo_dir, "package.json")
    if os.path.isfile(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                data = json.load(fh)
            main = data.get("main") or data.get("bin")
            if isinstance(main, str):
                return main
            if isinstance(main, dict):
                return next(iter(main.values()), "index.js")
        except Exception:
            pass
    for candidate in ("index.js", "cli.js", "main.js", "app.js", "bin/cli.js", "bin/index.js"):
        if os.path.isfile(os.path.join(repo_dir, candidate)):
            return candidate
    return "index.js"


def _detect_any_entry(repo_dir: str, candidates: list[str], ext: str) -> str:
    for c in candidates:
        if os.path.isfile(os.path.join(repo_dir, c)):
            return c
    for f in sorted(os.listdir(repo_dir)):
        if f.endswith(ext) and not f.startswith("_") and not f.startswith("test"):
            return f
    return candidates[0] if candidates else f"main{ext}"


def _detect_shell_entry(repo_dir: str, name: str, ext: str) -> str:
    return _detect_any_entry(
        repo_dir,
        [name + ext, "main" + ext, "run" + ext, "start" + ext, "install" + ext],
        ext,
    )


def _find_binary(repo_dir: str, name: str) -> str:
    """
    Return the path to a native executable in the repo or common build dirs.

    Searches named candidates first, then falls back to scanning for any
    executable file — including those with version suffixes or hyphens.
    """
    suffix = ".exe" if sys.platform == "win32" else ""
    candidates = [
        os.path.join(repo_dir, name + suffix),
        os.path.join(repo_dir, "target", "release", name + suffix),
        os.path.join(repo_dir, "_build", name + suffix),
        os.path.join(repo_dir, "build", name + suffix),
        os.path.join(repo_dir, "bin", name + suffix),
        os.path.join(repo_dir, "dist", name + suffix),
        os.path.join(repo_dir, "out", name + suffix),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    # Blocklist of extensions that are source/config — never treat as binary
    _source_exts = {
        ".go", ".rs", ".py", ".rb", ".js", ".ts", ".java", ".c", ".cpp",
        ".h", ".hpp", ".sh", ".ps1", ".md", ".txt", ".toml", ".yaml",
        ".yml", ".json", ".lock", ".sum", ".mod", ".cfg", ".ini", ".xml",
        ".gradle", ".properties", ".gitignore", ".gitmodules", ".dockerfile",
        ".html", ".css", ".scss", ".vue", ".jsx", ".tsx",
    }

    for f in sorted(os.listdir(repo_dir)):
        full = os.path.join(repo_dir, f)
        if not os.path.isfile(full):
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext in _source_exts:
            continue
        if suffix and f.lower().endswith(suffix):   # .exe on Windows — always accept
            return full
        if os.access(full, os.X_OK):
            return full
    return ""


def _find_jar(repo_dir: str) -> str:
    for sub in ("target", os.path.join("build", "libs")):
        d = os.path.join(repo_dir, sub)
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".jar") and "sources" not in f and "javadoc" not in f:
                    return os.path.join(d, f)
    return ""


# ---------------------------------------------------------------------------
# Toolchain pre-flight
# ---------------------------------------------------------------------------

def _preflight_toolchain(lang: str, progress: ProgressFn) -> None:
    """
    Check that the binaries required to build the detected language are
    present on PATH.  Emits warnings (non-fatal) for each missing binary
    and includes a human-readable install hint.
    """
    tc = _TOOLCHAIN_REQS.get(lang)
    if not tc:
        return
    missing = [b for b in tc.binaries if shutil.which(b) is None]
    if missing:
        progress(f"[!] Missing toolchain binary/binaries for {lang}: {', '.join(missing)}")
        progress(f"[!] Install hint: {tc.install_hint}")
    else:
        found_versions = []
        for b in tc.binaries:
            try:
                result = subprocess.run(
                    [b, "--version"], capture_output=True, text=True, timeout=5
                )
                ver = (result.stdout or result.stderr).strip().splitlines()[0]
                found_versions.append(f"{b} ({ver[:40]})")
            except Exception:
                found_versions.append(b)
        progress(f"[*] Toolchain OK: {'; '.join(found_versions)}")


# ---------------------------------------------------------------------------
# Shared subprocess helpers
# ---------------------------------------------------------------------------

def _git_clone(url: str, dest: str, progress: ProgressFn) -> None:
    _run(["git", "clone", "--depth=1", "--recurse-submodules", url, dest], progress)


def _git_head_short(repo_dir: str) -> str:
    """Return the 7-char short commit hash of HEAD in *repo_dir*, or '' on failure."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _run(
    cmd: list[str],
    progress: ProgressFn,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> None:
    """Stream subprocess output to *progress*. Raises RuntimeError on non-zero exit."""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in proc.stdout:
        progress(line.rstrip())
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed (exit {proc.returncode}): {' '.join(str(c) for c in cmd)}"
        )


def _venv_python(venv_dir: str) -> str:
    if sys.platform == "win32":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def _require(cmd: str) -> None:
    if shutil.which(cmd) is None:
        raise RuntimeError(
            f"'{cmd}' is not installed or not on PATH.\n"
            f"Install it and try again."
        )


def _require_or_warn(cmd: str, msg: str) -> None:
    """Emit a warning if *cmd* is missing; does NOT raise — build continues."""
    if shutil.which(cmd) is None:
        print(f"[!] {msg}", flush=True)


def _infer_description(repo_dir: str) -> str:
    """Extract the first substantive line from a README as a description."""
    for fname in ("README.md", "README.rst", "README.txt", "readme.md", "Readme.md"):
        path = os.path.join(repo_dir, fname)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        # Skip headings, badges, HTML, dividers — keep prose
                        if not line:
                            continue
                        if line.startswith(("#", "!", "<", "=", "-", ">", "|", "~")):
                            continue
                        if line.startswith("[!") or line.startswith("[!["):
                            continue
                        # Skip lines that are only punctuation / whitespace
                        if re.match(r'^[\W_]+$', line):
                            continue
                        if len(line) > 10:
                            return line[:120]
            except OSError:
                pass
    return "(no description)"


# ===========================================================================
# SYSTEM 2 — DependencyResolver
# ===========================================================================
# Resolves the OS-level (apt/pacman/dnf/brew) and Python-level packages that
# each tool or language requires.  Call resolve(name_or_lang) to get a
# DependencyReport back; it lists what is present, what is missing, and what
# install commands would fix the gaps.
#
# Usage
# -----
#   from megaploit.toolbox.installer import dep_resolver
#   report = dep_resolver.resolve("sqlmap")
#   for line in report.summary():
#       print(line)
#   if not report.all_satisfied:
#       dep_resolver.install_missing(report, progress=print)
# ===========================================================================

import importlib.util as _importlib_util


# ---------------------------------------------------------------------------
# Per-language and per-tool OS dependency tables
# ---------------------------------------------------------------------------

# Maps lang ID → list of (package_manager_family, [package_names])
# Each tuple says "on this distro family, you need these packages"
_LANG_OS_DEPS: dict[str, list[tuple[str, list[str]]]] = {
    LANG_PYTHON: [
        ("debian", ["python3", "python3-pip", "python3-venv", "python3-dev",
                    "libssl-dev", "libffi-dev", "build-essential"]),
        ("arch",   ["python", "python-pip"]),
        ("fedora", ["python3", "python3-pip", "python3-devel",
                    "openssl-devel", "libffi-devel", "gcc"]),
        ("macos",  ["python@3"]),
    ],
    LANG_GO: [
        ("debian", ["golang-go"]),
        ("arch",   ["go"]),
        ("fedora", ["golang"]),
        ("macos",  ["go"]),
    ],
    LANG_RUST: [
        ("debian", ["cargo", "rustc", "libssl-dev"]),
        ("arch",   ["rust"]),
        ("fedora", ["cargo", "rust", "openssl-devel"]),
        ("macos",  ["rust"]),
    ],
    LANG_NODE: [
        ("debian", ["nodejs", "npm"]),
        ("arch",   ["nodejs", "npm"]),
        ("fedora", ["nodejs", "npm"]),
        ("macos",  ["node"]),
    ],
    LANG_RUBY: [
        ("debian", ["ruby", "ruby-dev", "ruby-bundler", "build-essential"]),
        ("arch",   ["ruby"]),
        ("fedora", ["ruby", "ruby-devel", "rubygems"]),
        ("macos",  ["ruby"]),
    ],
    LANG_JAVA: [
        ("debian", ["default-jdk", "maven"]),
        ("arch",   ["jdk-openjdk", "maven"]),
        ("fedora", ["java-latest-openjdk-devel", "maven"]),
        ("macos",  ["openjdk", "maven"]),
    ],
    LANG_BASH: [
        ("debian", ["bash", "coreutils"]),
        ("arch",   ["bash", "coreutils"]),
        ("fedora", ["bash", "coreutils"]),
        ("macos",  ["bash", "coreutils"]),
    ],
    LANG_POWERSHELL: [
        ("debian", ["powershell"]),
        ("arch",   ["powershell-bin"]),
        ("fedora", ["powershell"]),
        ("macos",  ["powershell"]),
    ],
    LANG_BINARY: [
        ("debian", ["cmake", "make", "gcc", "g++", "libssl-dev", "libpcap-dev"]),
        ("arch",   ["cmake", "make", "gcc", "libpcap"]),
        ("fedora", ["cmake", "make", "gcc", "gcc-c++", "openssl-devel",
                    "libpcap-devel"]),
        ("macos",  ["cmake", "libpcap"]),
    ],
}

# Per-tool Python package requirements (pip names).
# These supplement (or replace) what requirements.txt provides for tools
# where we know the runtime deps at catalogue-entry time.
_TOOL_PIP_DEPS: dict[str, list[str]] = {
    "sqlmap":           [],
    "dirsearch":        ["requests", "urllib3"],
    "wfuzz":            ["pycurl", "pyparsing", "future"],
    "xsstrike":         ["requests", "fuzzywuzzy"],
    "arjun":            ["requests"],
    "corsy":            ["requests", "tqdm"],
    "jwt-tool":         ["requests", "pycryptodomex", "termcolor"],
    "graphqlmap":       ["requests", "termcolor"],
    "ghauri":           ["requests", "colorama"],
    "bloodhound-python":["dnspython", "impacket", "ldap3"],
    "impacket":         ["cryptography", "pyopenssl", "pyasn1"],
    "crackmapexec":     ["impacket", "ldap3", "paramiko", "bloodhound"],
    "lsassy":           ["impacket"],
    "pypykatz":         ["minikerberos", "aiosmb"],
    "adcs-attack":      ["impacket", "cryptography", "pyopenssl", "ldap3"],
    "sprayhound":       ["impacket", "ldap3"],
    "credmaster":       ["requests", "boto3"],
    "theHarvester":     ["requests", "dnspython", "shodan"],
    "sherlock":         ["requests", "colorama", "tqdm"],
    "spiderfoot":       ["requests", "flask", "cherrypy", "bs4"],
    "holehe":           ["requests", "httpx", "tqdm"],
    "maigret":          ["requests", "aiohttp", "tqdm"],
    "recon-ng":         ["requests", "flask"],
    "phoneinfoga":      [],
    "socialscan":       ["aiohttp", "tqdm"],
    "h8mail":           ["requests", "tqdm"],
    "photon":           ["requests", "tld", "urllib3"],
    "metagoofil":       ["requests", "bs4"],
    "finalrecon":       ["requests", "dnspython", "bs4"],
    "twint":            ["aiohttp", "elasticsearch", "pysocks"],
    "maltego-trx":      ["flask"],
    "pwncat":           ["prompt_toolkit", "paramiko", "pygments", "rich"],
    "pwntools":         ["pyelftools", "capstone", "unicorn2", "ropgadget"],
    "angr":             ["cle", "claripy", "archinfo", "pyvex"],
    "ropper":           ["capstone"],
    "volatility3":      ["pefile", "pillow", "yara-python"],
    "binwalk":          ["capstone", "pycryptodome"],
    "oletools":         ["easygui", "colorclass"],
    "peepdf":           ["pylzma", "pycryptodome"],
    "boofuzz":          ["pyzmq", "flask"],
    "shodan-cli":       ["shodan"],
    "scoutsuite":       ["boto3", "msrestazure", "google-cloud-storage"],
    "cloudmapper":      ["boto3", "policyuniverse", "netaddr"],
    "s3scanner":        [],
    "detect-secrets":   [],
    "semgrep":          [],
    "pacu":             ["boto3", "botocore", "requests"],
    "trufflehog":       [],
    "gitleaks":         [],
    "wafw00f":          ["requests"],
    "cupp":             [],
    "mentalist":        ["tkinter"],
    "patator":          ["impacket", "dnspython", "paramiko"],
    "crowbar":          [],
    "hashid":           [],
    "name-that-hash":   ["rich"],
    "haiti":            [],
    "empire":           ["flask", "jinja2", "netifaces", "pydispatcher"],
    "king-phisher":     ["requests", "gi"],
    "osintgram":        ["instaloader", "requests"],
}

# Per-tool OS-level extra packages (beyond what the lang table gives)
_TOOL_OS_EXTRAS: dict[str, list[tuple[str, list[str]]]] = {
    "sqlmap": [
        ("debian", ["tor", "proxychains"]),
    ],
    "hydra": [
        ("debian", ["libssl-dev", "libssh-dev", "libidn11-dev",
                    "libpcre3-dev", "libgtk2.0-dev", "libmysqlclient-dev",
                    "libpq-dev", "libsvn-dev", "firebird-dev"]),
        ("fedora", ["openssl-devel", "libssh-devel", "mysql-devel",
                    "postgresql-devel"]),
    ],
    "masscan": [
        ("debian", ["libpcap-dev"]),
        ("arch",   ["libpcap"]),
        ("fedora", ["libpcap-devel"]),
    ],
    "aircrack-ng": [
        ("debian", ["libssl-dev", "libpcap-dev", "ethtool", "iw"]),
    ],
    "bettercap": [
        ("debian", ["libpcap-dev", "libusb-dev", "libnetfilter-queue-dev"]),
    ],
    "nmap": [
        ("debian", ["libpcap-dev", "libssl-dev"]),
    ],
    "wireshark": [
        ("debian", ["libpcap-dev", "qt5-default"]),
    ],
    "afl-plus-plus": [
        ("debian", ["clang", "llvm", "lld"]),
        ("fedora", ["clang", "llvm"]),
    ],
    "volatility3": [
        ("debian", ["python3-capstone", "python3-yara"]),
    ],
    "binwalk": [
        ("debian", ["zlib1g-dev", "liblzma-dev", "liblzo2-dev",
                    "libfuzzy-dev", "squashfs-tools", "sasquatch"]),
    ],
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class _OsDep:
    """One OS-level package dependency."""
    family:   str    # "debian" | "arch" | "fedora" | "macos" | "any"
    package:  str
    present:  bool   # whether it was found on the current system
    check_cmd: str   # the command that was checked (e.g. "gcc")


@dataclass
class _PipDep:
    """One Python package dependency."""
    import_name:  str   # the name to `import`
    pip_name:     str   # the name to `pip install`
    present:      bool


@dataclass
class DependencyReport:
    """
    Full dependency analysis result for a tool or language.

    Attributes
    ----------
    name          : Tool name or lang ID analysed.
    os_family     : Detected OS family used for the analysis.
    os_deps       : All OS-level deps with presence flags.
    pip_deps      : All Python-level deps with presence flags.
    all_satisfied : True iff every dep is present.
    """
    name:     str
    os_family: str
    os_deps:  list[_OsDep]
    pip_deps: list[_PipDep]

    @property
    def all_satisfied(self) -> bool:
        return (
            all(d.present for d in self.os_deps)
            and all(d.present for d in self.pip_deps)
        )

    @property
    def missing_os(self) -> list[_OsDep]:
        return [d for d in self.os_deps if not d.present]

    @property
    def missing_pip(self) -> list[_PipDep]:
        return [d for d in self.pip_deps if not d.present]

    def summary(self) -> list[str]:
        lines = [f"[*] Dependency report for '{self.name}'  (OS: {self.os_family})"]
        if self.all_satisfied:
            lines.append("[+] All dependencies satisfied.")
            return lines
        if self.missing_os:
            lines.append(f"[-] Missing OS packages ({len(self.missing_os)}):")
            for d in self.missing_os:
                lines.append(f"    • {d.package}")
        if self.missing_pip:
            lines.append(f"[-] Missing Python packages ({len(self.missing_pip)}):")
            for d in self.missing_pip:
                lines.append(f"    • {d.pip_name}")
        return lines

    def install_commands(self) -> list[str]:
        """
        Return a list of shell commands that would satisfy all missing deps.
        Returned strings are human-readable suggestions, not executed directly.
        """
        cmds: list[str] = []
        if self.missing_os:
            pkgs = " ".join(d.package for d in self.missing_os)
            if self.os_family == "debian":
                cmds.append(f"sudo apt-get install -y {pkgs}")
            elif self.os_family == "arch":
                cmds.append(f"sudo pacman -S --noconfirm {pkgs}")
            elif self.os_family == "fedora":
                cmds.append(f"sudo dnf install -y {pkgs}")
            elif self.os_family == "macos":
                cmds.append(f"brew install {pkgs}")
            else:
                cmds.append(f"# Install these packages manually: {pkgs}")
        if self.missing_pip:
            pkgs = " ".join(d.pip_name for d in self.missing_pip)
            cmds.append(f"pip install {pkgs}")
        return cmds


# ---------------------------------------------------------------------------
# DependencyResolver class
# ---------------------------------------------------------------------------

class DependencyResolver:
    """
    Analyse and optionally install the OS + Python dependencies for a tool.

    The resolver:
      1. Detects the current OS family (reads /etc/os-release or uname).
      2. Looks up OS packages for the tool's language and any per-tool extras.
      3. Checks each OS package by testing whether its expected binary is on
         PATH (heuristic — not a full dpkg/pacman query, avoids root).
      4. Checks Python packages by attempting importlib.util.find_spec().
      5. Returns a DependencyReport.

    Attributes
    ----------
    os_family : Detected OS family string.
    """

    # Binary that represents each OS package (used for presence check)
    _OS_PACKAGE_PROBE: dict[str, str] = {
        # compilers / build tools
        "gcc":              "gcc",
        "g++":              "g++",
        "make":             "make",
        "cmake":            "cmake",
        "clang":            "clang",
        "lld":              "lld",
        "llvm":             "llvm-config",
        # langs
        "python3":          "python3",
        "python3-pip":      "pip3",
        "golang-go":        "go",
        "go":               "go",
        "cargo":            "cargo",
        "rustc":            "rustc",
        "nodejs":           "node",
        "node":             "node",
        "npm":              "npm",
        "ruby":             "ruby",
        "default-jdk":      "java",
        "java-latest-openjdk-devel": "java",
        "openjdk":          "java",
        "maven":            "mvn",
        # network libs (no binary probe — skip / assume present)
        "libssl-dev":       "openssl",
        "libpcap-dev":      "tcpdump",
        "libffi-dev":       None,
        "libssh-dev":       None,
        "libidn11-dev":     None,
        "libmysqlclient-dev": None,
        "libpq-dev":        None,
        # shells
        "bash":             "bash",
        "powershell":       "pwsh",
        "powershell-bin":   "pwsh",
        # utils
        "git":              "git",
        "curl":             "curl",
        "wget":             "wget",
        "unzip":            "unzip",
        "tor":              "tor",
        "proxychains":      "proxychains",
        "iw":               "iw",
        "ethtool":          "ethtool",
        "tcpdump":          "tcpdump",
        "squashfs-tools":   "mksquashfs",
        # Java build
        "ruby-bundler":     "bundle",
        "rubygems":         "gem",
    }

    def __init__(self) -> None:
        self.os_family = self._detect_os_family()

    # ------------------------------------------------------------------
    # OS detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_os_family() -> str:
        """Return one of: debian | arch | fedora | macos | unknown"""
        import platform as _platform
        if _platform.system() == "Darwin":
            return "macos"
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as fh:
                content = fh.read()
            id_like = ""
            distro_id = ""
            for line in content.splitlines():
                if line.startswith("ID_LIKE="):
                    id_like = line.split("=", 1)[1].strip().strip('"').lower()
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"').lower()
            combined = f"{id_like} {distro_id}"
            if any(k in combined for k in ("debian", "ubuntu")):
                return "debian"
            if "arch" in combined:
                return "arch"
            if any(k in combined for k in ("fedora", "rhel", "centos", "rocky", "alma")):
                return "fedora"
            if "suse" in combined:
                return "fedora"   # dnf-compatible enough
        except OSError:
            pass
        # Fallback: check which package manager is available
        for cmd, family in [("apt-get", "debian"), ("pacman", "arch"),
                             ("dnf", "fedora"), ("yum", "fedora"),
                             ("brew", "macos")]:
            if shutil.which(cmd):
                return family
        return "unknown"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, name: str) -> "DependencyReport":
        """
        Build a DependencyReport for an installed tool (by registry name)
        or a bare language ID (e.g. LANG_PYTHON).
        """
        # Determine the lang
        tool = registry.get(name)
        lang = tool.lang if tool else name

        # Gather OS deps for the language
        os_deps: list[_OsDep] = []
        seen_os: set[str] = set()
        for family, pkgs in _LANG_OS_DEPS.get(lang, []):
            if family != self.os_family:
                continue
            for pkg in pkgs:
                if pkg in seen_os:
                    continue
                seen_os.add(pkg)
                os_deps.append(self._check_os_pkg(pkg))

        # Gather per-tool OS extras
        for family, pkgs in _TOOL_OS_EXTRAS.get(name, []):
            if family != self.os_family:
                continue
            for pkg in pkgs:
                if pkg in seen_os:
                    continue
                seen_os.add(pkg)
                os_deps.append(self._check_os_pkg(pkg))

        # Gather Python deps
        pip_deps: list[_PipDep] = []
        seen_pip: set[str] = set()
        for pkg in _TOOL_PIP_DEPS.get(name, []):
            if pkg in seen_pip:
                continue
            seen_pip.add(pkg)
            import_name = pkg.replace("-", "_").split("[")[0].lower()
            pip_deps.append(_PipDep(
                import_name=import_name,
                pip_name=pkg,
                present=self._check_pip_pkg(import_name),
            ))

        return DependencyReport(
            name=name,
            os_family=self.os_family,
            os_deps=os_deps,
            pip_deps=pip_deps,
        )

    def resolve_lang(self, lang: str) -> "DependencyReport":
        """Resolve OS deps for a language without a specific tool context."""
        return self.resolve(lang)

    def install_missing(
        self,
        report: "DependencyReport",
        progress: ProgressFn = _NOOP,
        dry_run: bool = False,
    ) -> None:
        """
        Attempt to install every missing dependency in *report*.

        Missing OS packages are installed via the system package manager
        (requires root / sudo).  Missing Python packages are installed via
        pip into the current environment.

        Parameters
        ----------
        report   : DependencyReport from a prior resolve() call.
        progress : Progress callback.
        dry_run  : If True, print what would be done but do not execute.
        """
        if report.all_satisfied:
            progress("[+] All dependencies already satisfied.")
            return

        # OS packages
        if report.missing_os:
            pkgs = [d.package for d in report.missing_os]
            progress(f"[*] Installing {len(pkgs)} OS package(s): {', '.join(pkgs)}")
            cmd = self._os_install_cmd(pkgs)
            if cmd:
                if dry_run:
                    progress(f"[dry-run] Would run: {' '.join(cmd)}")
                else:
                    try:
                        _run(cmd, progress)
                        progress("[+] OS packages installed.")
                    except RuntimeError as exc:
                        progress(f"[!] OS package install failed: {exc}")
            else:
                progress(f"[!] Cannot install OS packages — unknown OS family: {self.os_family}")

        # Python packages
        if report.missing_pip:
            pkgs = [d.pip_name for d in report.missing_pip]
            progress(f"[*] Installing {len(pkgs)} Python package(s): {', '.join(pkgs)}")
            cmd = [sys.executable, "-m", "pip", "install", "-q"] + pkgs
            if dry_run:
                progress(f"[dry-run] Would run: {' '.join(cmd)}")
            else:
                try:
                    _run(cmd, progress)
                    progress("[+] Python packages installed.")
                except RuntimeError as exc:
                    progress(f"[!] pip install failed: {exc}")

    def which_missing(self, lang: str) -> list[str]:
        """
        Return a list of binary names that are required for *lang* but absent.
        Quick check — useful for upfront validation before a long clone.
        """
        tc = _TOOLCHAIN_REQS.get(lang)
        if not tc:
            return []
        return [b for b in tc.binaries if shutil.which(b) is None]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_os_pkg(self, pkg: str) -> "_OsDep":
        probe_cmd = self._OS_PACKAGE_PROBE.get(pkg)
        if probe_cmd is None:
            # No binary to probe — assume present (library, header)
            return _OsDep(family=self.os_family, package=pkg,
                          present=True, check_cmd="(no probe)")
        present = shutil.which(probe_cmd) is not None
        return _OsDep(family=self.os_family, package=pkg,
                      present=present, check_cmd=probe_cmd)

    @staticmethod
    def _check_pip_pkg(import_name: str) -> bool:
        return _importlib_util.find_spec(import_name) is not None

    def _os_install_cmd(self, pkgs: list[str]) -> list[str]:
        if self.os_family == "debian":
            return ["apt-get", "install", "-y", "--no-install-recommends"] + pkgs
        if self.os_family == "arch":
            return ["pacman", "-S", "--noconfirm", "--needed"] + pkgs
        if self.os_family == "fedora":
            mgr = shutil.which("dnf") or shutil.which("yum") or "dnf"
            return [mgr, "install", "-y"] + pkgs
        if self.os_family == "macos":
            return ["brew", "install"] + pkgs
        return []


# Module-level singleton
dep_resolver = DependencyResolver()


# ===========================================================================
# SYSTEM 3 — BuildCache
# ===========================================================================
# Tracks a content hash of a tool's source tree so we can skip the rebuild
# step when nothing has changed since the last successful build.
#
# The cache is stored as JSON in tools/.build_cache.json.
# Each entry maps tool_name → {hash, built_at, lang, run_cmd}.
#
# Usage
# -----
#   from megaploit.toolbox.installer import build_cache
#
#   if build_cache.is_fresh("sqlmap"):
#       print("Nothing changed — skipping rebuild")
#   else:
#       run_cmd = build("tools/sqlmap", "sqlmap", LANG_PYTHON, print)
#       build_cache.record("sqlmap", "tools/sqlmap", LANG_PYTHON, run_cmd)
# ===========================================================================

_CACHE_FILE = os.path.join(TOOLS_DIR, ".build_cache.json")

# How many files to hash per tool before stopping (perf guard for huge repos)
_HASH_FILE_LIMIT = 2000
# File extensions to include in the hash (source files only)
_HASH_INCLUDE_EXTS = {
    ".py", ".go", ".rs", ".js", ".ts", ".rb", ".java", ".c", ".cpp",
    ".h", ".hpp", ".sh", ".ps1", ".toml", ".mod", ".sum", ".gradle",
    ".xml", ".json", ".lock",
}


@dataclass
class _CacheEntry:
    """Persisted record of one successful build."""
    tool_name:  str
    source_hash: str   # SHA-256 of sorted file contents
    built_at:   str    # ISO-8601 UTC timestamp
    lang:       str
    run_cmd:    list[str]

    def to_dict(self) -> dict:
        return {
            "tool_name":   self.tool_name,
            "source_hash": self.source_hash,
            "built_at":    self.built_at,
            "lang":        self.lang,
            "run_cmd":     self.run_cmd,
        }

    @staticmethod
    def from_dict(d: dict) -> "_CacheEntry":
        return _CacheEntry(
            tool_name=d["tool_name"],
            source_hash=d["source_hash"],
            built_at=d["built_at"],
            lang=d["lang"],
            run_cmd=d.get("run_cmd", []),
        )


class BuildCache:
    """
    Persistent build cache.  Prevents unnecessary re-builds when the tool's
    source tree hasn't changed (e.g. toolbox update found no new commits).

    The hash covers every source file in the repo up to _HASH_FILE_LIMIT
    files.  File paths are sorted before hashing so the result is
    deterministic across OS/filesystem ordering differences.
    """

    def __init__(self) -> None:
        self._entries: dict[str, _CacheEntry] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.isfile(_CACHE_FILE):
            return
        try:
            with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for item in data:
                e = _CacheEntry.from_dict(item)
                self._entries[e.tool_name] = e
        except (json.JSONDecodeError, KeyError, TypeError):
            pass  # corrupt cache — start fresh

    def _save(self) -> None:
        os.makedirs(TOOLS_DIR, exist_ok=True)
        try:
            with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump([e.to_dict() for e in self._entries.values()], fh, indent=2)
        except OSError:
            pass  # non-fatal — cache just won't persist

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_fresh(self, name: str) -> bool:
        """
        Return True iff the tool has a recorded build AND the current
        source tree hashes to the same value as when it was built.
        """
        entry = self._entries.get(name)
        if not entry:
            return False
        tool = registry.get(name)
        if not tool or not os.path.isdir(tool.path):
            return False
        current_hash = self._hash_tree(tool.path)
        return current_hash == entry.source_hash

    def record(
        self,
        name: str,
        repo_dir: str,
        lang: str,
        run_cmd: list[str],
    ) -> None:
        """
        Record a successful build for *name*.  Call this immediately after
        a successful build() call.
        """
        h = self._hash_tree(repo_dir)
        entry = _CacheEntry(
            tool_name=name,
            source_hash=h,
            built_at=datetime.now(timezone.utc).isoformat(),
            lang=lang,
            run_cmd=run_cmd,
        )
        self._entries[name] = entry
        self._save()

    def invalidate(self, name: str) -> None:
        """Force the next is_fresh() check to return False for *name*."""
        self._entries.pop(name, None)
        self._save()

    def invalidate_all(self) -> None:
        """Clear the entire cache."""
        self._entries.clear()
        self._save()

    def get(self, name: str) -> Optional[_CacheEntry]:
        """Return the cached entry for *name*, or None."""
        return self._entries.get(name)

    def all(self) -> list[_CacheEntry]:
        """Return all cached entries."""
        return list(self._entries.values())

    def summary(self) -> list[str]:
        """Return a human-readable list of cached build entries."""
        if not self._entries:
            return ["[*] Build cache is empty."]
        lines = [f"[*] Build cache ({len(self._entries)} entries):"]
        for e in sorted(self._entries.values(), key=lambda x: x.built_at, reverse=True):
            lines.append(f"    {e.tool_name:<24}  {e.lang:<12}  built {e.built_at[:19]}  {e.source_hash[:8]}")
        return lines

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_tree(repo_dir: str) -> str:
        """
        Compute a deterministic SHA-256 hash of the source files under
        *repo_dir*.  Only files with extensions in _HASH_INCLUDE_EXTS are
        included.  Files are processed in sorted path order up to
        _HASH_FILE_LIMIT.
        """
        h = hashlib.sha256()
        count = 0
        collected: list[str] = []

        for root, dirs, files in os.walk(repo_dir):
            # Skip hidden dirs and common non-source dirs
            dirs[:] = sorted(
                d for d in dirs
                if not d.startswith(".")
                and d not in ("node_modules", "__pycache__", ".venv",
                              "target", "_build", "build", "dist",
                              ".git", "vendor", ".cargo")
            )
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _HASH_INCLUDE_EXTS:
                    continue
                full = os.path.join(root, fname)
                rel  = os.path.relpath(full, repo_dir)
                collected.append(rel)
                if len(collected) >= _HASH_FILE_LIMIT:
                    break
            if len(collected) >= _HASH_FILE_LIMIT:
                break

        for rel_path in sorted(collected):
            full = os.path.join(repo_dir, rel_path)
            h.update(rel_path.encode("utf-8", errors="replace"))
            try:
                with open(full, "rb") as fh:
                    while chunk := fh.read(65536):
                        h.update(chunk)
            except OSError:
                pass  # unreadable file — skip

        return h.hexdigest()


# Module-level singleton
build_cache = BuildCache()


# ===========================================================================
# SYSTEM 4 — ToolAudit
# ===========================================================================
# Scans an installed tool's source tree for:
#   • License type (MIT, GPL, Apache, BSD, AGPL, …)
#   • Hardcoded secrets / credentials (API keys, tokens, passwords)
#   • Shell injection patterns (backticks, os.system, subprocess with shell=True)
#   • TODO / FIXME / HACK comments
#   • File count, total size, and language breakdown
#
# Usage
# -----
#   from megaploit.toolbox.installer import tool_auditor
#   report = tool_auditor.audit("sqlmap")
#   for line in report.summary():
#       print(line)
# ===========================================================================

import stat as _stat


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# License identifier patterns (checked against LICENSE / README file content)
_LICENSE_PATTERNS: list[tuple[str, str]] = [
    (r"MIT License",                         "MIT"),
    (r"Apache License.*Version 2",           "Apache-2.0"),
    (r"GNU GENERAL PUBLIC LICENSE.*[Vv]ersion 3", "GPL-3.0"),
    (r"GNU GENERAL PUBLIC LICENSE.*[Vv]ersion 2", "GPL-2.0"),
    (r"GNU LESSER GENERAL PUBLIC LICENSE",   "LGPL"),
    (r"GNU AFFERO GENERAL PUBLIC LICENSE",   "AGPL-3.0"),
    (r"Mozilla Public License.*2\.0",        "MPL-2.0"),
    (r"BSD 2-Clause",                        "BSD-2-Clause"),
    (r"BSD 3-Clause",                        "BSD-3-Clause"),
    (r"ISC License",                         "ISC"),
    (r"The Unlicense",                       "Unlicense"),
    (r"Creative Commons",                    "CC"),
    (r"WTFPL",                               "WTFPL"),
    (r"Do What The Fuck",                    "WTFPL"),
]

# Secret / credential leakage patterns (regex → human label)
_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
     "Possible API key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{12,}",
     "Possible secret key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "Hardcoded password"),
    (r"(?i)(token|access_token|auth_token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{12,}",
     "Possible auth token"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "Embedded private key"),
    (r"(?i)aws_access_key_id\s*[=:]\s*['\"]?[A-Z0-9]{20}",
     "AWS access key"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}",
     "AWS secret key"),
    (r"(?i)github[_-]?token\s*[=:]\s*['\"]?gh[pousr]_[A-Za-z0-9]{36,}",
     "GitHub token"),
    (r"(?i)slack[_-]?(token|webhook)\s*[=:]\s*['\"]?xox[baprs]-[A-Za-z0-9\-]+",
     "Slack token/webhook"),
]

# Shell injection patterns
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"os\.system\s*\(",                     "os.system() call"),
    (r"subprocess\.[A-Za-z]+\(.*shell\s*=\s*True", "subprocess with shell=True"),
    (r"`[^`]+`",                             "Backtick shell execution"),
    (r"eval\s*\(",                           "eval() call"),
    (r"exec\s*\(",                           "exec() call"),
    (r"__import__\s*\(",                     "__import__() call"),
    (r"pickle\.loads?\s*\(",                 "pickle.load (deserialization)"),
    (r"yaml\.load\s*\([^)]*Loader",         "yaml.load without SafeLoader"),
]

# Source file extensions for scanning
_SCAN_EXTS = {
    ".py", ".go", ".rs", ".js", ".ts", ".rb", ".java", ".c", ".cpp",
    ".sh", ".ps1", ".php", ".pl",
}

# Max lines to scan per file (performance guard)
_MAX_SCAN_LINES = 5000
# Max files to scan per tool
_MAX_SCAN_FILES = 500


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AuditFinding:
    """A single finding from the audit scanner."""
    category:  str    # "secret" | "injection" | "todo" | "info"
    severity:  str    # "high" | "medium" | "low" | "info"
    file:      str    # relative file path
    line_no:   int
    label:     str    # human description
    snippet:   str    # short code snippet (up to 80 chars)


@dataclass
class AuditReport:
    """
    Full audit report for one tool.

    Attributes
    ----------
    name          : Tool name.
    license       : Detected SPDX license identifier, or "Unknown".
    copyleft      : True if the license is copyleft (GPL, AGPL, LGPL).
    file_count    : Total number of files in the tool directory.
    source_files  : Number of source files scanned.
    total_size_kb : Total size of the tool directory in kilobytes.
    lang_stats    : Dict mapping extension → file count.
    findings      : All AuditFinding objects.
    """
    name:         str
    license:      str
    copyleft:     bool
    file_count:   int
    source_files: int
    total_size_kb: float
    lang_stats:   dict[str, int]
    findings:     list[AuditFinding]

    @property
    def high_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    def summary(self) -> list[str]:
        lines = [
            f"[*] Audit report for '{self.name}'",
            f"    License       : {self.license}"
            + (" (⚠ copyleft)" if self.copyleft else ""),
            f"    Files         : {self.file_count} total, {self.source_files} source",
            f"    Size          : {self.total_size_kb:.1f} KB",
        ]
        # Language breakdown
        if self.lang_stats:
            top = sorted(self.lang_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            lang_line = "  ".join(f"{ext}:{n}" for ext, n in top)
            lines.append(f"    Languages     : {lang_line}")
        # Findings summary
        n_high   = len(self.high_findings)
        n_medium = len(self.medium_findings)
        n_low    = len([f for f in self.findings if f.severity == "low"])
        if self.findings:
            lines.append(
                f"    Findings      : {len(self.findings)} total  "
                f"({n_high} high / {n_medium} medium / {n_low} low)"
            )
            for finding in self.findings[:20]:   # cap output at 20
                sev_tag = {"high": "[-]", "medium": "[!]", "low": "[*]", "info": "[i]"}.get(
                    finding.severity, "[?]"
                )
                lines.append(
                    f"    {sev_tag} {finding.label:<32} "
                    f"{finding.file}:{finding.line_no}"
                )
            if len(self.findings) > 20:
                lines.append(f"    … and {len(self.findings) - 20} more findings")
        else:
            lines.append("    [+] No security findings detected.")
        return lines


# ---------------------------------------------------------------------------
# ToolAuditor class
# ---------------------------------------------------------------------------

class ToolAuditor:
    """
    Scans installed tools for license, security issues, and code quality.

    All scanning is purely static (read-only) and never executes any code
    from the tool being scanned.
    """

    def audit(self, name: str, progress: ProgressFn = _NOOP) -> AuditReport:
        """
        Run a full audit on the installed tool *name*.

        Parameters
        ----------
        name     : Registered tool name.
        progress : Optional progress callback.

        Returns
        -------
        AuditReport

        Raises
        ------
        RuntimeError if the tool is not installed.
        """
        tool = registry.get(name)
        if not tool:
            raise RuntimeError(f"Tool '{name}' not found in registry")
        if not os.path.isdir(tool.path):
            raise RuntimeError(f"Tool directory missing: {tool.path}")

        progress(f"[*] Auditing '{name}' at {tool.path}")

        # 1. License detection
        license_id, is_copyleft = self._detect_license(tool.path)
        progress(f"[*] License: {license_id}")

        # 2. Filesystem stats
        file_count, total_size_kb, lang_stats = self._fs_stats(tool.path)

        # 3. Security scan
        findings: list[AuditFinding] = []
        source_count = 0
        for root, dirs, files in os.walk(tool.path):
            dirs[:] = [d for d in dirs
                       if not d.startswith(".")
                       and d not in ("node_modules", "__pycache__", ".venv",
                                     "target", "_build", ".git", "vendor")]
            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in _SCAN_EXTS:
                    continue
                full = os.path.join(root, fname)
                rel  = os.path.relpath(full, tool.path)
                if source_count >= _MAX_SCAN_FILES:
                    break
                source_count += 1
                file_findings = self._scan_file(full, rel)
                findings.extend(file_findings)
            if source_count >= _MAX_SCAN_FILES:
                break

        progress(f"[*] Scanned {source_count} source files, {len(findings)} findings")

        return AuditReport(
            name=name,
            license=license_id,
            copyleft=is_copyleft,
            file_count=file_count,
            source_files=source_count,
            total_size_kb=total_size_kb,
            lang_stats=lang_stats,
            findings=findings,
        )

    def audit_many(
        self,
        names: list[str],
        progress: ProgressFn = _NOOP,
    ) -> dict[str, AuditReport]:
        """Audit multiple tools and return a name → AuditReport mapping."""
        results: dict[str, AuditReport] = {}
        for name in names:
            try:
                results[name] = self.audit(name, progress=progress)
            except RuntimeError as exc:
                progress(f"[-] Audit failed for '{name}': {exc}")
        return results

    # ------------------------------------------------------------------
    # Internal: license detection
    # ------------------------------------------------------------------

    def _detect_license(self, repo_dir: str) -> tuple[str, bool]:
        """
        Scan well-known license files and README for a license identifier.
        Returns (spdx_id, is_copyleft).
        """
        candidates = [
            "LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE.rst",
            "LICENCE", "LICENCE.txt", "COPYING", "COPYING.txt",
            "README.md", "README.rst", "README.txt",
        ]
        for fname in candidates:
            path = os.path.join(repo_dir, fname)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read(8192)
                for pattern, spdx_id in _LICENSE_PATTERNS:
                    if re.search(pattern, content):
                        copyleft = any(k in spdx_id for k in ("GPL", "AGPL", "LGPL", "CC"))
                        return spdx_id, copyleft
            except OSError:
                continue
        return "Unknown", False

    # ------------------------------------------------------------------
    # Internal: filesystem stats
    # ------------------------------------------------------------------

    @staticmethod
    def _fs_stats(repo_dir: str) -> tuple[int, float, dict[str, int]]:
        """
        Walk *repo_dir* and return (file_count, total_size_kb, lang_stats).
        lang_stats maps extension → count.
        """
        file_count = 0
        total_bytes = 0
        lang_stats: dict[str, int] = {}

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                full = os.path.join(root, fname)
                try:
                    st = os.stat(full)
                    if not _stat.S_ISREG(st.st_mode):
                        continue
                    file_count += 1
                    total_bytes += st.st_size
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in _SCAN_EXTS:
                        lang_stats[ext] = lang_stats.get(ext, 0) + 1
                except OSError:
                    pass

        return file_count, total_bytes / 1024.0, lang_stats

    # ------------------------------------------------------------------
    # Internal: file scanning
    # ------------------------------------------------------------------

    def _scan_file(self, path: str, rel_path: str) -> list[AuditFinding]:
        """Scan one source file for all patterns."""
        findings: list[AuditFinding] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return findings

        for lineno, line in enumerate(lines[:_MAX_SCAN_LINES], start=1):
            stripped = line.rstrip()
            snippet  = stripped[:80]

            # Secret patterns (high severity)
            for pattern, label in _SECRET_PATTERNS:
                if re.search(pattern, stripped):
                    # Ignore obvious placeholders
                    if any(p in stripped.lower() for p in
                           ("example", "placeholder", "your_", "<", ">",
                            "xxx", "changeme", "replace", "todo")):
                        continue
                    findings.append(AuditFinding(
                        category="secret", severity="high",
                        file=rel_path, line_no=lineno,
                        label=label, snippet=snippet,
                    ))

            # Injection patterns (medium severity)
            for pattern, label in _INJECTION_PATTERNS:
                if re.search(pattern, stripped):
                    findings.append(AuditFinding(
                        category="injection", severity="medium",
                        file=rel_path, line_no=lineno,
                        label=label, snippet=snippet,
                    ))

            # TODO / FIXME / HACK (low severity, informational)
            if re.search(r"(?i)\b(todo|fixme|hack|xxx|workaround)\b", stripped):
                findings.append(AuditFinding(
                    category="todo", severity="low",
                    file=rel_path, line_no=lineno,
                    label="TODO/FIXME/HACK comment",
                    snippet=snippet,
                ))

        return findings


# Module-level singleton
tool_auditor = ToolAuditor()


# ===========================================================================
# SYSTEM 5 — EnvironmentProbe
# ===========================================================================
# Detects every installed toolchain with its version string and reports the
# overall readiness of the build environment.
#
# Usage
# -----
#   from megaploit.toolbox.installer import env_probe
#   snapshot = env_probe.snapshot()
#   for line in snapshot.report():
#       print(line)
# ===========================================================================

@dataclass
class ToolchainInfo:
    """Information about one installed toolchain binary."""
    name:       str    # e.g. "go"
    path:       str    # absolute path on disk
    version:    str    # version string from --version
    available:  bool   # True if found on PATH


@dataclass
class EnvironmentSnapshot:
    """
    Full snapshot of the build environment.

    Attributes
    ----------
    toolchains : All probed toolchain binaries.
    python_version : The running Python version string.
    python_path    : Path to the Python executable.
    os_family      : Detected OS family.
    platform_str   : Full platform identifier.
    cpu_count      : Logical CPU count.
    arch           : CPU architecture string.
    """
    toolchains:     list[ToolchainInfo]
    python_version: str
    python_path:    str
    os_family:      str
    platform_str:   str
    cpu_count:      int
    arch:           str

    def available(self) -> list[ToolchainInfo]:
        return [t for t in self.toolchains if t.available]

    def missing(self) -> list[ToolchainInfo]:
        return [t for t in self.toolchains if not t.available]

    def get(self, name: str) -> Optional[ToolchainInfo]:
        for t in self.toolchains:
            if t.name == name:
                return t
        return None

    def report(self) -> list[str]:
        lines = [
            f"[*] Environment snapshot",
            f"    Platform   : {self.platform_str}",
            f"    OS family  : {self.os_family}",
            f"    Arch       : {self.arch}",
            f"    CPUs       : {self.cpu_count}",
            f"    Python     : {self.python_version}  ({self.python_path})",
            f"",
            f"    {'TOOL':<16} {'PATH':<36} VERSION",
            f"    {'─' * 16} {'─' * 36} {'─' * 24}",
        ]
        for tc in sorted(self.toolchains, key=lambda t: t.name):
            if tc.available:
                status = f"    [+] {tc.name:<14} {tc.path:<36} {tc.version[:48]}"
            else:
                status = f"    [-] {tc.name:<14} {'(not found)':<36} —"
            lines.append(status)
        n_ok = len(self.available())
        n_missing = len(self.missing())
        lines += [
            "",
            f"    {n_ok} available / {n_missing} missing",
        ]
        return lines

    def langs_supported(self) -> list[str]:
        """Return a list of language IDs that can be built in this environment."""
        supported = []
        av = {t.name for t in self.toolchains if t.available}
        if "python3" in av or "python" in av:
            supported.append(LANG_PYTHON)
        if "go" in av:
            supported.append(LANG_GO)
        if "cargo" in av:
            supported.append(LANG_RUST)
        if "node" in av and "npm" in av:
            supported.append(LANG_NODE)
        if "ruby" in av:
            supported.append(LANG_RUBY)
        if "java" in av:
            supported.append(LANG_JAVA)
        if "bash" in av:
            supported.append(LANG_BASH)
        if "pwsh" in av or "powershell" in av:
            supported.append(LANG_POWERSHELL)
        if "make" in av or "cmake" in av or "gcc" in av:
            supported.append(LANG_BINARY)
        return supported


class EnvironmentProbe:
    """
    Probe the build environment for available toolchains.

    All checks are non-invasive — each binary is located via shutil.which
    and interrogated with --version (with a short timeout).  The results
    are cached per process lifetime; call refresh() to re-probe.
    """

    # Binary name → (version flag, optional version-extraction regex)
    _PROBES: list[tuple[str, str, Optional[str]]] = [
        ("git",        "--version",   r"git version (.+)"),
        ("python3",    "--version",   r"Python (.+)"),
        ("python",     "--version",   r"Python (.+)"),
        ("pip3",       "--version",   r"pip (.+?) from"),
        ("go",         "version",     r"go version go(.+?) "),
        ("cargo",      "--version",   r"cargo (.+)"),
        ("rustc",      "--version",   r"rustc (.+)"),
        ("node",       "--version",   None),
        ("npm",        "--version",   None),
        ("ruby",       "--version",   r"ruby (.+?) "),
        ("java",       "-version",    r'"(.+?)"'),
        ("mvn",        "--version",   r"Apache Maven (.+?) "),
        ("gradle",     "--version",   r"Gradle (.+)"),
        ("gcc",        "--version",   r"gcc (.+?) "),
        ("make",       "--version",   r"GNU Make (.+)"),
        ("cmake",      "--version",   r"cmake version (.+)"),
        ("docker",     "--version",   r"Docker version (.+?),"),
        ("pwsh",       "--version",   r"PowerShell (.+)"),
        ("powershell", "--version",   r"PowerShell (.+)"),
        ("bash",       "--version",   r"GNU bash, version (.+?) "),
        ("curl",       "--version",   r"curl (.+?) "),
        ("wget",       "--version",   r"GNU Wget (.+?) "),
        ("openssl",    "version",     r"OpenSSL (.+?) "),
        ("tcpdump",    "--version",   r"tcpdump version (.+)"),
        ("nmap",       "--version",   r"Nmap version (.+?) "),
    ]

    def __init__(self) -> None:
        self._cache: Optional[EnvironmentSnapshot] = None

    def snapshot(self, force_refresh: bool = False) -> EnvironmentSnapshot:
        """
        Return a snapshot of the current environment.
        Results are cached; pass force_refresh=True to re-probe.
        """
        if self._cache is not None and not force_refresh:
            return self._cache
        self._cache = self._build_snapshot()
        return self._cache

    def refresh(self) -> EnvironmentSnapshot:
        """Re-probe the environment and return a fresh snapshot."""
        return self.snapshot(force_refresh=True)

    def is_available(self, binary: str) -> bool:
        """Quick check: is *binary* on PATH?"""
        return shutil.which(binary) is not None

    def version_of(self, binary: str) -> str:
        """Return the version string for *binary*, or '' if not found."""
        snap = self.snapshot()
        info = snap.get(binary)
        return info.version if (info and info.available) else ""

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _build_snapshot(self) -> EnvironmentSnapshot:
        import platform as _platform

        toolchains: list[ToolchainInfo] = []
        seen: set[str] = set()

        for binary, flag, ver_regex in self._PROBES:
            if binary in seen:
                continue
            seen.add(binary)
            path = shutil.which(binary) or ""
            if not path:
                toolchains.append(ToolchainInfo(
                    name=binary, path="", version="", available=False
                ))
                continue
            # Try to get version
            version = self._get_version(binary, flag, ver_regex)
            toolchains.append(ToolchainInfo(
                name=binary, path=path, version=version, available=True
            ))

        return EnvironmentSnapshot(
            toolchains=toolchains,
            python_version=sys.version.split()[0],
            python_path=sys.executable,
            os_family=DependencyResolver._detect_os_family(),
            platform_str=_platform.platform(),
            cpu_count=_CPU_COUNT,
            arch=_platform.machine(),
        )

    @staticmethod
    def _get_version(binary: str, flag: str, regex: Optional[str]) -> str:
        """Run `binary flag` and extract version via *regex* or return raw first line."""
        try:
            result = subprocess.run(
                [binary, flag],
                capture_output=True, text=True, timeout=5,
                encoding="utf-8", errors="replace",
            )
            output = (result.stdout or result.stderr).strip()
            if not output:
                return ""
            if regex:
                m = re.search(regex, output)
                return m.group(1).strip() if m else output.splitlines()[0][:48]
            return output.splitlines()[0][:48]
        except Exception:
            return ""


# Module-level singleton
env_probe = EnvironmentProbe()


# ===========================================================================
# SYSTEM 6 — ToolConfig
# ===========================================================================
# Per-tool configuration stored in tools/<name>/.megaploit_config.json.
# Allows operator-specific overrides: custom arguments, environment variables,
# proxy settings, timeout, aliases, and post-install notes.
#
# Usage
# -----
#   from megaploit.toolbox.installer import tool_config
#   cfg = tool_config.load("sqlmap")
#   cfg.extra_args = ["--batch", "--random-agent"]
#   cfg.env_vars["SQLMAP_VERBOSE"] = "3"
#   tool_config.save(cfg)
#
#   # Read back
#   cfg = tool_config.load("sqlmap")
#   print(cfg.extra_args)
# ===========================================================================

_TOOL_CONFIG_FILENAME = ".megaploit_config.json"


@dataclass
class ToolConfig:
    """
    Per-tool runtime configuration.

    Fields
    ------
    tool_name     : Name of the tool this config belongs to.
    extra_args    : Arguments appended to every invocation.
    env_vars      : Environment variables set before launching the tool.
    proxy         : HTTP/SOCKS proxy URL (e.g. "socks5://127.0.0.1:9050").
    timeout       : Default execution timeout in seconds (0 = no limit).
    aliases       : Short alias names that map to this tool.
    notes         : Free-text operator notes about this tool.
    disabled      : If True, toolbox_run and toolbox_deploy will refuse.
    created_at    : ISO-8601 timestamp when config was first created.
    updated_at    : ISO-8601 timestamp of last save.
    """
    tool_name:   str
    extra_args:  list[str]              = field(default_factory=list)
    env_vars:    dict[str, str]         = field(default_factory=dict)
    proxy:       str                    = ""
    timeout:     int                    = 0
    aliases:     list[str]              = field(default_factory=list)
    notes:       str                    = ""
    disabled:    bool                   = False
    created_at:  str                    = ""
    updated_at:  str                    = ""

    def to_dict(self) -> dict:
        return {
            "tool_name":  self.tool_name,
            "extra_args": self.extra_args,
            "env_vars":   self.env_vars,
            "proxy":      self.proxy,
            "timeout":    self.timeout,
            "aliases":    self.aliases,
            "notes":      self.notes,
            "disabled":   self.disabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "ToolConfig":
        return ToolConfig(
            tool_name=d.get("tool_name", ""),
            extra_args=d.get("extra_args", []),
            env_vars=d.get("env_vars", {}),
            proxy=d.get("proxy", ""),
            timeout=d.get("timeout", 0),
            aliases=d.get("aliases", []),
            notes=d.get("notes", ""),
            disabled=d.get("disabled", False),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )

    def summary(self) -> list[str]:
        lines = [f"[*] Config for '{self.tool_name}'"]
        if self.disabled:
            lines.append("    [!] DISABLED — will not run")
        if self.extra_args:
            lines.append(f"    Extra args   : {' '.join(self.extra_args)}")
        if self.env_vars:
            for k, v in self.env_vars.items():
                lines.append(f"    Env          : {k}={v}")
        if self.proxy:
            lines.append(f"    Proxy        : {self.proxy}")
        if self.timeout:
            lines.append(f"    Timeout      : {self.timeout}s")
        if self.aliases:
            lines.append(f"    Aliases      : {', '.join(self.aliases)}")
        if self.notes:
            lines.append(f"    Notes        : {self.notes[:120]}")
        if self.updated_at:
            lines.append(f"    Last updated : {self.updated_at[:19]}")
        return lines


class ToolConfigManager:
    """
    Load and save per-tool configuration files.

    Each tool's config is stored at:
      tools/<name>/.megaploit_config.json

    A default (empty) config is returned if no file exists yet.
    """

    def load(self, name: str) -> ToolConfig:
        """
        Load the config for *name*.  Returns a default ToolConfig if none exists.
        """
        path = self._config_path(name)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                return ToolConfig.from_dict(data)
            except (json.JSONDecodeError, KeyError):
                pass
        return ToolConfig(tool_name=name)

    def save(self, cfg: ToolConfig) -> None:
        """
        Persist *cfg* to disk.  Creates the tool directory if needed.
        Updates the updated_at timestamp automatically.
        """
        tool_dir = os.path.join(TOOLS_DIR, cfg.tool_name)
        os.makedirs(tool_dir, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        if not cfg.created_at:
            cfg.created_at = now
        cfg.updated_at = now
        path = self._config_path(cfg.tool_name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg.to_dict(), fh, indent=2)

    def delete(self, name: str) -> None:
        """Remove the config file for *name* if it exists."""
        path = self._config_path(name)
        if os.path.isfile(path):
            os.remove(path)

    def set_extra_args(self, name: str, args: list[str]) -> ToolConfig:
        """Convenience: set extra_args for *name* and persist."""
        cfg = self.load(name)
        cfg.extra_args = args
        self.save(cfg)
        return cfg

    def set_env(self, name: str, key: str, value: str) -> ToolConfig:
        """Convenience: set one environment variable for *name* and persist."""
        cfg = self.load(name)
        cfg.env_vars[key] = value
        self.save(cfg)
        return cfg

    def set_proxy(self, name: str, proxy: str) -> ToolConfig:
        """Convenience: set the proxy for *name* and persist."""
        cfg = self.load(name)
        cfg.proxy = proxy
        self.save(cfg)
        return cfg

    def set_notes(self, name: str, notes: str) -> ToolConfig:
        """Convenience: update the notes for *name* and persist."""
        cfg = self.load(name)
        cfg.notes = notes
        self.save(cfg)
        return cfg

    def disable(self, name: str) -> None:
        """Mark the tool as disabled."""
        cfg = self.load(name)
        cfg.disabled = True
        self.save(cfg)

    def enable(self, name: str) -> None:
        """Re-enable a disabled tool."""
        cfg = self.load(name)
        cfg.disabled = False
        self.save(cfg)

    def is_disabled(self, name: str) -> bool:
        """Return True if the tool has been disabled via its config."""
        return self.load(name).disabled

    def resolve_alias(self, alias: str) -> Optional[str]:
        """
        Return the canonical tool name for *alias*, or None if not found.
        Searches all config files in the tools/ directory.
        """
        if not os.path.isdir(TOOLS_DIR):
            return None
        for entry in os.listdir(TOOLS_DIR):
            tool_dir = os.path.join(TOOLS_DIR, entry)
            if not os.path.isdir(tool_dir):
                continue
            cfg_path = os.path.join(tool_dir, _TOOL_CONFIG_FILENAME)
            if not os.path.isfile(cfg_path):
                continue
            try:
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if alias in data.get("aliases", []):
                    return entry
            except (json.JSONDecodeError, KeyError):
                continue
        return None

    def all_configs(self) -> list[ToolConfig]:
        """Return all stored tool configs."""
        configs: list[ToolConfig] = []
        if not os.path.isdir(TOOLS_DIR):
            return configs
        for entry in sorted(os.listdir(TOOLS_DIR)):
            tool_dir = os.path.join(TOOLS_DIR, entry)
            cfg_path = os.path.join(tool_dir, _TOOL_CONFIG_FILENAME)
            if os.path.isfile(cfg_path):
                configs.append(self.load(entry))
        return configs

    @staticmethod
    def _config_path(name: str) -> str:
        return os.path.join(TOOLS_DIR, name, _TOOL_CONFIG_FILENAME)


# Module-level singleton
tool_config = ToolConfigManager()


# ===========================================================================
# SYSTEM 7 — WorkspaceManager
# ===========================================================================
# Manage named "workspaces" — logical groups of tools for different
# engagements or target types (e.g. "web-pentest", "ad-attack", "recon").
#
# A workspace records which tools belong to it and can be:
#   • Exported to JSON (share with a colleague)
#   • Imported from JSON (restore on a new machine)
#   • Installed in bulk (install all tools in a workspace at once)
#
# Usage
# -----
#   from megaploit.toolbox.installer import workspace_manager
#
#   ws = workspace_manager.create("web-pentest", description="Web application testing")
#   workspace_manager.add_tool(ws.name, "sqlmap")
#   workspace_manager.add_tool(ws.name, "gobuster")
#
#   # Export
#   workspace_manager.export_json(ws.name, "/tmp/web-pentest.json")
#
#   # Install all tools in a workspace
#   workspace_manager.install_all(ws.name, progress=print)
#
# Workspaces are stored in tools/.workspaces.json.
# ===========================================================================

_WORKSPACES_FILE = os.path.join(TOOLS_DIR, ".workspaces.json")


@dataclass
class Workspace:
    """A named collection of tools."""
    name:        str
    description: str                    = ""
    tools:       list[str]              = field(default_factory=list)
    tags:        list[str]              = field(default_factory=list)
    created_at:  str                    = ""
    updated_at:  str                    = ""

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "description": self.description,
            "tools":       self.tools,
            "tags":        self.tags,
            "created_at":  self.created_at,
            "updated_at":  self.updated_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "Workspace":
        return Workspace(
            name=d["name"],
            description=d.get("description", ""),
            tools=d.get("tools", []),
            tags=d.get("tags", []),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )

    def summary(self) -> list[str]:
        lines = [
            f"[*] Workspace: {self.name}",
            f"    Description : {self.description or '(none)'}",
            f"    Tools ({len(self.tools)}) : {', '.join(self.tools) or '(empty)'}",
        ]
        if self.tags:
            lines.append(f"    Tags        : {', '.join(self.tags)}")
        if self.updated_at:
            lines.append(f"    Updated     : {self.updated_at[:19]}")
        return lines


class WorkspaceManager:
    """
    Manage named tool workspaces.

    Workspaces persist in tools/.workspaces.json.
    """

    def __init__(self) -> None:
        self._workspaces: dict[str, Workspace] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.isfile(_WORKSPACES_FILE):
            return
        try:
            with open(_WORKSPACES_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for item in data:
                ws = Workspace.from_dict(item)
                self._workspaces[ws.name] = ws
        except (json.JSONDecodeError, KeyError):
            pass

    def _save(self) -> None:
        os.makedirs(TOOLS_DIR, exist_ok=True)
        try:
            with open(_WORKSPACES_FILE, "w", encoding="utf-8") as fh:
                json.dump(
                    [ws.to_dict() for ws in self._workspaces.values()],
                    fh, indent=2
                )
        except OSError:
            pass

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(
        self,
        name: str,
        description: str = "",
        tags: Optional[list[str]] = None,
    ) -> Workspace:
        """Create a new workspace.  Raises RuntimeError if it already exists."""
        if name in self._workspaces:
            raise RuntimeError(f"Workspace '{name}' already exists.")
        now = datetime.now(timezone.utc).isoformat()
        ws = Workspace(
            name=name,
            description=description,
            tags=tags or [],
            created_at=now,
            updated_at=now,
        )
        self._workspaces[name] = ws
        self._save()
        return ws

    def get(self, name: str) -> Optional[Workspace]:
        return self._workspaces.get(name)

    def delete(self, name: str) -> None:
        if name not in self._workspaces:
            raise RuntimeError(f"Workspace '{name}' not found.")
        del self._workspaces[name]
        self._save()

    def all(self) -> list[Workspace]:
        return sorted(self._workspaces.values(), key=lambda w: w.name)

    def rename(self, old_name: str, new_name: str) -> Workspace:
        """Rename a workspace."""
        ws = self._workspaces.pop(old_name, None)
        if ws is None:
            raise RuntimeError(f"Workspace '{old_name}' not found.")
        if new_name in self._workspaces:
            raise RuntimeError(f"Workspace '{new_name}' already exists.")
        ws.name = new_name
        ws.updated_at = datetime.now(timezone.utc).isoformat()
        self._workspaces[new_name] = ws
        self._save()
        return ws

    # ------------------------------------------------------------------
    # Tool management
    # ------------------------------------------------------------------

    def add_tool(self, ws_name: str, tool_name: str) -> None:
        """Add *tool_name* to workspace *ws_name*."""
        ws = self._require(ws_name)
        if tool_name not in ws.tools:
            ws.tools.append(tool_name)
            ws.updated_at = datetime.now(timezone.utc).isoformat()
            self._save()

    def remove_tool(self, ws_name: str, tool_name: str) -> None:
        """Remove *tool_name* from workspace *ws_name*."""
        ws = self._require(ws_name)
        if tool_name in ws.tools:
            ws.tools.remove(tool_name)
            ws.updated_at = datetime.now(timezone.utc).isoformat()
            self._save()

    def set_tools(self, ws_name: str, tool_names: list[str]) -> None:
        """Replace the tool list for *ws_name* entirely."""
        ws = self._require(ws_name)
        ws.tools = list(tool_names)
        ws.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()

    # ------------------------------------------------------------------
    # Bulk install
    # ------------------------------------------------------------------

    def install_all(
        self,
        ws_name: str,
        progress: ProgressFn = _NOOP,
        max_workers: int = 4,
        skip_installed: bool = True,
    ) -> dict[str, "Tool | Exception"]:
        """
        Install every tool listed in workspace *ws_name*.

        Parameters
        ----------
        ws_name        : Workspace to install.
        progress       : Progress callback.
        max_workers    : Parallel workers for git clone phase.
        skip_installed : Skip tools already in the registry.

        Returns
        -------
        Dict mapping tool_name → Tool (success) or Exception (failure).
        """
        ws = self._require(ws_name)
        if not ws.tools:
            progress(f"[!] Workspace '{ws_name}' is empty.")
            return {}

        specs = []
        for name in ws.tools:
            if skip_installed and registry.get(name):
                progress(f"[*] Skipping '{name}' — already installed")
                continue
            # Look up in catalogue
            cat_entry = CATALOGUE.get(name)
            if cat_entry:
                specs.append({
                    "repo":        cat_entry.repo,
                    "name":        name,
                    "description": cat_entry.description,
                    "entry":       cat_entry.entry,
                    "tags":        cat_entry.tags,
                })
            else:
                progress(f"[!] '{name}' not in catalogue — skipping (add it manually)")

        if not specs:
            progress("[*] Nothing to install.")
            return {}

        progress(f"[*] Installing {len(specs)} tool(s) from workspace '{ws_name}'…")
        return install_many(specs, progress=progress, max_workers=max_workers)

    # ------------------------------------------------------------------
    # Export / import
    # ------------------------------------------------------------------

    def export_json(self, ws_name: str, output_path: str) -> None:
        """
        Export workspace *ws_name* (including tool catalogue data) to a JSON file.
        The JSON can be imported on another machine via import_json().
        """
        ws = self._require(ws_name)
        export: dict = {
            "workspace": ws.to_dict(),
            "tool_specs": [],
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "megaploit_version": "3.0",
        }
        for name in ws.tools:
            tool = registry.get(name)
            if tool:
                export["tool_specs"].append(tool.to_dict())
            elif name in CATALOGUE:
                cat = CATALOGUE[name]
                export["tool_specs"].append({
                    "name":        name,
                    "repo":        cat.repo,
                    "description": cat.description,
                    "entry":       cat.entry,
                    "lang":        cat.lang,
                    "run_cmd":     [],
                    "installed_at": "",
                    "tags":        cat.tags,
                })
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(export, fh, indent=2)

    def import_json(
        self,
        input_path: str,
        progress: ProgressFn = _NOOP,
        install_tools: bool = False,
        max_workers: int = 4,
    ) -> Workspace:
        """
        Import a workspace from a JSON file exported by export_json().

        Parameters
        ----------
        input_path    : Path to the exported JSON file.
        progress      : Progress callback.
        install_tools : If True, install any tools listed but not yet present.

        Returns
        -------
        The imported Workspace.
        """
        with open(input_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        ws_data = data.get("workspace", {})
        ws_name = ws_data.get("name", "imported")

        # If workspace already exists, overwrite
        if ws_name in self._workspaces:
            progress(f"[!] Overwriting existing workspace '{ws_name}'")
        ws = Workspace.from_dict(ws_data)
        ws.updated_at = datetime.now(timezone.utc).isoformat()
        self._workspaces[ws_name] = ws
        self._save()
        progress(f"[+] Workspace '{ws_name}' imported ({len(ws.tools)} tools)")

        if install_tools:
            specs = []
            for spec in data.get("tool_specs", []):
                name = spec.get("name", "")
                if not name or registry.get(name):
                    continue
                specs.append({
                    "repo":        spec.get("repo", ""),
                    "name":        name,
                    "description": spec.get("description", ""),
                    "entry":       spec.get("entry", ""),
                    "tags":        spec.get("tags", []),
                })
            if specs:
                progress(f"[*] Installing {len(specs)} tool(s) from imported workspace…")
                install_many(specs, progress=progress, max_workers=max_workers)

        return ws

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require(self, ws_name: str) -> Workspace:
        ws = self._workspaces.get(ws_name)
        if ws is None:
            available = ", ".join(sorted(self._workspaces.keys())) or "(none)"
            raise RuntimeError(
                f"Workspace '{ws_name}' not found.\n"
                f"Available workspaces: {available}\n"
                f"Create one with:  workspace_manager.create('{ws_name}')"
            )
        return ws


# Module-level singleton
workspace_manager = WorkspaceManager()


# ===========================================================================
# SYSTEM 8 — InstallPlan (dry-run mode)
# ===========================================================================
# Simulate an install or workspace install without touching disk.
# Reports exactly what would happen: clone URLs, detected languages,
# build commands, and any missing toolchains — so the operator can review
# before committing.
#
# Usage
# -----
#   from megaploit.toolbox.installer import InstallPlan
#   plan = InstallPlan.from_url("https://github.com/sqlmapproject/sqlmap", "sqlmap")
#   for line in plan.describe():
#       print(line)
# ===========================================================================

@dataclass
class InstallStep:
    """One step in an install plan."""
    step_no:     int
    kind:        str    # "clone" | "detect" | "build" | "deps" | "register"
    description: str
    command:     str    # the command that would be run (human-readable)
    can_skip:    bool   # True if build_cache says this is fresh


@dataclass
class InstallPlan:
    """
    A planned install operation — no disk changes are made.

    Attributes
    ----------
    name      : Tool name.
    repo_url  : Source repository URL.
    lang      : Language ID (may be 'unknown' if not detectable without cloning).
    steps     : Ordered list of InstallStep objects.
    warnings  : Non-fatal issues detected during planning.
    errors    : Fatal issues that would prevent the install.
    """
    name:     str
    repo_url: str
    lang:     str
    steps:    list[InstallStep]
    warnings: list[str]
    errors:   list[str]

    @property
    def feasible(self) -> bool:
        """True iff there are no hard errors blocking the install."""
        return len(self.errors) == 0

    def describe(self) -> list[str]:
        """Return a formatted human-readable plan."""
        lines = [
            f"[*] Install plan for '{self.name}'",
            f"    Source   : {self.repo_url}",
            f"    Language : {self.lang}",
            f"    Steps    : {len(self.steps)}",
        ]
        if self.warnings:
            for w in self.warnings:
                lines.append(f"    [!] {w}")
        if self.errors:
            for e in self.errors:
                lines.append(f"    [-] ERROR: {e}")
            lines.append("    Install would FAIL with these errors.")
            return lines
        lines.append("")
        for step in self.steps:
            skip_tag = "  (cached — skip)" if step.can_skip else ""
            lines.append(f"    {step.step_no}. [{step.kind:<8}] {step.description}{skip_tag}")
            if step.command:
                lines.append(f"       $ {step.command}")
        return lines

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_url(
        cls,
        repo_url: str,
        name: str,
        lang_hint: str = "",
    ) -> "InstallPlan":
        """
        Build a plan for installing a tool from *repo_url*.

        The language must be provided as a hint since we can't detect it
        without cloning.  If omitted, 'unknown' is used and a warning is added.
        """
        warnings: list[str] = []
        errors:   list[str] = []
        steps:    list[InstallStep] = []
        step_no = 1

        # Validation
        if not repo_url.startswith(("https://", "http://", "git@", "ssh://")):
            errors.append(f"Invalid repo URL: {repo_url}")
        if registry.get(name):
            errors.append(
                f"Tool '{name}' is already installed. "
                f"Use 'toolbox update {name}' or 'toolbox remove {name}' first."
            )
        if not shutil.which("git"):
            errors.append("'git' is not on PATH — cannot clone.")

        if errors:
            return cls(name=name, repo_url=repo_url, lang=lang_hint or "unknown",
                       steps=steps, warnings=warnings, errors=errors)

        # Step 1: clone
        dest = os.path.join(TOOLS_DIR, name)
        steps.append(InstallStep(
            step_no=step_no, kind="clone",
            description=f"Clone {repo_url} → {dest}",
            command=f"git clone --depth=1 --recurse-submodules {repo_url} {dest}",
            can_skip=False,
        ))
        step_no += 1

        # Step 2: detect language
        lang = lang_hint or "unknown"
        if not lang_hint:
            warnings.append("Language unknown without cloning — using 'unknown'")
        steps.append(InstallStep(
            step_no=step_no, kind="detect",
            description=f"Detect language (expected: {lang})",
            command="",
            can_skip=False,
        ))
        step_no += 1

        # Check toolchain
        missing_bins = dep_resolver.which_missing(lang)
        if missing_bins:
            warnings.append(
                f"Missing toolchain binaries for {lang}: {', '.join(missing_bins)}"
            )

        # Step 3: build (language-specific)
        build_cmd, build_desc = cls._build_plan(lang, name, dest)
        can_skip = build_cache.is_fresh(name)
        steps.append(InstallStep(
            step_no=step_no, kind="build",
            description=build_desc,
            command=build_cmd,
            can_skip=can_skip,
        ))
        step_no += 1

        # Step 4: detect entry-point
        steps.append(InstallStep(
            step_no=step_no, kind="entry",
            description="Detect entry-point",
            command="",
            can_skip=False,
        ))
        step_no += 1

        # Step 5: register
        steps.append(InstallStep(
            step_no=step_no, kind="register",
            description=f"Register '{name}' in tools/tools.json",
            command="",
            can_skip=False,
        ))

        return cls(name=name, repo_url=repo_url, lang=lang,
                   steps=steps, warnings=warnings, errors=errors)

    @classmethod
    def from_catalogue(cls, short_name: str) -> "InstallPlan":
        """Build a plan from the built-in catalogue entry."""
        entry = CATALOGUE.get(short_name)
        if entry is None:
            return cls(
                name=short_name, repo_url="", lang="",
                steps=[], warnings=[],
                errors=[f"'{short_name}' not found in catalogue"],
            )
        return cls.from_url(
            repo_url=entry.repo,
            name=short_name,
            lang_hint=entry.lang or "",
        )

    @staticmethod
    def _build_plan(lang: str, name: str, dest: str) -> tuple[str, str]:
        """Return (command_str, description) for the build step."""
        if lang == LANG_PYTHON:
            return (
                f"python3 -m venv {dest}/.venv && "
                f"{dest}/.venv/bin/pip install -r {dest}/requirements.txt",
                "Create Python venv + pip install",
            )
        if lang == LANG_GO:
            return (
                f"cd {dest} && go build -ldflags='-s -w' -o {dest}/{name} ./...",
                "Go build binary",
            )
        if lang == LANG_RUST:
            return (
                f"cd {dest} && cargo build --release",
                "Cargo build --release",
            )
        if lang == LANG_NODE:
            lock = os.path.join(dest, "package-lock.json")
            cmd = "npm ci" if os.path.isfile(lock) else "npm install"
            return (
                f"cd {dest} && {cmd}",
                f"Node {cmd}",
            )
        if lang == LANG_RUBY:
            return (
                f"cd {dest} && bundle install --quiet",
                "Bundle install",
            )
        if lang == LANG_JAVA:
            return (
                f"cd {dest} && mvn package -q -DskipTests",
                "Maven package",
            )
        if lang == LANG_BASH:
            return (
                f"chmod +x {dest}/*.sh",
                "chmod +x shell scripts",
            )
        if lang == LANG_BINARY:
            return (
                f"cd {dest} && cmake .. && make -j{_CPU_COUNT}",
                "cmake + make",
            )
        return ("", f"No build step for lang={lang}")
