"""megaploit.modules.post.linux.privesc.suid_check — enumerate SUID binaries."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

# Known GTFOBins SUID exploits for quick triage
_GTFOBINS = {
    "bash","sh","dash","zsh","python","python3","perl","ruby","lua","php","node",
    "awk","nawk","gawk","mawk","vim","vi","nano","less","more","man","find",
    "cp","mv","dd","tee","cat","cut","head","tail","sed","grep","env","xargs",
    "sudo","su","nmap","netcat","nc","socat","curl","wget","ftp","tftp","ssh",
    "strace","gdb","gcore","zip","tar","git","svn","docker","lxc","runc",
    "pkexec","policykit","dbus","busybox","ionice","nice","taskset","unshare",
    "nsenter","newgrp","chfn","chsh","passwd","chage","crontab","mount","umount",
    "systemctl","journalctl","apt","dpkg","pip","pip3","npm","gem","make","cmake",
}

class PostSuidCheck(AgentModule):
    name        = "post/linux/privesc/suid_check"
    description = "Find SUID/SGID binaries and flag known GTFOBins privesc vectors"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1548/001/",
        "https://gtfobins.github.io/",
    ]
    platform    = ["linux"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("SESSION", OptionType.INTEGER, required=True,
                  description="Session ID to target")

    def run(self, session=None) -> list:
        self.validate()
        sess = session or self.session
        if sess is None:
            from megaploit.modules.base import ModuleError
            raise ModuleError("No session — set SESSION <id>")
        self.results.clear()
        self._emit("[*] Searching for SUID/SGID binaries…")
        out = self._send("find_suid", sess)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        hits = []
        for line in lines:
            name = line.split("/")[-1].lower()
            if name in _GTFOBINS:
                hits.append(line)
                self._emit(f"  [!] GTFOBins hit: {line}")
        if hits:
            self._ok(f"Found {len(hits)} GTFOBins SUID binary/ies",
                     suid_binaries=lines, gtfobins=hits)
        elif lines:
            self._ok(f"Found {len(lines)} SUID binaries (no GTFOBins matches)",
                     suid_binaries=lines, gtfobins=[])
        else:
            self._fail("No SUID binaries found or insufficient permissions")
        return self.results

MODULE = PostSuidCheck
