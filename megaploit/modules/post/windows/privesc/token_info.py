"""megaploit.modules.post.windows.privesc.token_info — enumerate token privileges."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

# Privilege names that enable token impersonation or SYSTEM escalation
_INTERESTING = {
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
    "SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
    "SeCreateTokenPrivilege", "SeTokenObjectPrivilege",
}

class PostTokenInfo(AgentModule):
    name        = "post/windows/privesc/token_info"
    description = "List current token privileges and flag privesc vectors (SeImpersonate etc.)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1134/",
        "https://exploit.ph/impersonation-privileges.html",
    ]
    platform    = ["windows"]; arch = ["x64", "x86"]; rank = 400

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
        out = self._send("whoami_priv", sess)
        lines = out.splitlines()
        enabled: list[str] = []
        for line in lines:
            for priv in _INTERESTING:
                if priv in line and "Enabled" in line:
                    enabled.append(priv)
                    self._emit(f"  [!] Interesting privilege: {priv}")
        if enabled:
            self._ok(f"Found {len(enabled)} interesting privilege(s)",
                     interesting_privileges=enabled, raw=out)
        else:
            self._ok("Token enumerated — no immediate privesc privileges found",
                     raw=out, interesting_privileges=[])
        return self.results

MODULE = PostTokenInfo
