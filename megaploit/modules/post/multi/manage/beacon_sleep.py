"""megaploit.modules.post.multi.manage.beacon_sleep — set C2 beacon interval."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostBeaconSleep(AgentModule):
    name        = "post/multi/manage/beacon_sleep"
    description = "Configure the agent's C2 beacon sleep interval (reduces network noise)"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = []
    platform    = ["windows","linux","macos"]; arch = []; rank = 500

    def _define_options(self) -> None:
        self._opt("SESSION",  OptionType.INTEGER, required=True,
                  description="Session ID to target")
        self._opt("INTERVAL", OptionType.INTEGER, default=30,
                  description="Sleep interval in seconds (0 = no sleep)")

    def run(self, session=None) -> list:
        self.validate()
        sess = session or self.session
        if sess is None:
            from megaploit.modules.base import ModuleError
            raise ModuleError("No session — set SESSION <id>")
        self.results.clear()
        interval = int(self.get("INTERVAL"))
        out = self._send(f"beacon_sleep {interval}", sess)
        if "[+]" in out or "set" in out.lower():
            self._ok(f"Beacon sleep set to {interval}s", interval=interval)
        else:
            self._fail(f"beacon_sleep: {out}")
        return self.results

MODULE = PostBeaconSleep
