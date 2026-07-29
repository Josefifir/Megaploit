"""megaploit.modules.post.multi.gather.enum_users — enumerate local users and groups."""
from megaploit.modules.base import AgentModule, ModuleType, OptionType

class PostEnumUsers(AgentModule):
    name        = "post/multi/gather/enum_users"
    description = "List local user accounts and groups on the target"
    module_type = ModuleType.POST
    author      = "megaploit"
    references  = ["https://attack.mitre.org/techniques/T1087/001/"]
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
        users = self._send("users", sess)
        logged = self._send("logged_in", sess)
        combined = f"=== Local Accounts ===\n{users}\n\n=== Logged In ===\n{logged}"
        if users.strip() or logged.strip():
            self._ok("User enumeration complete", output=combined)
        else:
            self._fail("users/logged_in returned empty")
        return self.results

MODULE = PostEnumUsers
