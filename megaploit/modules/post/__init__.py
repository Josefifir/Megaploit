"""
megaploit.modules.post
~~~~~~~~~~~~~~~~~~~~~~
Post-exploitation modules — run against active agent sessions.

All modules here subclass ``AgentModule`` from ``megaploit.modules.base`` and
implement the standard ``run(session=None)`` lifecycle.  Operators load them with:

    use post/linux/gather/dump_shadow
    setopt SESSION 1
    run

Or from a session context:

    (session:1) use post/linux/gather/dump_shadow
    (session:1) run

Available modules
-----------------
  post/multi/gather/sysinfo          — detailed system info via sysinfo command
  post/multi/gather/env_dump         — all environment variables
  post/multi/gather/enum_users       — local user and group accounts
  post/multi/gather/network_info     — ifconfig, netstat, routes, arp
  post/linux/gather/dump_shadow      — read /etc/shadow (needs root)
  post/linux/privesc/suid_check      — list SUID binaries for privesc research
  post/windows/gather/hashdump       — SAM + SYSTEM hash dump (needs SYSTEM)
  post/windows/gather/lsa_secrets    — LSA secrets dump
  post/windows/privesc/token_info    — enumerate token privileges
  post/multi/manage/beacon_sleep     — set C2 beacon interval
  post/multi/manage/persist          — cross-platform persistence (Win/Linux/macOS)
"""
