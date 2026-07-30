# Pivot Routes

Document your pivot topology and route traffic through compromised hosts.

## Commands

```
megaploit [0] » route add 10.10.0.0/16 2      # route 10.10.x.x through session 2
megaploit [0] » route print                    # show routing table
megaploit [0] » route remove 10.10.0.0/16     # remove a route
megaploit [0] » route flush                    # remove all routes
```

## In-session pivoting

```bash
# Port forward — traffic to target:8888 is relayed to 10.10.10.20:3389
megaploit (10.0.0.42) > portfwd 8888 10.10.10.20 3389

# SOCKS5 proxy — route all tools through the target
megaploit (10.0.0.42) > socks5
megaploit (10.0.0.42) > socks5 9050
```

Configure proxychains or your tools to use `target-IP:1080` (default port).
