# Credential Store & Reporting

## Credential Store

Credentials from `hashdump`, `browser_creds`, `wifi_passwords`, `cred_vault`, and `ssh_harvest` are automatically saved to a local SQLite database.

```
megaploit [0] » creds show
megaploit [0] » creds search admin
megaploit [0] » creds export creds.json
```

## Loot Browser

```
megaploit [0] » loot browse
```

## Reports

```
megaploit [0] » report html pentest_report.html
megaploit [0] » report json pentest_report.json
megaploit [0] » engagement name "Client Corp Q2 2024"
megaploit [0] » engagement show
```
