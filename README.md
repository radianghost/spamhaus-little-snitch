# Spamhaus DROP for Little Snitch

This repository publishes the official Spamhaus DROP IPv4 and IPv6 CIDR lists in a format Little Snitch can consume.

The GitHub Action runs daily, downloads the fixed official Spamhaus JSON feeds, validates global CIDRs, and updates these files only when their contents change:

- `drop_v4.txt`
- `drop_v6.txt`

Use these URLs in Little Snitch after the first workflow run:

```text
https://raw.githubusercontent.com/radianghost/spamhaus-little-snitch/main/drop_v4.txt
https://raw.githubusercontent.com/radianghost/spamhaus-little-snitch/main/drop_v6.txt
```

The repository is public because Little Snitch needs to download the lists without GitHub authentication. Spamhaus asks users not to fetch its DROP feeds more than once per day.
