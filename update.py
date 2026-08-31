#!/usr/bin/env python3
"""Publish validated Spamhaus DROP CIDRs for Little Snitch."""

import ipaddress
import json
from pathlib import Path
import tempfile
import urllib.request

FEEDS = {
    4: "https://www.spamhaus.org/drop/drop_v4.json",
    6: "https://www.spamhaus.org/drop/drop_v6.json",
}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "spamhaus-little-snitch/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("unexpected HTTP status %s" % response.status)
        body = response.read(10 * 1024 * 1024 + 1)
    if len(body) > 10 * 1024 * 1024:
        raise ValueError("feed is unexpectedly large")
    return body.decode("utf-8")


def parse(text, version):
    cidrs = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("bad JSON on line %d: %s" % (number, error))
        if not isinstance(record, dict):
            raise ValueError("non-object JSON on line %d" % number)
        if record.get("type") is not None:  # Spamhaus metadata row
            continue
        try:
            network = ipaddress.ip_network(record["cidr"], strict=True)
        except (KeyError, ValueError) as error:
            raise ValueError("invalid CIDR on line %d: %s" % (number, error))
        if network.version != version or network.prefixlen < {4: 8, 6: 16}[version]:
            raise ValueError("unsafe CIDR on line %d: %s" % (number, network))
        if not network.is_global:
            raise ValueError("non-global CIDR on line %d: %s" % (number, network))
        cidrs.add(network.with_prefixlen)
    if not cidrs:
        raise ValueError("feed contained no usable CIDRs")
    return sorted(cidrs, key=lambda item: (int(ipaddress.ip_network(item).network_address),
                                            ipaddress.ip_network(item).prefixlen))


def write(name, cidrs):
    target = Path(name)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=".", encoding="utf-8") as output:
        output.write("\n".join(cidrs) + "\n")
        temporary = output.name
    Path(temporary).replace(target)


lists = {version: parse(fetch(url), version) for version, url in FEEDS.items()}
write("drop_v4.txt", lists[4])
write("drop_v6.txt", lists[6])
print("Published %d IPv4 and %d IPv6 CIDRs" % (len(lists[4]), len(lists[6])))
