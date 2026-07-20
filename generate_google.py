#!/usr/bin/env python3
"""
Generate google.txt: Google's own service IP ranges (goog.json) with the
Google Cloud customer ranges (cloud.json) removed.

Why the subtraction: goog.json lists every Google-owned range, which includes
the GCP customer ranges published in cloud.json. GCP customer ranges are shared
infrastructure where abuse is also hosted, so they must stay blockable. We keep
only "goog minus cloud" — Google's own services (google.com, gmail, Pages/CDN,
etc.) — which is what should be excluded from a blocklist.

Output: one CIDR per line, IPv4 ranges first then IPv6, each family collapsed.
"""

import json
import sys
import urllib.request
import ipaddress

GOOG_URL = "https://www.gstatic.com/ipranges/goog.json"
CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"
OUTPUT = "google.txt"


def load(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def prefixes(data):
    """Return (ipv4_networks, ipv6_networks) from a *.json ipranges document."""
    v4, v6 = [], []
    for entry in data.get("prefixes", []):
        cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)
    return v4, v6


def subtract(google_nets, cloud_nets):
    """Return google_nets with any space contained in cloud_nets removed.

    Both inputs are a single address family. CIDR blocks are either disjoint or
    one contains the other, so address_exclude() handles every real case.
    """
    google_nets = list(ipaddress.collapse_addresses(google_nets))
    cloud_nets = list(ipaddress.collapse_addresses(cloud_nets))
    result = []
    for g in google_nets:
        fragments = [g]
        for c in cloud_nets:
            if not fragments:
                break
            nxt = []
            for frag in fragments:
                if not frag.overlaps(c):
                    nxt.append(frag)
                elif frag.subnet_of(c):
                    continue  # fragment fully inside a cloud range -> drop
                elif c.subnet_of(frag):
                    nxt.extend(frag.address_exclude(c))  # shred out the cloud block
                else:
                    nxt.append(frag)  # unreachable for aligned CIDRs
            fragments = nxt
        result.extend(fragments)
    return list(ipaddress.collapse_addresses(result))


def main():
    goog = load(GOOG_URL)
    cloud = load(CLOUD_URL)

    g4, g6 = prefixes(goog)
    c4, c6 = prefixes(cloud)

    own_v4 = subtract(g4, c4)
    own_v6 = subtract(g6, c6)

    if not own_v4 and not own_v6:
        print("ERROR: computed an empty Google range set, refusing to write.", file=sys.stderr)
        sys.exit(1)

    lines = [str(n) for n in own_v4] + [str(n) for n in own_v6]
    with open(OUTPUT, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} ranges to {OUTPUT} "
          f"({len(own_v4)} IPv4, {len(own_v6)} IPv6). "
          f"goog={len(g4)+len(g6)} cloud={len(c4)+len(c6)} prefixes.")


if __name__ == "__main__":
    main()
