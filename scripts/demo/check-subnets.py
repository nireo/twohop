#!/usr/bin/env python3
"""Refuse overlapping routes before adding the fixed demo topology."""

import ipaddress
import json
import subprocess
import sys

demo = ipaddress.ip_network("10.203.0.0/22")
if sys.platform == "darwin":
    output = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
    destinations = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or not fields[0][0].isdigit():
            continue
        address, _, prefix = fields[0].partition("/")
        octets = address.split(".")
        # BSD abbreviates network routes, e.g. 10.203/16.
        destinations.append(
            ".".join(octets + ["0"] * (4 - len(octets)))
            + "/"
            + (prefix or str(len(octets) * 8))
        )
else:
    routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show", "table", "all"]))
    destinations = [route["dst"] for route in routes if "dst" in route]

for destination in destinations:
    if destination == "default":
        continue
    network = ipaddress.ip_network(destination, strict=False)
    if network.prefixlen and demo.overlaps(network):
        sys.exit(f"Demo subnet {demo} overlaps existing route {destination}; refusing setup.")
