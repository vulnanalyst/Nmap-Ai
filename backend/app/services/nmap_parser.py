from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


class NmapParseError(ValueError):
    pass


def parse_nmap_xml(source: str | Path | bytes) -> dict[str, Any]:
    """Parse Nmap XML into a normalized dict without inventing hosts or ports."""
    try:
        if isinstance(source, bytes):
            root = ET.fromstring(source)
        else:
            path = Path(source)
            if path.exists():
                tree = ET.parse(path)
                root = tree.getroot()
            else:
                root = ET.fromstring(str(source))
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapParseError(f"Expected nmaprun root, found {root.tag}")

    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    hosts_stats = runstats.find("hosts") if runstats is not None else None

    hosts: list[dict[str, Any]] = []
    port_counts = {"open": 0, "closed": 0, "filtered": 0, "other": 0}

    for host_el in root.findall("host"):
        host = _parse_host(host_el, port_counts)
        hosts.append(host)

    return {
        "scanner": root.attrib.get("scanner"),
        "args": root.attrib.get("args"),
        "start": root.attrib.get("start"),
        "startstr": root.attrib.get("startstr"),
        "version": root.attrib.get("version"),
        "xmloutputversion": root.attrib.get("xmloutputversion"),
        "elapsed": _to_float(finished.attrib.get("elapsed") if finished is not None else None),
        "exit": finished.attrib.get("exit") if finished is not None else None,
        "hosts_up": _to_int(hosts_stats.attrib.get("up") if hosts_stats is not None else None),
        "hosts_down": _to_int(hosts_stats.attrib.get("down") if hosts_stats is not None else None),
        "hosts_total": _to_int(hosts_stats.attrib.get("total") if hosts_stats is not None else None),
        "port_counts": port_counts,
        "hosts": hosts,
        "provenance": "nmap_xml",
    }


def _parse_host(host_el: ET.Element, port_counts: dict[str, int]) -> dict[str, Any]:
    status_el = host_el.find("status")
    ipv4 = None
    ipv6 = None
    mac = None
    mac_vendor = None
    for addr in host_el.findall("address"):
        kind = addr.attrib.get("addrtype")
        if kind == "ipv4":
            ipv4 = addr.attrib.get("addr")
        elif kind == "ipv6":
            ipv6 = addr.attrib.get("addr")
        elif kind == "mac":
            mac = addr.attrib.get("addr")
            mac_vendor = addr.attrib.get("vendor")

    hostnames = [
        {"name": hn.attrib.get("name"), "type": hn.attrib.get("type")}
        for hn in host_el.findall("./hostnames/hostname")
        if hn.attrib.get("name")
    ]
    ports = []
    for port_el in host_el.findall("./ports/port"):
        parsed = _parse_port(port_el)
        state = parsed["state"]
        if state in port_counts:
            port_counts[state] += 1
        else:
            port_counts["other"] += 1
        ports.append(parsed)

    os_matches = []
    for match in host_el.findall("./os/osmatch"):
        os_matches.append(
            {
                "name": match.attrib.get("name"),
                "accuracy": _to_int(match.attrib.get("accuracy")),
                "label": "os_guess",
            }
        )

    host_scripts = [_parse_script(s) for s in host_el.findall("./hostscript/script")]

    return {
        "ip": ipv4 or ipv6,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "mac": mac,
        "mac_vendor": mac_vendor,
        "state": status_el.attrib.get("state") if status_el is not None else "unknown",
        "reason": status_el.attrib.get("reason") if status_el is not None else None,
        "hostnames": hostnames,
        "ports": ports,
        "os_guesses": os_matches,
        "scripts": host_scripts,
    }


def _parse_port(port_el: ET.Element) -> dict[str, Any]:
    state_el = port_el.find("state")
    svc_el = port_el.find("service")
    scripts = [_parse_script(s) for s in port_el.findall("script")]
    service = {}
    if svc_el is not None:
        service = {
            "name": svc_el.attrib.get("name"),
            "product": svc_el.attrib.get("product"),
            "version": svc_el.attrib.get("version"),
            "extrainfo": svc_el.attrib.get("extrainfo"),
            "tunnel": svc_el.attrib.get("tunnel"),
            "method": svc_el.attrib.get("method"),
            "conf": svc_el.attrib.get("conf"),
        }
    return {
        "protocol": port_el.attrib.get("protocol"),
        "port": _to_int(port_el.attrib.get("portid")),
        "state": (state_el.attrib.get("state") if state_el is not None else "unknown"),
        "reason": state_el.attrib.get("reason") if state_el is not None else None,
        "service": service,
        "scripts": scripts,
    }


def _parse_script(script_el: ET.Element) -> dict[str, Any]:
    return {
        "id": script_el.attrib.get("id"),
        "output": script_el.attrib.get("output"),
    }


def _to_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _to_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None
