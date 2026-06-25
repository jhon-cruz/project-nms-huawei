import re
import subprocess
from typing import Any


OIDS = {
    "ifDescr": ".1.3.6.1.2.1.2.2.1.2",
    "ifType": ".1.3.6.1.2.1.2.2.1.3",
    "ifSpeed": ".1.3.6.1.2.1.2.2.1.5",
    "ifAdminStatus": ".1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": ".1.3.6.1.2.1.2.2.1.8",
    "ifName": ".1.3.6.1.2.1.31.1.1.1.1",
    "ifInOctets": ".1.3.6.1.2.1.31.1.1.1.6",
    "ifOutOctets": ".1.3.6.1.2.1.31.1.1.1.10",
    "ifHighSpeed": ".1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias": ".1.3.6.1.2.1.31.1.1.1.18",
}

TEXT_OIDS = {
    "ifDescr": "IF-MIB::ifDescr",
    "ifType": "IF-MIB::ifType",
    "ifSpeed": "IF-MIB::ifSpeed",
    "ifAdminStatus": "IF-MIB::ifAdminStatus",
    "ifOperStatus": "IF-MIB::ifOperStatus",
    "ifName": "IF-MIB::ifName",
    "ifInOctets": "IF-MIB::ifHCInOctets",
    "ifOutOctets": "IF-MIB::ifHCOutOctets",
    "ifHighSpeed": "IF-MIB::ifHighSpeed",
    "ifAlias": "IF-MIB::ifAlias",
}


STATUS = {
    "1": "up",
    "2": "down",
    "3": "testing",
    "4": "unknown",
    "5": "dormant",
    "6": "notPresent",
    "7": "lowerLayerDown",
}


IF_TYPES = {
    "6": "ethernetCsmacd",
    "24": "softwareLoopback",
    "53": "propVirtual",
    "131": "tunnel",
    "135": "l2vlan",
    "136": "l3ipvlan",
    "161": "ieee8023adLag",
}


def _target(host: str, port: int) -> str:
    return host if int(port) == 161 else f"{host}:{port}"


def _snmpwalk(host: str, port: int, community: str, oid: str, timeout: int = 4) -> str:
    cmd = [
        "snmpwalk",
        "-v2c",
        "-c",
        community,
        "-On",
        "-t",
        "2",
        "-r",
        "1",
        _target(host, port),
        oid,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "snmpwalk failed").strip())
    return proc.stdout


def _parse_value(raw: str) -> str:
    text = raw.strip()
    if ":" in text:
        text = text.split(":", 1)[1].strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return text


def _parse_walk(output: str, base_oid: str) -> dict[int, str]:
    values: dict[int, str] = {}
    base = base_oid.lstrip(".")
    for line in (output or "").splitlines():
        if " = " not in line:
            continue
        left, right = line.split(" = ", 1)
        left_text = left.strip()
        match = re.search(rf"\.?{re.escape(base)}\.(\d+)$", left_text)
        if not match:
            match = re.search(r"\.(\d+)$", left_text)
        if not match:
            continue
        values[int(match.group(1))] = _parse_value(right)
    return values


def _status(value: str | None) -> str:
    if not value:
        return "unknown"
    match = re.search(r"\((\d+)\)", value)
    number = match.group(1) if match else value.split("(", 1)[0].strip()
    return STATUS.get(number, value)


def _if_type(value: str | None) -> str:
    if not value:
        return "unknown"
    match = re.search(r"\((\d+)\)", value)
    number = match.group(1) if match else value.split("(", 1)[0].strip()
    return IF_TYPES.get(number, value)


def _speed(speed: str | None, high_speed: str | None) -> str:
    try:
        high = int(high_speed or 0)
        if high > 0:
            return f"{high} Mbps"
    except ValueError:
        pass
    try:
        bits = int(speed or 0)
        if bits >= 1_000_000_000:
            return f"{bits // 1_000_000_000} Gbps"
        if bits >= 1_000_000:
            return f"{bits // 1_000_000} Mbps"
        if bits > 0:
            return f"{bits} bps"
    except ValueError:
        pass
    return "-"


def collect_interfaces_with_diagnostics(host: str, port: int, community: str) -> dict[str, Any]:
    if not community:
        raise ValueError("snmp community not configured")

    walks = {}
    diagnostics = []
    for key, oid in OIDS.items():
        try:
            values = _parse_walk(_snmpwalk(host, port, community, oid), oid)
            walks[key] = values
            diagnostics.append({"oid": key, "source": oid, "count": len(values), "ok": True})
        except Exception as exc:
            walks[key] = {}
            diagnostics.append({"oid": key, "source": oid, "count": 0, "ok": False, "error": str(exc)})

    if not set().union(*(set(values.keys()) for values in walks.values())):
        for key, oid in TEXT_OIDS.items():
            try:
                values = _parse_walk(_snmpwalk(host, port, community, oid), oid)
                if values:
                    walks[key] = values
                diagnostics.append({"oid": key, "source": oid, "count": len(values), "ok": True})
            except Exception as exc:
                diagnostics.append({"oid": key, "source": oid, "count": 0, "ok": False, "error": str(exc)})

    indexes = sorted(set().union(*(set(values.keys()) for values in walks.values())))
    interfaces = []
    for index in indexes:
        name = walks["ifName"].get(index) or walks["ifDescr"].get(index) or f"ifIndex{index}"
        interfaces.append({
            "index": index,
            "name": name,
            "description": walks["ifAlias"].get(index, ""),
            "type": _if_type(walks["ifType"].get(index)),
            "admin": _status(walks["ifAdminStatus"].get(index)),
            "oper": _status(walks["ifOperStatus"].get(index)),
            "speed": _speed(walks["ifSpeed"].get(index), walks["ifHighSpeed"].get(index)),
            "in_octets": walks["ifInOctets"].get(index, "0"),
            "out_octets": walks["ifOutOctets"].get(index, "0"),
            "source": "snmp",
        })

    total_errors = sum(1 for item in diagnostics if not item["ok"])
    return {
        "interfaces": interfaces,
        "diagnostics": diagnostics,
        "errors": total_errors,
        "message": "interfaces collected" if interfaces else "SNMP respondeu, mas nenhuma interface foi encontrada nos OIDs IF-MIB consultados.",
    }


def collect_interfaces(host: str, port: int, community: str) -> list[dict[str, Any]]:
    return collect_interfaces_with_diagnostics(host, port, community)["interfaces"]
