import re
from typing import List, Dict, Any


def parse_version(output: str) -> Dict[str, Any]:
    out = output or ''
    res = {}
    # try to extract VRP version
    m = re.search(r'VRP \(R\) software, Version\s+([\d\.\w\-]+)', out)
    if m:
        res['vrp_version'] = m.group(1)
    m_full = re.search(r'VRP \(R\) software, Version\s+([^\n]+)', out)
    if m_full:
        res['vrp_release'] = m_full.group(1).strip()
    # hostname may appear as: <hostname>
    m2 = re.search(r'<([\w\-]+)>', out)
    if m2:
        res['hostname'] = m2.group(1)
    # uptime
    m3 = re.search(r'uptime is\s+([^\n]+)', out)
    if m3:
        res['uptime'] = m3.group(1).strip()
    # model line
    m4 = re.search(r'NetEngine\s+([\w\s0-9\-]+)\s+version', out)
    if m4:
        res['model'] = m4.group(1).strip()
    m5 = re.search(r'HUAWEI\s+(.+?)\s+uptime is', out)
    if m5:
        res['model'] = m5.group(1).strip()
    return res


def parse_interface_brief(output: str) -> List[Dict[str, Any]]:
    lines = (output or '').splitlines()
    items: List[Dict[str, Any]] = []
    # common Huawei header lines may be present; find section with column-like data
    # Try to find lines that look like: Interface  PHY   Protocol  ... or look for lines starting with interface names
    for ln in lines:
        ln = ln.strip()
        # skip empty and obvious banners
        if not ln or ln.startswith('display') or ln.startswith('Error:') or ln.startswith('^'):
            continue
        # match interface lines like: Eth0/0/0                     up       up
        m = re.match(r'([A-Za-z0-9\-/\.]+)\s+([a-zA-Z]+)\s+([a-zA-Z]+)(?:\s+(.*))?', ln)
        if m:
            name = m.group(1)
            admin = m.group(2)
            oper = m.group(3)
            rest = (m.group(4) or '').strip()
            items.append({'name': name, 'admin': admin, 'oper': oper, 'extra': rest})
    return items


def parse_logbuffer(output: str) -> List[Dict[str, Any]]:
    lines = (output or '').splitlines()
    logs: List[Dict[str, Any]] = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        # try to capture timestamp-like prefix e.g. 2025-09-08 10:21:33 or [Info]
        m = re.match(r'(?:(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})\s+)?(?:\[?(INFO|WARN|ERROR|DEBUG|NOTICE)\]?\s*)?(.*)', ln, re.I)
        if m:
            ts = m.group(1) or None
            level = (m.group(2) or 'INFO').upper()
            msg = (m.group(3) or '').strip()
            logs.append({'ts': ts, 'level': level, 'msg': msg})
        else:
            logs.append({'ts': None, 'level': 'INFO', 'msg': ln})
    return logs
