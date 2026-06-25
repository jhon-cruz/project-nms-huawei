from typing import Any


DEVICE_LAYOUTS: dict[str, dict[str, Any]] = {
    "S6730-H48X6C": {
        "model": "S6730-H48X6C",
        "label": "Huawei S6730-H48X6C",
        "port_count": 54,
        "groups": [
            {"label": "10GE", "prefix": "10GE1/0/", "start": 1, "count": 48},
            {"label": "100GE", "prefix": "100GE1/0/", "start": 1, "count": 6},
        ],
    },
    "NetEngine 8000 F1A-8H20Q": {
        "model": "NetEngine 8000 F1A-8H20Q",
        "label": "Huawei NetEngine 8000 F1A-8H20Q",
        "port_count": 28,
        "groups": [
            {"label": "10GE", "prefix": "10GE0/1/", "start": 0, "count": 8},
            {"label": "100GE", "prefix": "100GE0/1/", "start": 0, "count": 20},
        ],
    },
    "NE40E-M2H": {
        "model": "NE40E-M2H",
        "label": "Huawei NE40E-M2H",
        "port_count": 16,
        "groups": [
            {"label": "GE", "prefix": "GigabitEthernet0/0/", "start": 0, "count": 8},
            {"label": "10GE", "prefix": "10GE0/1/", "start": 0, "count": 8},
        ],
    },
    "NE40E": {
        "model": "NE40E",
        "label": "Huawei NE40E generico",
        "port_count": 24,
        "groups": [
            {"label": "GE", "prefix": "GigabitEthernet0/0/", "start": 0, "count": 12},
            {"label": "10GE", "prefix": "10GE0/1/", "start": 0, "count": 12},
        ],
    },
}


def list_layouts() -> list[dict[str, Any]]:
    return list(DEVICE_LAYOUTS.values())


def get_layout(model: str) -> dict[str, Any] | None:
    normalized = (model or "").strip().lower()
    for key, layout in DEVICE_LAYOUTS.items():
        if key.lower() == normalized or layout["model"].lower() == normalized:
            return layout
    return None


def expand_ports(layout: dict[str, Any]) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    for group in layout["groups"]:
        for offset in range(group["count"]):
            port_number = group["start"] + offset
            ports.append({
                "name": f"{group['prefix']}{port_number}",
                "group": group["label"],
                "status": "unknown",
            })
    return ports
