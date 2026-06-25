import re
from typing import Any


COMMAND_ACTIONS = [
    {
        "value": "show_interface",
        "label": "Ver interface",
        "destructive": False,
        "needs_description": False,
    },
    {
        "value": "enable_interface",
        "label": "Ativar porta",
        "destructive": True,
        "needs_description": False,
    },
    {
        "value": "disable_interface",
        "label": "Desativar porta",
        "destructive": True,
        "needs_description": False,
    },
    {
        "value": "set_description",
        "label": "Alterar descricao",
        "destructive": True,
        "needs_description": True,
    },
]


INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*(?:/\d+){1,4}(?:\.\d+)?$")


def validate_interface_name(interface: str) -> str:
    value = (interface or "").strip()
    if not value:
        raise ValueError("interface required")
    if len(value) > 64:
        raise ValueError("interface too long")
    if not INTERFACE_RE.match(value):
        raise ValueError("invalid interface name")
    return value


def validate_description(description: str | None) -> str:
    value = (description or "").strip()
    if len(value) > 120:
        raise ValueError("description too long")
    if any(ch in value for ch in ("\n", "\r")):
        raise ValueError("description cannot contain line breaks")
    return value


def device_uses_commit(device_type: str, model: str = "", vrp_version: str = "") -> bool:
    text = f"{device_type} {model} {vrp_version}".lower()
    return any(marker in text for marker in ("netengine", "ne40", "v800", "bras_bng", "router"))


def build_interface_command_preview(
    *,
    device_type: str,
    interface: str,
    action: str,
    description: str | None = None,
    model: str = "",
    vrp_version: str = "",
) -> dict[str, Any]:
    iface = validate_interface_name(interface)
    desc = validate_description(description)
    commit = device_uses_commit(device_type, model, vrp_version)

    if action not in {item["value"] for item in COMMAND_ACTIONS}:
        raise ValueError("invalid action")

    if action == "show_interface":
        commands = [f"display interface {iface}"]
        destructive = False
    else:
        commands = ["system-view", f"interface {iface}"]
        destructive = True
        if action == "enable_interface":
            commands.append("undo shutdown")
        elif action == "disable_interface":
            commands.append("shutdown")
        elif action == "set_description":
            if not desc:
                raise ValueError("description required")
            commands.append(f"description {desc}")
        if commit:
            commands.append("commit")
        commands.append("quit")
        commands.append("return")

    return {
        "device_type": device_type,
        "interface": iface,
        "action": action,
        "destructive": destructive,
        "requires_confirmation": destructive,
        "uses_commit": commit,
        "commands": commands,
    }
