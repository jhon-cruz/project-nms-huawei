import ipaddress
import re
from typing import Any


PARAM_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,80}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,80}$")
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:/\d+){1,4}(?:\.\d+)?$")


BRAS_QUERY_ACTIONS = [
    {"value": "online_total", "label": "Total online", "param_label": "", "requires_param": False},
    {"value": "online_ipv4", "label": "Total IPv4", "param_label": "", "requires_param": False},
    {"value": "online_ipv6", "label": "Total IPv6", "param_label": "", "requires_param": False},
    {"value": "online_dual", "label": "Total dual-stack", "param_label": "", "requires_param": False},
    {"value": "user_verbose", "label": "Assinante por login", "param_label": "Login PPPoE", "requires_param": True},
    {"value": "user_ip", "label": "Assinante por IP", "param_label": "IPv4 ou IPv6", "requires_param": True},
    {"value": "user_mac", "label": "Assinante por MAC", "param_label": "MAC address", "requires_param": True},
    {"value": "domain_users", "label": "Usuarios por dominio", "param_label": "Dominio", "requires_param": True},
    {"value": "vlan_total", "label": "Total por VLAN", "param_label": "VLAN", "requires_param": True},
    {"value": "qos_profile", "label": "Usuarios por QoS", "param_label": "QoS profile", "requires_param": True},
    {"value": "qos_inbound", "label": "QoS upload", "param_label": "QoS profile", "requires_param": True},
    {"value": "qos_outbound", "label": "QoS download", "param_label": "QoS profile", "requires_param": True},
    {"value": "ip_pool_usage", "label": "Uso de pools", "param_label": "", "requires_param": False},
    {"value": "ip_pool_detail", "label": "Detalhe de pool", "param_label": "Nome do pool", "requires_param": True},
    {"value": "radius_config", "label": "Configuracao Radius", "param_label": "", "requires_param": False},
    {"value": "radius_auth_packets", "label": "Pacotes Radius auth", "param_label": "IP do Radius", "requires_param": True},
    {"value": "radius_acct_packets", "label": "Pacotes Radius accounting", "param_label": "IP do Radius", "requires_param": True},
    {"value": "aaa_fail_record", "label": "Falhas AAA", "param_label": "Login opcional", "requires_param": False},
    {"value": "aaa_offline_record", "label": "Desconexoes AAA", "param_label": "Login opcional", "requires_param": False},
    {"value": "pppoe_interface", "label": "PPPoE por interface", "param_label": "Interface", "requires_param": True},
    {"value": "clock", "label": "Hora do equipamento", "param_label": "", "requires_param": False},
    {"value": "arp_interface", "label": "ARP por interface", "param_label": "Interface", "requires_param": True},
]


BRAS_ADMIN_ACTIONS = [
    {"value": "cut_user", "label": "Derrubar assinante por login", "param_label": "Login PPPoE", "requires_param": True},
    {"value": "cut_domain", "label": "Derrubar dominio", "param_label": "Dominio", "requires_param": True},
    {"value": "cut_ipv4", "label": "Derrubar por IPv4", "param_label": "IPv4", "requires_param": True},
    {"value": "cut_ipv6", "label": "Derrubar por IPv6", "param_label": "IPv6", "requires_param": True},
    {"value": "cut_pool", "label": "Derrubar pool IPv4", "param_label": "Pool IPv4", "requires_param": True},
    {"value": "cut_ipv6_pool", "label": "Derrubar pool IPv6", "param_label": "Pool IPv6", "requires_param": True},
    {"value": "cut_radius", "label": "Derrubar autenticados via Radius", "param_label": "", "requires_param": False},
    {"value": "reset_pppoe_interface", "label": "Reset estatisticas PPPoE da interface", "param_label": "Interface", "requires_param": True},
    {"value": "reset_pppoe_fail_slot", "label": "Reset falhas PPPoE por slot", "param_label": "Slot", "requires_param": True},
    {"value": "reset_arp_all", "label": "Reset ARP dinamico", "param_label": "", "requires_param": False},
    {"value": "reset_arp_static", "label": "Reset ARP estatico", "param_label": "", "requires_param": False},
    {"value": "move_pool_priority", "label": "Alterar prioridade de pool", "param_label": "pool-group,pool,posicao", "requires_param": True},
]


def _required(value: str | None, label: str = "parametro") -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError(f"{label} required")
    if len(cleaned) > 80:
        raise ValueError(f"{label} too long")
    return cleaned


def _safe_token(value: str | None, label: str = "parametro", required: bool = True) -> str:
    cleaned = _required(value, label) if required else (value or "").strip()
    if cleaned and not PARAM_RE.match(cleaned):
        raise ValueError(f"invalid {label}")
    return cleaned


def _username(value: str | None, required: bool = True) -> str:
    cleaned = _required(value, "username") if required else (value or "").strip()
    if cleaned and not USERNAME_RE.match(cleaned):
        raise ValueError("invalid username")
    return cleaned


def _ip(value: str | None, version: int | None = None) -> str:
    cleaned = _required(value, "ip")
    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError("invalid ip") from exc
    if version and parsed.version != version:
        raise ValueError(f"invalid ipv{version}")
    return str(parsed)


def _mac(value: str | None) -> str:
    cleaned = _required(value, "mac")
    if not MAC_RE.match(cleaned):
        raise ValueError("invalid mac")
    return cleaned


def _vlan(value: str | None) -> str:
    cleaned = _required(value, "vlan")
    if not cleaned.isdigit():
        raise ValueError("invalid vlan")
    number = int(cleaned)
    if number < 1 or number > 4094:
        raise ValueError("invalid vlan")
    return str(number)


def _slot(value: str | None) -> str:
    cleaned = _required(value, "slot")
    if not cleaned.isdigit() or int(cleaned) < 0 or int(cleaned) > 31:
        raise ValueError("invalid slot")
    return str(int(cleaned))


def _interface(value: str | None) -> str:
    cleaned = _required(value, "interface")
    if len(cleaned) > 64 or not INTERFACE_RE.match(cleaned):
        raise ValueError("invalid interface")
    return cleaned


def _pool_priority(value: str | None) -> tuple[str, str, str]:
    cleaned = _required(value, "pool priority")
    parts = [part.strip() for part in cleaned.split(",")]
    if len(parts) != 3:
        raise ValueError("use pool-group,pool,posicao")
    group = _safe_token(parts[0], "pool group")
    pool = _safe_token(parts[1], "pool")
    position = parts[2]
    if not position.isdigit() or int(position) < 1 or int(position) > 1024:
        raise ValueError("invalid pool position")
    return group, pool, str(int(position))


def build_bras_query_command(action: str, value: str | None = "") -> dict[str, Any]:
    if action == "online_total":
        command = "display access-user online-total-number"
    elif action == "online_ipv4":
        command = "display access-user online-total-number ipv4"
    elif action == "online_ipv6":
        command = "display access-user online-total-number ipv6"
    elif action == "online_dual":
        command = "display access-user online-total-number dual"
    elif action == "user_verbose":
        command = f"display access-user username {_username(value)} verbose"
    elif action == "user_ip":
        command = f"display access-user ip-address {_ip(value)}"
    elif action == "user_mac":
        command = f"display access-user mac-address {_mac(value)}"
    elif action == "domain_users":
        command = f"display access-user domain {_safe_token(value, 'domain')}"
    elif action == "vlan_total":
        command = f"display access-user online-total-number pevlan {_vlan(value)} brief"
    elif action == "qos_profile":
        command = f"display access-user qos-profile {_safe_token(value, 'qos profile')}"
    elif action == "qos_inbound":
        command = f"display access-user qos-profile {_safe_token(value, 'qos profile')} inbound"
    elif action == "qos_outbound":
        command = f"display access-user qos-profile {_safe_token(value, 'qos profile')} outbound"
    elif action == "ip_pool_usage":
        command = "display ip-pool pool-usage all"
    elif action == "ip_pool_detail":
        command = f"display ip pool name {_safe_token(value, 'pool')}"
    elif action == "radius_config":
        command = "display radius-server configuration"
    elif action == "radius_auth_packets":
        command = f"display radius-server packet ip-address {_ip(value)} 1812 authentication"
    elif action == "radius_acct_packets":
        command = f"display radius-server packet ip-address {_ip(value)} 1813 accounting"
    elif action == "aaa_fail_record":
        user = _username(value, required=False)
        command = f"display aaa online-fail-record username {user}" if user else "display aaa online-fail-record"
    elif action == "aaa_offline_record":
        user = _username(value, required=False)
        command = f"display aaa offline-record username {user}" if user else "display aaa offline-record"
    elif action == "pppoe_interface":
        command = f"display pppoe statistics interface {_interface(value)}"
    elif action == "clock":
        command = "display clock"
    elif action == "arp_interface":
        command = f"display arp interface {_interface(value)}"
    else:
        raise ValueError("invalid bras query")
    return {"action": action, "commands": [command], "destructive": False}


def build_bras_admin_preview(action: str, value: str | None = "") -> dict[str, Any]:
    if action == "cut_user":
        commands = ["system-view", "aaa", f"cut access-user username {_username(value)} radius", "quit", "return"]
    elif action == "cut_domain":
        commands = ["system-view", "aaa", f"cut access-user domain {_safe_token(value, 'domain')}", "quit", "return"]
    elif action == "cut_ipv4":
        commands = ["system-view", "aaa", f"cut access-user ip-address {_ip(value, 4)}", "quit", "return"]
    elif action == "cut_ipv6":
        commands = ["system-view", "aaa", f"cut access-user ipv6-address {_ip(value, 6)}", "quit", "return"]
    elif action == "cut_pool":
        commands = ["system-view", "aaa", f"cut access-user ip-pool {_safe_token(value, 'pool')}", "quit", "return"]
    elif action == "cut_ipv6_pool":
        commands = ["system-view", "aaa", f"cut access-user ipv6-pool {_safe_token(value, 'pool')}", "quit", "return"]
    elif action == "cut_radius":
        commands = ["system-view", "aaa", "cut access-user authen-method radius", "quit", "return"]
    elif action == "reset_pppoe_interface":
        commands = [f"reset pppoe statistics interface {_interface(value)}"]
    elif action == "reset_pppoe_fail_slot":
        commands = [f"reset pppoe statistics online-fail-record slot {_slot(value)}"]
    elif action == "reset_arp_all":
        commands = ["reset arp all"]
    elif action == "reset_arp_static":
        commands = ["reset arp static"]
    elif action == "move_pool_priority":
        group, pool, position = _pool_priority(value)
        commands = ["system-view", f"ip pool-group {group} bas", f"ip-pool {pool} move-to {position}", "commit", "quit", "return"]
    else:
        raise ValueError("invalid bras admin action")
    return {
        "action": action,
        "commands": commands,
        "destructive": True,
        "requires_confirmation": True,
    }


def simplify_auth_failures(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    blocks = re.split(r"\n\s*\n", output or "")
    for block in blocks:
        text = block.strip()
        if not text:
            continue
        lower = text.lower()
        if not any(marker in lower for marker in ("fail", "error", "reject", "timeout", "radius", "password", "mac", "username", "user-name")):
            continue
        reason = "Falha de autenticacao"
        if "timeout" in lower or "time out" in lower or "no response" in lower:
            reason = "Radius sem resposta ou timeout"
        elif "password" in lower or "chap" in lower or "pap" in lower:
            reason = "Senha PPPoE incorreta ou metodo de autenticacao rejeitado"
        elif "mac" in lower:
            reason = "MAC diferente do esperado ou bloqueado no Radius"
        elif "not exist" in lower or "no such user" in lower or "unknown user" in lower or "username" in lower or "user-name" in lower:
            reason = "Login PPPoE inexistente ou rejeitado"
        elif "reject" in lower or "rejected" in lower or "deny" in lower:
            reason = "Radius rejeitou a autenticacao"
        elif "domain" in lower:
            reason = "Dominio PPPoE incorreto ou sem perfil valido"

        username_match = re.search(r"(?:username|user-name|user name)\s*[:=]?\s*([A-Za-z0-9_.:@+-]+)", text, re.I)
        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}", text)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        entries.append({
            "reason": reason,
            "username": username_match.group(1) if username_match else "",
            "mac": mac_match.group(0) if mac_match else "",
            "ip": ip_match.group(0) if ip_match else "",
            "raw": text[:1200],
        })
    return entries[:20]
