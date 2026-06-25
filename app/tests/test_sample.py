import sys
import os
import time
from fastapi.testclient import TestClient

# ensure project root is importable
proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)

from app.main import app
from app.security import hash_password
from app.storage import ensure_default_admin, get_connection, init_db
from app.parsers import parse_version
from app.commands import build_interface_command_preview
from app.bras import build_bras_admin_preview, build_bras_query_command, simplify_auth_failures
from app import snmp_client
from app.snmp_client import _if_type, _parse_walk


def create_test_user(username: str, password: str):
    init_db()
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), "admin"),
        )
        conn.commit()


def cleanup_test_users():
    init_db()
    with get_connection() as conn:
        ids = conn.execute(
            "SELECT id FROM users WHERE username LIKE 'test_%' OR username LIKE 'ban_%'"
        ).fetchall()
        for row in ids:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
        conn.execute("DELETE FROM users WHERE username LIKE 'test_%' OR username LIKE 'ban_%'")
        conn.commit()


def authenticated_client() -> TestClient:
    cleanup_test_users()
    username = f"test_{int(time.time() * 1000)}"
    password = "SenhaTeste123!"
    create_test_user(username, password)
    client = TestClient(app)
    r = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert r.status_code == 200
    return client


def test_sample_version():
    client = TestClient(app)
    r = client.get('/api/sample/version')
    assert r.status_code == 200
    assert 'Versatile Routing Platform' in r.text


def test_parse_vrp_8180_ne40e_version():
    parsed = parse_version("""
Huawei Versatile Routing Platform Software
VRP (R) software, Version 8.180 (NE40E V800R011C00SPC607B607)
Copyright (C) 2012-2018 Huawei Technologies Co., Ltd.
HUAWEI NE40E uptime is 0 day, 0 hour, 33 minutes
SVRP Platform Version 1.0
""")
    assert parsed["vrp_version"] == "8.180"
    assert parsed["model"] == "NE40E"
    assert parsed["uptime"] == "0 day, 0 hour, 33 minutes"


def test_device_create_masks_credentials():
    client = authenticated_client()
    r = client.post('/api/devices', json={
        'name': 'Teste Core',
        'host': '192.0.2.10',
        'description': 'Equipamento de teste',
        'device_type': 'router',
        'ssh_username': 'admin',
        'ssh_password': 'senha-super-secreta',
        'snmp_community': 'community-super-secreta',
    })
    assert r.status_code == 201
    data = r.json()
    assert data['ssh_password_status'] == 'configured'
    assert data['snmp_community_status'] == 'configured'
    assert 'senha-super-secreta' not in r.text
    assert 'community-super-secreta' not in r.text

    client.delete(f"/api/devices/{data['id']}")
    cleanup_test_users()


def test_default_admin_login_exists_when_empty():
    cleanup_test_users()
    ensure_default_admin()
    client = TestClient(app)
    r = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin@nms'})
    assert r.status_code == 200


def test_devices_require_authentication():
    client = TestClient(app)
    r = client.get('/api/devices')
    assert r.status_code == 401


def test_login_fail_ban_after_five_errors():
    cleanup_test_users()
    username = f"ban_{int(time.time() * 1000)}"
    create_test_user(username, "SenhaCorreta123!")
    client = TestClient(app)
    headers = {"x-forwarded-for": f"198.51.100.{int(time.time()) % 200}"}

    for _ in range(4):
        r = client.post('/api/auth/login', json={'username': username, 'password': 'SenhaErrada123!'}, headers=headers)
        assert r.status_code == 401

    r = client.post('/api/auth/login', json={'username': username, 'password': 'SenhaErrada123!'}, headers=headers)
    assert r.status_code == 429

    r = client.post('/api/auth/login', json={'username': username, 'password': 'SenhaCorreta123!'}, headers=headers)
    assert r.status_code == 429
    cleanup_test_users()


def test_command_preview_for_device():
    client = authenticated_client()
    r = client.post('/api/devices', json={
        'name': 'Switch Lab',
        'host': '192.0.2.20',
        'device_type': 'switch',
        'ssh_username': 'admin',
    })
    assert r.status_code == 201
    device_id = r.json()['id']

    preview = client.post(f'/api/devices/{device_id}/command-preview', json={
        'interface': '10GE1/0/1',
        'action': 'disable_interface',
    })
    assert preview.status_code == 200
    data = preview.json()
    assert data['destructive'] is True
    assert data['commands'] == ['system-view', 'interface 10GE1/0/1', 'shutdown', 'quit', 'return']

    audit = client.get('/api/command-audit')
    assert audit.status_code == 200
    assert any(item['interface'] == '10GE1/0/1' for item in audit.json())

    client.delete(f"/api/devices/{device_id}")
    cleanup_test_users()


def test_router_description_command_commits_before_quit():
    preview = build_interface_command_preview(
        device_type='router',
        model='NE40E',
        vrp_version='V800R011C00SPC607B607',
        interface='GigabitEthernet1/0/0',
        action='set_description',
        description='UPLINK-INTERNET',
    )
    assert preview['commands'] == [
        'system-view',
        'interface GigabitEthernet1/0/0',
        'description UPLINK-INTERNET',
        'commit',
        'quit',
        'return',
    ]


def test_snmp_walk_parser_extracts_ifname_indexes():
    parsed = _parse_walk(
        """
.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "GigabitEthernet1/0/0"
.1.3.6.1.2.1.31.1.1.1.1.2 = STRING: "GigabitEthernet1/0/1"
""",
        ".1.3.6.1.2.1.31.1.1.1.1",
    )
    assert parsed == {1: 'GigabitEthernet1/0/0', 2: 'GigabitEthernet1/0/1'}


def test_snmp_if_type_labels_ethernet():
    assert _if_type("INTEGER: ethernetCsmacd(6)") == "ethernetCsmacd"
    assert _if_type("6") == "ethernetCsmacd"


def test_snmp_collect_marks_timeout_as_unreachable(monkeypatch):
    def fail_walk(*args, **kwargs):
        raise RuntimeError("Timeout: No Response from 192.0.2.1")

    monkeypatch.setattr(snmp_client, "_snmpwalk", fail_walk)
    result = snmp_client.collect_interfaces_with_diagnostics("192.0.2.1", 161, "public")
    assert result["reachable"] is False
    assert "Sem resposta SNMP" in result["message"]
    assert result["interfaces"] == []


def test_layout_catalog_requires_auth_and_returns_models():
    client = TestClient(app)
    assert client.get('/api/device-layouts').status_code == 401

    client = authenticated_client()
    r = client.get('/api/device-layouts')
    assert r.status_code == 200
    models = {item['model'] for item in r.json()}
    assert 'S6730-H48X6C' in models
    cleanup_test_users()


def test_login_page_does_not_expose_default_password():
    client = TestClient(app)
    r = client.get('/')
    assert r.status_code == 200
    assert 'admin@nms' not in r.text


def test_database_status_requires_auth():
    client = TestClient(app)
    assert client.get('/api/system/database').status_code == 401

    client = authenticated_client()
    r = client.get('/api/system/database')
    assert r.status_code == 200
    assert r.json()['engine'] == 'sqlite'
    cleanup_test_users()


def test_command_execute_requires_confirmation():
    client = authenticated_client()
    r = client.post('/api/devices', json={
        'name': 'Router Exec Lab',
        'host': '192.0.2.30',
        'device_type': 'router',
        'ssh_username': 'admin',
        'ssh_password': 'admin',
    })
    assert r.status_code == 201
    device_id = r.json()['id']

    execute = client.post(f'/api/devices/{device_id}/command-execute', json={
        'interface': 'GE0/0/0',
        'action': 'show_interface',
        'confirm': False,
    })
    assert execute.status_code == 400

    client.delete(f"/api/devices/{device_id}")
    cleanup_test_users()


def test_bras_query_builds_safe_subscriber_commands():
    query = build_bras_query_command("user_ip", "100.64.0.1")
    assert query["commands"] == ["display access-user ip-address 100.64.0.1"]
    assert query["destructive"] is False

    query = build_bras_query_command("vlan_total", "1000")
    assert query["commands"] == ["display access-user online-total-number pevlan 1000 brief"]


def test_bras_rejects_unsafe_parameters():
    try:
        build_bras_query_command("user_verbose", "cliente\nreset saved-configuration")
        assert False, "unsafe username should fail"
    except ValueError:
        pass

    try:
        build_bras_query_command("vlan_total", "5000")
        assert False, "invalid vlan should fail"
    except ValueError:
        pass


def test_bras_admin_preview_for_cut_user():
    preview = build_bras_admin_preview("cut_user", "cliente@isp")
    assert preview["destructive"] is True
    assert preview["commands"] == [
        "system-view",
        "aaa",
        "cut access-user username cliente@isp radius",
        "quit",
        "return",
    ]


def test_bras_pool_priority_preview_commits():
    preview = build_bras_admin_preview("move_pool_priority", "pool_ftth,NOMEPOOL,3")
    assert preview["commands"] == [
        "system-view",
        "ip pool-group pool_ftth bas",
        "ip-pool NOMEPOOL move-to 3",
        "commit",
        "quit",
        "return",
    ]


def test_auth_failure_simplifier_labels_common_reasons():
    parsed = simplify_auth_failures("""
User-name : cliente01
MAC address : aa:bb:cc:dd:ee:ff
Fail reason : Radius timeout

Username = cliente02
Fail reason : password error
""")
    reasons = [item["reason"] for item in parsed]
    assert "Radius sem resposta ou timeout" in reasons
    assert "Senha PPPoE incorreta ou metodo de autenticacao rejeitado" in reasons


def test_bras_action_execute_requires_admin_and_confirmation():
    client = authenticated_client()
    r = client.post('/api/devices', json={
        'name': 'BRAS Lab',
        'host': '192.0.2.40',
        'device_type': 'bras_bng',
        'ssh_username': 'admin',
        'ssh_password': 'admin',
    })
    assert r.status_code == 201
    device_id = r.json()['id']

    execute = client.post(f'/api/devices/{device_id}/bras/action-execute', json={
        'action': 'cut_user',
        'value': 'cliente@isp',
        'confirm': False,
    })
    assert execute.status_code == 400

    client.delete(f"/api/devices/{device_id}")
    cleanup_test_users()
