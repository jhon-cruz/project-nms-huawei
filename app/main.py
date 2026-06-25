from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, conint, constr
from typing import Optional
import paramiko
from .bras import (
    BRAS_ADMIN_ACTIONS,
    BRAS_QUERY_ACTIONS,
    build_bras_admin_preview,
    build_bras_query_command,
    simplify_auth_failures,
)
from .commands import COMMAND_ACTIONS, build_interface_command_preview
from .layouts import expand_ports, get_layout, list_layouts
from .snmp_client import collect_interfaces, collect_interfaces_with_diagnostics
from .ssh_client import SSHClientWrapper
from .storage import (
    DB_PATH,
    DEVICE_TYPES,
    authenticate_user,
    create_command_audit_log,
    create_device,
    create_initial_user,
    create_session,
    delete_device,
    delete_session,
    ensure_default_admin,
    get_device,
    get_device_private,
    get_login_ban,
    get_session_user,
    init_db,
    list_command_audit_logs,
    list_devices,
    list_users,
    create_user,
    update_user,
    delete_user,
    update_device,
    users_exist,
)
from .system_update import system_status, update_from_git
import os
import logging
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('netengine-poc')

app = FastAPI(title="NetEngine POC API")

# mount static UI
pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
static_dir = os.path.join(pkg_root, 'static')
app.mount('/static', StaticFiles(directory=static_dir, html=True), name='static')


@app.on_event("startup")
async def startup_event():
    init_db()
    ensure_default_admin()


@app.get('/', response_class=HTMLResponse)
async def index():
    idx = os.path.join(static_dir, 'index.html')
    return FileResponse(
        idx,
        media_type='text/html',
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get('/main.js')
async def main_js_alias():
    return FileResponse(
        os.path.join(static_dir, 'main.js'),
        media_type='application/javascript',
        headers={"Cache-Control": "no-store"},
    )


@app.get('/styles.css')
async def styles_css_alias():
    return FileResponse(
        os.path.join(static_dir, 'styles.css'),
        media_type='text/css',
        headers={"Cache-Control": "no-store"},
    )


class ConnectPayload(BaseModel):
    host: constr(strip_whitespace=True, min_length=1, max_length=253)
    username: constr(strip_whitespace=True, min_length=1, max_length=64)
    password: constr(min_length=1, max_length=128)
    port: conint(ge=1, le=65535) = 22


class DevicePayload(BaseModel):
    name: Optional[constr(strip_whitespace=True, max_length=80)] = None
    host: constr(strip_whitespace=True, min_length=1, max_length=253)
    description: Optional[constr(strip_whitespace=True, max_length=500)] = ""
    device_type: str = "other"
    ssh_username: Optional[constr(strip_whitespace=True, max_length=64)] = ""
    ssh_password: Optional[constr(max_length=128)] = ""
    ssh_port: Optional[conint(ge=1, le=65535)] = 22
    snmp_community: Optional[constr(max_length=128)] = ""
    snmp_port: Optional[conint(ge=1, le=65535)] = 161
    model: Optional[constr(strip_whitespace=True, max_length=80)] = ""
    vrp_version: Optional[constr(strip_whitespace=True, max_length=80)] = ""
    notes: Optional[constr(strip_whitespace=True, max_length=1000)] = ""


class AuthPayload(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=64)
    password: constr(min_length=8, max_length=128)


class CommandPreviewPayload(BaseModel):
    interface: constr(strip_whitespace=True, min_length=1, max_length=64)
    action: constr(strip_whitespace=True, min_length=1, max_length=40)
    description: Optional[constr(strip_whitespace=True, max_length=120)] = ""


class CommandExecutePayload(CommandPreviewPayload):
    confirm: bool = False
    timeout: conint(ge=3, le=30) = 8


class InterfacePayload(BaseModel):
    interface: constr(strip_whitespace=True, min_length=1, max_length=64)


class BrasQueryPayload(BaseModel):
    action: constr(strip_whitespace=True, min_length=1, max_length=40)
    value: Optional[constr(strip_whitespace=True, max_length=80)] = ""
    timeout: conint(ge=3, le=30) = 10


class BrasActionPayload(BrasQueryPayload):
    confirm: bool = False


class UserPayload(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=64)
    password: constr(min_length=8, max_length=128)
    role: constr(strip_whitespace=True, min_length=5, max_length=7) = "leitura"


class UserUpdatePayload(BaseModel):
    password: Optional[constr(max_length=128)] = ""
    role: Optional[constr(strip_whitespace=True, min_length=5, max_length=7)] = None


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def require_user(request: Request) -> dict:
    user = get_session_user(request.cookies.get("nms_session"))
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def require_admin(request: Request) -> dict:
    user = require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin permission required")
    return user


def ssh_error_detail(exc: Exception, device: dict) -> dict:
    base = {
        "message": str(exc) or exc.__class__.__name__,
        "error_type": exc.__class__.__name__,
        "host": device.get("host"),
        "port": device.get("ssh_port"),
        "username": device.get("ssh_username"),
    }
    if isinstance(exc, paramiko.AuthenticationException):
        base["hint"] = "Falha de autenticacao. Confirme usuario/senha no cadastro; acesso por chave/agent no terminal nao e usado pelo sistema."
    elif isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
        base["hint"] = "Nao foi possivel abrir TCP na porta SSH a partir do servidor da aplicacao."
    elif isinstance(exc, (socket.timeout, TimeoutError)):
        base["hint"] = "Timeout ao conectar ou aguardar banner/autenticacao SSH."
    elif isinstance(exc, paramiko.SSHException):
        base["hint"] = "Falha no protocolo SSH. Pode haver incompatibilidade de algoritmo, banner ou shell interativo do equipamento."
    else:
        base["hint"] = "A conexao autenticou, mas falhou ao abrir shell ou executar o comando de teste."
    return base


@app.get('/api/auth/status')
async def auth_status(request: Request):
    user = get_session_user(request.cookies.get("nms_session"))
    return JSONResponse({
        "authenticated": bool(user),
        "setup_required": not users_exist(),
        "user": user,
    })


@app.post('/api/auth/setup')
async def auth_setup(payload: AuthPayload, request: Request, response: Response):
    if users_exist():
        raise HTTPException(status_code=409, detail="initial user already exists")
    user = create_initial_user(payload.username, payload.password)
    token = create_session(user["id"])
    response = JSONResponse({"user": user}, status_code=201)
    response.set_cookie(
        "nms_session",
        token,
        httponly=True,
        samesite="strict",
        max_age=8 * 60 * 60,
    )
    return response


@app.post('/api/auth/login')
async def auth_login(payload: AuthPayload, request: Request):
    ip = client_ip(request)
    ban = get_login_ban(ip)
    if ban["banned"]:
        raise HTTPException(
            status_code=429,
            detail=f"IP bloqueado temporariamente. Tente novamente em {ban['remaining_seconds']} segundos.",
        )

    user, auth_state = authenticate_user(payload.username, payload.password, ip)
    if not user:
        if auth_state["banned"]:
            raise HTTPException(
                status_code=429,
                detail=f"IP bloqueado temporariamente. Tente novamente em {auth_state['remaining_seconds']} segundos.",
            )
        raise HTTPException(status_code=401, detail="usuario ou senha invalidos")

    token = create_session(user["id"])
    response = JSONResponse({"user": user})
    response.set_cookie(
        "nms_session",
        token,
        httponly=True,
        samesite="strict",
        max_age=8 * 60 * 60,
    )
    return response


@app.post('/api/auth/logout')
async def auth_logout(request: Request):
    delete_session(request.cookies.get("nms_session"))
    response = JSONResponse({"ok": True})
    response.delete_cookie("nms_session")
    return response


@app.get('/api/users')
async def users_list(user: dict = Depends(require_admin)):
    return JSONResponse(list_users())


@app.post('/api/users')
async def users_create(payload: UserPayload, user: dict = Depends(require_admin)):
    try:
        created = create_user(payload.dict())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return JSONResponse(created, status_code=201)


@app.put('/api/users/{user_id}')
async def users_update(user_id: int, payload: UserUpdatePayload, user: dict = Depends(require_admin)):
    try:
        updated = update_user(user_id, payload.dict())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail="user not found")
    return JSONResponse(updated)


@app.delete('/api/users/{user_id}')
async def users_delete(user_id: int, user: dict = Depends(require_admin)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="cannot remove current user")
    try:
        deleted = delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not deleted:
        raise HTTPException(status_code=404, detail="user not found")
    return JSONResponse({"ok": True})


@app.get('/api/device-types')
async def device_types(user: dict = Depends(require_user)):
    return JSONResponse(DEVICE_TYPES)


@app.get('/api/system/database')
async def database_status(user: dict = Depends(require_user)):
    return JSONResponse({
        "engine": "sqlite",
        "path": str(DB_PATH),
        "exists": DB_PATH.exists(),
        "size_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
    })


@app.get('/api/system/status')
async def system_runtime_status(user: dict = Depends(require_user)):
    return JSONResponse(system_status())


@app.post('/api/system/update')
async def system_runtime_update(user: dict = Depends(require_admin)):
    try:
        result = update_from_git()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    status_code = 200 if result.get("ok") else 500
    return JSONResponse(result, status_code=status_code)


@app.get('/api/command-actions')
async def command_actions(user: dict = Depends(require_user)):
    return JSONResponse(COMMAND_ACTIONS)


@app.get('/api/bras/actions')
async def bras_actions(user: dict = Depends(require_user)):
    return JSONResponse({"queries": BRAS_QUERY_ACTIONS, "admin_actions": BRAS_ADMIN_ACTIONS})


@app.get('/api/command-audit')
async def command_audit(
    user: dict = Depends(require_admin),
    limit: int = 30,
    device_id: int = None,
    date_from: str = None,
    date_to: str = None,
):
    return JSONResponse(list_command_audit_logs(limit, device_id, date_from, date_to))


@app.get('/api/device-layouts')
async def device_layouts(user: dict = Depends(require_user)):
    return JSONResponse(list_layouts())


@app.get('/api/devices')
async def devices_list(user: dict = Depends(require_user)):
    return JSONResponse(list_devices())


@app.post('/api/devices')
async def devices_create(payload: DevicePayload, user: dict = Depends(require_admin)):
    try:
        device = create_device(payload.dict())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return JSONResponse(device, status_code=201)


@app.get('/api/devices/{device_id}')
async def devices_get(device_id: int, user: dict = Depends(require_user)):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    return JSONResponse(device)


@app.get('/api/devices/{device_id}/layout')
async def devices_layout(device_id: int, user: dict = Depends(require_user)):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    layout = get_layout(device.get("model", ""))
    if not layout:
        raise HTTPException(status_code=404, detail='layout not found for device model')
    return JSONResponse({**layout, "ports": expand_ports(layout)})


@app.put('/api/devices/{device_id}')
async def devices_update(device_id: int, payload: DevicePayload, user: dict = Depends(require_admin)):
    try:
        device = update_device(device_id, payload.dict())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    return JSONResponse(device)


@app.delete('/api/devices/{device_id}')
async def devices_delete(device_id: int, user: dict = Depends(require_admin)):
    if not delete_device(device_id):
        raise HTTPException(status_code=404, detail='device not found')
    return JSONResponse({'ok': True})


@app.post('/api/devices/{device_id}/ssh-test')
async def device_ssh_test(device_id: int, user: dict = Depends(require_user)):
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    if not device["ssh_username"] or not device["ssh_password"]:
        raise HTTPException(status_code=400, detail='ssh credentials not configured')

    wrapper = SSHClientWrapper(device["host"], device["ssh_port"], device["ssh_username"], device["ssh_password"])
    try:
        wrapper.connect(timeout=10)
        output = wrapper.run('display version', timeout=8)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=ssh_error_detail(exc, device))
    finally:
        wrapper.close()

    from .parsers import parse_version
    return JSONResponse({"ok": True, "summary": parse_version(output), "output": output[:4000]})


@app.post('/api/devices/{device_id}/snmp-test')
async def device_snmp_test(device_id: int, user: dict = Depends(require_user)):
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    if not device["snmp_community"]:
        raise HTTPException(status_code=400, detail='snmp community not configured')
    try:
        result = collect_interfaces_with_diagnostics(device["host"], device["snmp_port"], device["snmp_community"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'SNMP test failed: {exc}')
    return JSONResponse({
        "ok": True,
        "count": len(result["interfaces"]),
        "interfaces": result["interfaces"][:10],
        "diagnostics": result["diagnostics"],
        "message": result["message"],
    })


@app.get('/api/devices/{device_id}/interfaces')
async def device_interfaces(device_id: int, user: dict = Depends(require_user)):
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    if not device["snmp_community"]:
        raise HTTPException(status_code=400, detail='snmp community not configured')
    try:
        result = collect_interfaces_with_diagnostics(device["host"], device["snmp_port"], device["snmp_community"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'SNMP collect failed: {exc}')
    return JSONResponse({
        "device": get_device(device_id),
        "interfaces": result["interfaces"],
        "diagnostics": result["diagnostics"],
        "message": result["message"],
    })


@app.post('/api/devices/{device_id}/interface-config')
async def device_interface_config(device_id: int, payload: InterfacePayload, request: Request, user: dict = Depends(require_user)):
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    if not device["ssh_username"] or not device["ssh_password"]:
        raise HTTPException(status_code=400, detail='ssh credentials not configured')

    command = f"display current interface {payload.interface}"
    wrapper = SSHClientWrapper(device["host"], device["ssh_port"], device["ssh_username"], device["ssh_password"])
    try:
        wrapper.connect(timeout=10)
        output = wrapper.run(command, timeout=8)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'SSH command failed: {exc}')
    finally:
        wrapper.close()

    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action="show_interface_config",
        interface_name=payload.interface,
        commands_preview=[command],
        executed=True,
        source_ip=client_ip(request),
    )
    return JSONResponse({"interface": payload.interface, "command": command, "output": output})


def _run_device_commands(device: dict, commands: list[str], timeout: int = 10) -> list[dict[str, str]]:
    if not device["ssh_username"] or not device["ssh_password"]:
        raise HTTPException(status_code=400, detail='ssh credentials not configured')

    wrapper = SSHClientWrapper(device["host"], device["ssh_port"], device["ssh_username"], device["ssh_password"])
    outputs = []
    try:
        wrapper.connect(timeout=10)
        for command in commands:
            command_timeout = timeout
            if command in {"system-view", "aaa", "quit", "return"} or command.startswith(("cut access-user ", "ip pool-group ", "ip-pool ")):
                command_timeout = min(timeout, 3)
            if command == "commit":
                command_timeout = max(timeout, 8)
            outputs.append({
                "command": command,
                "output": wrapper.run(command, timeout=command_timeout),
            })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'SSH command failed: {exc}')
    finally:
        wrapper.close()
    return outputs


@app.post('/api/devices/{device_id}/bras/query')
async def device_bras_query(device_id: int, payload: BrasQueryPayload, request: Request, user: dict = Depends(require_user)):
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    try:
        preview = build_bras_query_command(payload.action, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    outputs = _run_device_commands(device, preview["commands"], timeout=payload.timeout)
    raw_output = "\n\n".join(f"$ {item['command']}\n{item['output'] or ''}" for item in outputs)
    simplified = simplify_auth_failures(raw_output) if payload.action == "aaa_fail_record" else []

    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action=f"bras_query:{payload.action}",
        interface_name=payload.value or "",
        commands_preview=preview["commands"],
        executed=True,
        source_ip=client_ip(request),
    )
    return JSONResponse({"ok": True, "preview": preview, "outputs": outputs, "simplified": simplified})


@app.post('/api/devices/{device_id}/bras/action-preview')
async def device_bras_action_preview(device_id: int, payload: BrasActionPayload, request: Request, user: dict = Depends(require_admin)):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    try:
        preview = build_bras_admin_preview(payload.action, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action=f"bras_preview:{payload.action}",
        interface_name=payload.value or "",
        commands_preview=preview["commands"],
        executed=False,
        source_ip=client_ip(request),
    )
    return JSONResponse(preview)


@app.post('/api/devices/{device_id}/bras/action-execute')
async def device_bras_action_execute(device_id: int, payload: BrasActionPayload, request: Request, user: dict = Depends(require_admin)):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail='confirmation required')
    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    try:
        preview = build_bras_admin_preview(payload.action, payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    outputs = _run_device_commands(device, preview["commands"], timeout=payload.timeout)
    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action=f"bras_execute:{payload.action}",
        interface_name=payload.value or "",
        commands_preview=preview["commands"],
        executed=True,
        source_ip=client_ip(request),
    )
    return JSONResponse({"ok": True, "preview": preview, "outputs": outputs})


@app.post('/api/devices/{device_id}/command-preview')
async def device_command_preview(device_id: int, payload: CommandPreviewPayload, request: Request, user: dict = Depends(require_admin)):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    try:
        preview = build_interface_command_preview(
            device_type=device["device_type"],
            interface=payload.interface,
            action=payload.action,
            description=payload.description,
            model=device.get("model", ""),
            vrp_version=device.get("vrp_version", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action=payload.action,
        interface_name=preview["interface"],
        commands_preview=preview["commands"],
        executed=False,
        source_ip=client_ip(request),
    )
    return JSONResponse(preview)


@app.post('/api/devices/{device_id}/command-execute')
async def device_command_execute(device_id: int, payload: CommandExecutePayload, request: Request, user: dict = Depends(require_admin)):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail='confirmation required')

    device = get_device_private(device_id)
    if not device:
        raise HTTPException(status_code=404, detail='device not found')
    if not device["ssh_username"] or not device["ssh_password"]:
        raise HTTPException(status_code=400, detail='ssh credentials not configured')

    try:
        preview = build_interface_command_preview(
            device_type=device["device_type"],
            interface=payload.interface,
            action=payload.action,
            description=payload.description,
            model=device.get("model", ""),
            vrp_version=device.get("vrp_version", ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    wrapper = SSHClientWrapper(device["host"], device["ssh_port"], device["ssh_username"], device["ssh_password"])
    outputs = []
    try:
        wrapper.connect(timeout=10)
        for command in preview["commands"]:
            command_timeout = payload.timeout
            if command in {"system-view", "quit", "return"} or command.startswith(("interface ", "description ", "shutdown", "undo shutdown")):
                command_timeout = min(payload.timeout, 2)
            if command == "commit":
                command_timeout = max(payload.timeout, 8)
            outputs.append({
                "command": command,
                "output": wrapper.run(command, timeout=command_timeout),
            })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'SSH command failed: {exc}')
    finally:
        wrapper.close()

    create_command_audit_log(
        user_id=user["id"],
        device_id=device_id,
        action=payload.action,
        interface_name=preview["interface"],
        commands_preview=preview["commands"],
        executed=True,
        source_ip=client_ip(request),
    )
    return JSONResponse({"ok": True, "preview": preview, "outputs": outputs})


@app.post('/api/run')
async def run_command(payload: ConnectPayload, user: dict = Depends(require_user)):
    """Connect via SSH and run a few diagnostic commands."""
    wrapper = SSHClientWrapper(payload.host, payload.port, payload.username, payload.password)
    try:
        wrapper.connect(timeout=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSH connect failed: {e}")

    try:
        version = wrapper.run('display version')
        interfaces = wrapper.run('display interface brief')
        # fallback: some devices may reject 'display interface brief'
        if interfaces and ('Unrecognized command' in interfaces or 'Error: Unrecognized command' in interfaces):
            logger.info('display interface brief rejected, trying fallback')
            interfaces = wrapper.run('display interface')

        # correct log command: include 'size'
        logs = wrapper.run('display logbuffer size 50')
    finally:
        # ensure we always close the connection
        wrapper.close()

    # log outputs server-side (no credentials)
    logger.debug('version output:\n%s', version)
    logger.debug('interfaces output:\n%s', interfaces)
    logger.debug('logs output:\n%s', logs)

    return JSONResponse({
        'version': version,
        'interfaces': interfaces,
        'logs': logs,
    })



@app.get('/api/summary')
async def summary(
    payload_host: str = None,
    payload_user: str = None,
    payload_pass: str = None,
    port: int = 22,
    user: dict = Depends(require_user),
):
    """Connects using provided query parameters (optional) and returns structured JSON summary.
    If no host is provided, returns 400.
    """
    # minimal: require host
    if not payload_host:
        raise HTTPException(status_code=400, detail='host required')
    wrapper = SSHClientWrapper(payload_host, port, payload_user or '', payload_pass or '')
    try:
        wrapper.connect(timeout=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'SSH connect failed: {e}')
    try:
        version = wrapper.run('display version')
        interfaces_raw = wrapper.run('display interface brief')
        if 'Unrecognized command' in interfaces_raw:
            interfaces_raw = wrapper.run('display interface')
        logs_raw = wrapper.run('display logbuffer size 50')
    finally:
        wrapper.close()

    # parse using parsers
    from .parsers import parse_version, parse_interface_brief, parse_logbuffer
    parsed = {
        'device': parse_version(version),
        'interfaces': parse_interface_brief(interfaces_raw),
        'logs': parse_logbuffer(logs_raw),
    }
    return JSONResponse(parsed)


@app.post('/api/summary')
async def summary_post(payload: ConnectPayload, user: dict = Depends(require_user)):
    """POST variant: accept JSON body with host/username/password/port and return parsed summary."""
    payload_host = payload.host
    payload_user = payload.username
    payload_pass = payload.password
    port = payload.port
    wrapper = SSHClientWrapper(payload_host, port, payload_user or '', payload_pass or '')
    try:
        wrapper.connect(timeout=10)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'SSH connect failed: {e}')
    try:
        version = wrapper.run('display version')
        interfaces_raw = wrapper.run('display interface brief')
        if 'Unrecognized command' in interfaces_raw:
            interfaces_raw = wrapper.run('display interface')
        logs_raw = wrapper.run('display logbuffer size 50')
    finally:
        wrapper.close()

    from .parsers import parse_version, parse_interface_brief, parse_logbuffer
    parsed = {
        'device': parse_version(version),
        'interfaces': parse_interface_brief(interfaces_raw),
        'logs': parse_logbuffer(logs_raw),
    }
    return JSONResponse(parsed)


@app.get('/api/sample/summary')
async def sample_summary():
    root = os.path.join(pkg_root, 'app', 'sample_outputs')
    ver = open(os.path.join(root, 'display_version.txt')).read()
    intf = open(os.path.join(root, 'display_interface_brief.txt')).read()
    logs = open(os.path.join(root, 'display_logbuffer_size_50.txt')).read()
    from .parsers import parse_version, parse_interface_brief, parse_logbuffer
    parsed = {
        'device': parse_version(ver),
        'interfaces': parse_interface_brief(intf),
        'logs': parse_logbuffer(logs),
    }
    return JSONResponse(parsed)


@app.get('/api/sample/version')
async def sample_version():
    path = os.path.join(pkg_root, 'app', 'sample_outputs', 'display_version.txt')
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='sample not found')
    return FileResponse(path, media_type='text/plain')
