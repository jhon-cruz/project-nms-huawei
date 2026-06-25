import os
import subprocess
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICE_NAME = os.environ.get("NMS_SERVICE_NAME", "project-nms-huawei")


def _run(args: list[str], timeout: int = 60) -> dict[str, str | int]:
    proc = subprocess.run(
        args,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "command": " ".join(args),
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def _schedule_restart() -> dict[str, str | int]:
    command = f"sleep 2; sudo -n systemctl restart {SERVICE_NAME}"
    subprocess.Popen(
        ["sh", "-c", command],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return {
        "command": f"sudo -n systemctl restart {SERVICE_NAME} (agendado)",
        "returncode": 0,
        "stdout": "Restart agendado em segundo plano.",
        "stderr": "",
    }


def git_revision() -> dict[str, str]:
    if not (PROJECT_ROOT / ".git").exists():
        return {"branch": "sem git", "commit": "desconhecido"}
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    commit = _run(["git", "rev-parse", "--short", "HEAD"])
    return {
        "branch": branch["stdout"] if branch["returncode"] == 0 else "desconhecido",
        "commit": commit["stdout"] if commit["returncode"] == 0 else "desconhecido",
    }


def system_status() -> dict[str, object]:
    service = _run(["systemctl", "is-active", SERVICE_NAME], timeout=10)
    revision = git_revision()
    return {
        "service": SERVICE_NAME,
        "service_active": service["stdout"] if service["returncode"] == 0 else "indisponivel",
        "project_root": str(PROJECT_ROOT),
        **revision,
    }


def update_from_git() -> dict[str, object]:
    if os.geteuid() == 0:
        raise RuntimeError("nao execute atualizacao da interface como root")
    if not (PROJECT_ROOT / ".git").exists():
        raise RuntimeError("instalacao nao possui repositorio git local")

    steps = [
        _run(["git", "fetch", "--all", "--prune"], timeout=120),
        _run(["git", "pull", "--ff-only"], timeout=120),
    ]

    venv_pip = PROJECT_ROOT / ".venv" / "bin" / "pip"
    pip_cmd = str(venv_pip) if venv_pip.exists() else "pip3"
    steps.append(_run([pip_cmd, "install", "-r", "requirements.txt"], timeout=240))

    failed = [step for step in steps if int(step["returncode"]) != 0]
    if failed:
        return {"ok": False, "steps": steps, **git_revision()}

    restart = _schedule_restart()
    steps.append(restart)
    return {
        "ok": True,
        "steps": steps,
        **git_revision(),
    }
