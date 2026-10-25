"""Cross-platform system and process telemetry collection."""

import os
import platform
import socket
from datetime import datetime, timezone

import psutil

from .models import ProcessRecord, SystemSnapshot


def _disk_path() -> str:
    """Choose a disk path that exists on Windows and POSIX systems."""
    if os.name == "nt":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"


def collect_system_snapshot() -> SystemSnapshot:
    try:
        uptime = max(0.0, datetime.now(timezone.utc).timestamp() - psutil.boot_time())
    except (OSError, psutil.Error):
        uptime = None
    def safe_metric(reader):
        try:
            return reader()
        except (OSError, psutil.Error):
            return None
    cpu = safe_metric(lambda: psutil.cpu_percent(interval=0.2))
    memory = safe_metric(lambda: psutil.virtual_memory().percent)
    disk = safe_metric(lambda: psutil.disk_usage(_disk_path()).percent)
    return SystemSnapshot(
        captured_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        hostname=socket.gethostname(),
        operating_system=f"{platform.system()} {platform.release()}",
        cpu_percent=cpu,
        memory_percent=memory,
        disk_percent=disk,
        uptime_seconds=uptime,
    )


def collect_processes(limit: int = 10) -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "status"]):
        try:
            info = proc.info
            try:
                executable = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                executable = None
            records.append(ProcessRecord(
                pid=int(info.get("pid") or 0),
                name=info.get("name") or "<unknown>",
                username=info.get("username"),
                cpu_percent=float(info.get("cpu_percent") or 0),
                memory_percent=float(info.get("memory_percent") or 0),
                status=info.get("status") or "unknown",
                executable=executable,
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(records, key=lambda item: item.memory_percent, reverse=True)[:max(0, limit)]
