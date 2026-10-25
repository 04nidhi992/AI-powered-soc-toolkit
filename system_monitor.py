
"""Backward-compatible command-line view over the modular monitoring package."""

from soc_toolkit.alerts import configure_logging, evaluate_snapshot
from soc_toolkit.monitoring import collect_processes, collect_system_snapshot


def main() -> None:
    snapshot = collect_system_snapshot()
    alerts = evaluate_snapshot(snapshot)
    logger = configure_logging("soc_alerts.log")

    print("=" * 50)
    print("       AI-POWERED SOC TOOLKIT")
    print("          SYSTEM MONITOR")
    print("=" * 50)
    print(f"Time: {snapshot.captured_at}")
    print(f"Operating System: {snapshot.operating_system}")
    cpu = f"{snapshot.cpu_percent:.1f}%" if snapshot.cpu_percent is not None else "Unavailable"
    memory = f"{snapshot.memory_percent:.1f}%" if snapshot.memory_percent is not None else "Unavailable"
    disk = f"{snapshot.disk_percent:.1f}%" if snapshot.disk_percent is not None else "Unavailable"
    print(f"CPU Usage: {cpu}")
    print(f"Memory Usage: {memory}")
    print(f"Disk Usage: {disk}")
    print("\n--- SECURITY MONITORING ALERTS ---")
    if alerts:
        for alert in alerts:
            print(f"[{alert.severity}] {alert.message}")
            logger.warning("%s | reason=%s", alert.message, alert.reason)
    else:
        print("[OK] CPU, memory, and disk usage are below their alert thresholds.")

    print("\nTop 10 Processes by Memory Usage")
    print("-" * 50)
    for process in collect_processes(10):
        print(f"PID: {process.pid:<7} Name: {process.name:<25} Memory: {process.memory_percent:.2f}%")
    print("\nSystem monitoring completed.")


if __name__ == "__main__":
    main()
