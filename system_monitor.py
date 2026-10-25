
import psutil
import platform
from datetime import datetime

print("=" * 50)
print("       AI-POWERED SOC TOOLKIT")
print("          SYSTEM MONITOR")
print("=" * 50)

print(f"Time: {datetime.now()}")
print(f"Operating System: {platform.system()} {platform.release()}")

cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent

print(f"CPU Usage: {cpu_usage}%")
print(f"Memory Usage: {memory_usage}%")

print("\n--- SECURITY MONITORING ALERTS ---")

if cpu_usage >= 90:
    print("[HIGH] CPU usage is unusually high!")
else:
    print("[OK] CPU usage is below the alert threshold.")

if memory_usage >= 85:
    print("[WARNING] High memory usage detected!")
else:
    print("[OK] Memory usage is below the alert threshold.")

print(f"Disk Usage: {psutil.disk_usage('/').percent}%")

print("\nTop 10 Processes by Memory Usage")
print("-" * 50)

processes = []

for proc in psutil.process_iter(
    ['pid', 'name', 'memory_percent']
):
    try:
        processes.append(proc.info)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

processes.sort(
    key=lambda p: p.get('memory_percent') or 0,
    reverse=True
)

for proc in processes[:10]:
    print(
        f"PID: {proc['pid']:<7} "
        f"Name: {str(proc['name']):<25} "
        f"Memory: {proc['memory_percent'] or 0:.2f}%"
    )

print("\nSystem monitoring completed.")
