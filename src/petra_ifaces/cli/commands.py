import click
import platform 
import psutil 
import subprocess 
from datetime import datetime
#for scanning
from tabulate import tabulate
from pathlib import Path
from petra_model.application.scan_service import ScanService
from petra_domain.entities.anomaly import Anomaly, AnomalyLevel

@click.group()
def cli():
    """PETRA - Post-Exploitation Threat Recognition & Analysis"""
    pass

@cli.command()
def status():
    """Tells system status and ascii"""
    click.clear()
    ascii_art = """
    \033[31m
      ██████╗ ███████╗████████╗██████╗  █████╗ 
      ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
      ██████╔╝█████╗     ██║   ██████╔╝███████║
      ██╔═══╝ ██╔══╝     ██║   ██╔══██╗██╔══██║
      ██║     ███████╗   ██║   ██║  ██║██║  ██║
      ╚═╝     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
    \033[33m                        v1.0.0-beta (Quantum Edition)\033[0m
        """.strip()
    
    print(ascii_art)
    #info
    print(f"\033[32m✔ \033[1mSystem\033[0m:\033[0m {platform.system()} {platform.release()} {platform.machine()}")
    # CPU
    cpu = platform.processor() or "Unknown"
    cores = psutil.cpu_count(logical=False)
    threads = psutil.cpu_count(logical=True)
    freq = psutil.cpu_freq().current / 1000 if psutil.cpu_freq() else 0
    print(f"\033[32m✔ \033[1mCPU\033[0m:\033[0m {cpu} @ {freq:.1f}GHz ({cores}c/{threads}t)")

    # RAM
    mem = psutil.virtual_memory()
    print(f"\033[32m✔ \033[1mRAM\033[0m:\033[0m {mem.total // (1024**3):.1f} GiB / {mem.used // (1024**3):.1f} GiB ({mem.percent}% used)")

        # GPU Detection (Apple Silicon, NVIDIA, AMD, Intel)
    try:
        # Apple Silicon
        if platform.system() == "Darwin" and platform.machine().startswith("arm"):
            brand = subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string']).decode().strip()
            print(f"\033[32m✔ \033[1mGPU\033[0m:\033[0m Apple {brand.split()[-1]} (Integrated)")
        else:
            # NVIDIA
            result = subprocess.check_output(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"], stderr=subprocess.DEVNULL)
            gpu = result.decode().strip().split(", ")
            print(f"\033[32m✔ \033[1mGPU\033[0m:\033[0m {gpu[0]} {gpu[1]} (Driver {gpu[2]})")
    except:
        try:
            # AMD / Intel
            result = subprocess.check_output(["lspci | grep VGA"], shell=True).decode()
            print(f"\033[32m✔ \033[1mGPU\033[0m:\033[0m {result.strip().split(': ')[1]}")
        except:
            print(f"\033[33m⚡ \033[1mGPU\033[0m:\033[0m No detected/No drivers")

    # Disk
    disk = psutil.disk_usage('/')
    print(f"\033[32m✔ \033[1mDisk\033[0m:\033[0m {disk.total // (1024**3):.1f} TiB total | {disk.free // (1024**3):.1f} TiB free")

    # date / hour
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n\033[96m {now} - \033[1mPETRA\033[0m ready to hunt.\033[0m")
    print(f"\033[104m PETRA \033[0m\033[92m Ready. Use `petra scan` to start.\033[0m\n")

if __name__ == "__main__":
    cli()


## scanning
@cli.command()
@click.option('-f', '--file', type=str, required=True, help="Path to log file")
@click.option('--ml-mode', is_flag=True, help="Enable ML detection (future)")
def scan(file: str, ml_mode: bool):
    """Scan log file for anomalies."""
    try:
        file_path = Path(file)
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file}")
        service = ScanService()
        anomalies = service.scan(file_path, ml_mode=ml_mode)
        if not anomalies:
            click.echo("\033[32m✔ No anomalies detected.\033[0m")
            return

        # print table
        table_data = [
            [
                anomaly.level.value.upper(),
                f"{anomaly.score:.2f}",
                anomaly.type,
                anomaly.evidence[0].ip if anomaly.evidence else "N/A",
                anomaly.description
            ] for anomaly in anomalies
        ]

        headers = ["Level", "Score", "Type", "IP", "Description"]
        table = tabulate(table_data, headers, tablefmt="fancy_grid")

        click.echo("\033[31m╔════════════════════════════════════════════╗\033[0m")
        click.echo("\033[31m║         ANOMALIES DETECTED!                ║\033[0m")
        click.echo("\033[31m╚════════════════════════════════════════════╝\033[0m")
        click.echo(table)

        if any(a.level == AnomalyLevel.CRITICAL for a in anomalies):
            click.echo("\a")  # beep for critical

    except Exception as e:
        click.echo(f"\033[31mError: {e}\033[0m", err=True)
        raise