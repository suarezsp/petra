import click
import platform 
import psutil 
import subprocess 
from datetime import datetime

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