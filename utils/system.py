import os
import sys
import subprocess
from uuid import getnode
from rich.console import Console
import config

console = Console()
original_mac_address = None

def initial_environment_check():
    if os.geteuid() != 0:
        console.print("[bold red]FATAL: Root privileges are required for low-level network access.[/bold red]")
        sys.exit(13)

    current_filename = os.path.basename(sys.argv[0])
    if current_filename != config.EXPECTED_FILENAME:
        console.print(f"[bold red]CRITICAL: Filename mismatch detected. Anti-analysis protocol initiated.[/bold red]")
        sys.exit(1)

    if "com.termux" in os.environ.get("PREFIX", ""):
        console.print("[bold cyan][*] Virtualized environment detected (Termux). Stealth mode enhanced.[/bold cyan]")

def manage_mac_address(action='spoof', interface='wlan0'):
    global original_mac_address
    if sys.platform != "linux":
        console.print("[bold yellow]Warning: MAC spoofing is only supported on Linux.[/bold yellow]")
        return

    if action == 'spoof':
        try:
            mac_int = getnode()
            original_mac_address = f"{mac_int:012x}"
            original_mac_formatted = ":".join(original_mac_address[i:i+2] for i in range(0, 12, 2))
            
            new_mac_bytes = [0x02, 0x00, 0x00, random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
            new_mac_str = ':'.join(map(lambda x: f'{x:02x}', new_mac_bytes))
            
            console.print(f"[*] Original MAC ({interface}): {original_mac_formatted}. Spoofing to {new_mac_str}...")
            subprocess.run(["ifconfig", interface, "down"], check=True, capture_output=True)
            subprocess.run(["ifconfig", interface, "hw", "ether", new_mac_str], check=True, capture_output=True)
            subprocess.run(["ifconfig", interface, "up"], check=True, capture_output=True)
            console.print("[bold green][✔] MAC address successfully spoofed.[/bold green]")
        except (subprocess.CalledProcessError, FileNotFoundError):
            console.print(f"[bold yellow][!] Warning: Could not spoof MAC on '{interface}'. 'ifconfig' might be missing or permission denied. Check interface name in config.py.[/bold yellow]")
    
    elif action == 'restore' and original_mac_address:
        try:
            original_mac_formatted = ":".join(original_mac_address[i:i+2] for i in range(0, 12, 2))
            console.print(f"\n[*] Restoring original MAC address ({original_mac_formatted}) for {interface}...")
            subprocess.run(["ifconfig", interface, "down"], check=True, capture_output=True)
            subprocess.run(["ifconfig", interface, "hw", "ether", original_mac_formatted], check=True, capture_output=True)
            subprocess.run(["ifconfig", interface, "up"], check=True, capture_output=True)
            console.print("[bold green][✔] MAC address successfully restored.[/bold green]")
        except (subprocess.CalledProcessError, FileNotFoundError):
            console.print(f"[bold red][!] Failed to restore MAC address. Manual intervention may be required.[/bold red]")

