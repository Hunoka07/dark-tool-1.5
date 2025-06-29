import time
from urllib.parse import urlparse

import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config

console = Console()

def get_system_panel():
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    return Panel(Text(f"CPU: [white]{cpu: >5.1f}%[/white]\nRAM: [white]{ram: >5.1f}%[/white]"), title="[b]System[/b]", border_style="yellow")

def get_attack_stats_panel():
    elapsed = max(time.time() - config.attack_stats["start_time"], 1)
    l7_rps = config.attack_stats["l7_requests"] / elapsed
    l4_pps = config.attack_stats["l4_packets"] / elapsed
    total = config.attack_stats["l7_requests"] + config.attack_stats["l4_packets"]
    err_rate = (config.attack_stats["errors"] / total * 100) if total > 0 else 0
    
    data_sent = config.attack_stats["bytes_sent"]
    if data_sent > 1024**3: data_str = f"{data_sent / 1024**3:.2f} GB"
    elif data_sent > 1024**2: data_str = f"{data_sent / 1024**2:.2f} MB"
    else: data_str = f"{data_sent / 1024:.2f} KB"
    
    rate_str = f"{data_sent / elapsed / 1024**2:.2f} MB/s"

    table = Table(show_header=False, show_edge=False, box=None)
    table.add_column(style="cyan", justify="right")
    table.add_column(style="bold white", justify="left")
    table.add_row("L7 RPS :", f" {l7_rps:,.1f}")
    table.add_row("L4 PPS :", f" {l4_pps:,.1f}")
    table.add_row("Total Hits :", f" {total:,}")
    table.add_row("Errors :", f" {config.attack_stats['errors']:,} ({err_rate:.1f}%)")
    table.add_row("Threads :", f" {config.attack_stats['active_threads']}")
    table.add_row("Data Sent :", f" {data_str}")
    table.add_row("Bandwidth :", f" {rate_str}")

    return Panel(table, title="[b]Live Statistics[/b]", border_style="green")

def update_threat_intelligence():
    total = config.attack_stats["l7_requests"] + config.attack_stats["l4_packets"]
    if total < 10: return
    err_rate = (config.attack_stats["errors"] / total * 100) if total > 0 else 0
    
    if err_rate > 90: config.attack_stats["threat_intelligence"] = "Extreme error rate. Target defense is effective. Pivot attack vector."
    elif err_rate > 60: config.attack_stats["threat_intelligence"] = "High error rate detected. Defense system may be throttling. Increase thread count or switch to L4."
    elif total > 5000 and err_rate < 5: config.attack_stats["threat_intelligence"] = "Target is absorbing load. Escalate to 'Eradicate' mode for maximum impact."
    elif config.attack_stats["l4_packets"] > config.attack_stats["l7_requests"]: config.attack_stats["threat_intelligence"] = "L4 flood is dominant. Network infrastructure is under pressure. Maintain momentum."
    else: config.attack_stats["threat_intelligence"] = "L7 attack is proceeding. Monitor error rate for signs of blocking."

def launch_dashboard(target_url, mode):
    config.attack_stats["start_time"] = time.time()
    layout = Layout(name="root")
    layout.split(Layout(name="header", size=3), Layout(ratio=1, name="main"), Layout(size=3, name="footer"))
    layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2))
    layout["side"].split(Layout(name="sys_info"), Layout(name="intel"))

    layout["header"].update(Panel(Text(f"DARK TOOL {config.VERSION} :: ATTACKING {urlparse(target_url).netloc} :: MODE: {mode.upper()}", justify="center", style="bold red on black")))
    layout["footer"].update(Panel(Text("Press [bold]CTRL+C[/bold] to terminate operation.", justify="center", style="yellow")))
    
    with Live(layout, screen=True, redirect_stderr=False, vertical_overflow="visible") as live:
        try:
            while not config.stop_event.is_set():
                update_threat_intelligence()
                layout["body"].update(get_attack_stats_panel())
                layout["sys_info"].update(get_system_panel())
                layout["intel"].update(Panel(Text(config.attack_stats['threat_intelligence'], style="italic magenta"), title="[b]Threat Intel[/b]", border_style="blue"))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

