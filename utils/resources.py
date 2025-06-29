import requests
from rich.console import Console
import config

console = Console()

def update_attack_resources():
    with console.status("[bold cyan]Downloading attack resources...[/bold cyan]", spinner="earth"):
        try:
            proxy_res = requests.get(config.PROXY_URL, timeout=10)
            proxy_res.raise_for_status()
            config.proxies = [p for p in proxy_res.text.splitlines() if p.strip()]
            console.log(f"[green]Acquired {len(config.proxies)} HTTP proxies.[/green]")
        except Exception:
            console.log("[yellow]Primary proxy list failed. Trying backup...[/yellow]")
            try:
                proxy_res = requests.get(config.PROXY_URL_2, timeout=10)
                proxy_res.raise_for_status()
                config.proxies = [p for p in proxy_res.text.splitlines() if p.strip()]
                console.log(f"[green]Acquired {len(config.proxies)} HTTP proxies from backup.[/green]")
            except Exception:
                console.log("[red]Could not fetch any proxy list. Proceeding without proxies.[/red]")

        try:
            ua_res = requests.get(config.USER_AGENT_URL, timeout=10)
            ua_res.raise_for_status()
            config.user_agents = [item['user_agent'] for item in ua_res.json()]
            console.log(f"[green]Acquired {len(config.user_agents)} User-Agents.[/green]")
        except Exception:
            console.log("[yellow]Could not fetch User-Agent list. Using default.[/yellow]")
            if not config.user_agents:
                config.user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"]

