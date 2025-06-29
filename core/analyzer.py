import socket
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
import cloudscraper

import config

console = Console()

class TargetAnalyzer:
    def __init__(self, target_url):
        self.url = target_url
        self.domain = urlparse(self.url).netloc
        self.results = {}
        self.scraper = cloudscraper.create_scraper()

    def analyze(self):
        with console.status(f"[bold magenta]Analyzing target: {self.domain}...[/bold magenta]"):
            self.results['Target'] = self.domain
            try:
                ip = socket.gethostbyname(self.domain)
                self.results['IP Address'] = ip
            except socket.gaierror:
                self.results['IP Address'] = "Resolution Failed"
                self.display_report()
                return None

            try:
                response = self.scraper.get(self.url, timeout=15)
                headers = {k.lower(): v for k,v in response.headers.items()}
                server = headers.get('server', 'N/A').lower()

                if 'cloudflare' in server: self.results['WAF/CDN'] = "Cloudflare"
                elif 'awselb' in server or 'aws' in headers.get('x-amz-cf-id', ''): self.results['WAF/CDN'] = "AWS WAF/CloudFront"
                elif 'sucuri' in server: self.results['WAF/CDN'] = "Sucuri CloudProxy"
                elif 'incapsula' in str(headers): self.results['WAF/CDN'] = "Imperva Incapsula"
                else: self.results['WAF/CDN'] = f"Unknown ({server.capitalize()})"
                
                self.results['Status'] = f"{response.status_code} {response.reason}"
                if "js-challenge" in response.text or response.status_code in [403, 503]:
                    self.results['Protection'] = "Active (JS Challenge / Block)"
                    config.attack_stats["threat_intelligence"] = "Target is actively blocking. L7 bypass vectors are critical."
                else:
                    self.results['Protection'] = "Passive/None Detected"
                    config.attack_stats["threat_intelligence"] = "Target appears vulnerable. Proceed with Overload or Eradicate."
            except Exception:
                self.results['WAF/CDN'] = "Detection Error"
                self.results['Protection'] = "Unreachable"
                config.attack_stats["threat_intelligence"] = "Cannot connect to target. Verify URL and network connectivity."
        
        self.display_report()
        return self.results
    
    def scan_ports(self):
        open_ports = []
        target_ip = self.results.get('IP Address')
        if not target_ip or target_ip == "Resolution Failed": return []
        
        common_ports = [80, 443, 21, 22, 25, 53, 8080, 8443, 3306, 3389]
        with console.status(f"[bold magenta]Scanning common ports on {target_ip}...[/bold magenta]"):
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
        
        self.results['Open TCP Ports'] = str(open_ports) if open_ports else "None found"
        if open_ports:
             config.attack_stats["threat_intelligence"] = f"Open ports found: {open_ports}. L4 vectors will be more effective."
        return open_ports

    def display_report(self):
        table = Table(title=f"Target Analysis Report: {self.domain}", style="magenta", title_style="bold magenta", border_style="blue")
        table.add_column("Parameter", style="cyan")
        table.add_column("Finding", style="white")
        for key, value in self.results.items():
            table.add_row(key, str(value))
        console.print(table)
