#!/usr/bin/env python3
"""
IDS Engine - Bộ phát hiện và ngăn chặn xâm nhập
Simulation mode: tạo traffic và threat giả lập thực tế
"""

import threading
import random
import time
from datetime import datetime
from collections import defaultdict


class IDSEngine:
    def __init__(self, data_store, socketio):
        self.data_store = data_store
        self.socketio = socketio
        self.running = False
        self.mode = 'IDS'  # IDS or IPS
        self._threads = []
        
        # Detection thresholds
        self.port_scan_threshold = 15
        self.syn_flood_threshold = 500
        self.icmp_flood_threshold = 100
        self.http_flood_threshold = 200
        
        # IP connection tracking
        self.ip_connections = defaultdict(lambda: defaultdict(int))
        self.ip_timestamps = defaultdict(list)
        
        # Simulated IPs for demo
        self.attack_ips = [
            '203.113.45.67', '118.70.12.34', '45.33.32.156',
            '185.220.101.5', '94.102.49.190', '62.210.115.78',
            '91.108.4.11', '198.51.100.42', '192.0.2.88',
            '10.10.10.55', '172.20.0.99', '192.168.100.200'
        ]
        self.benign_ips = [
            '192.168.1.10', '192.168.1.20', '192.168.1.30',
            '10.0.0.5', '10.0.0.10', '172.16.0.10', '172.16.0.20'
        ]
        self.dest_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        
        # Attack scenarios
        self.attack_scenarios = [
            self._sim_port_scan,
            self._sim_syn_flood,
            self._sim_sql_injection,
            self._sim_xss_attack,
            self._sim_ssh_brute,
            self._sim_icmp_flood,
            self._sim_http_flood,
            self._sim_nmap_scan,
        ]

    def start(self):
        if not self.running:
            self.running = True
            
            # Start traffic simulator
            t1 = threading.Thread(target=self._traffic_simulator, daemon=True)
            t1.start()
            self._threads.append(t1)
            
            # Start attack simulator
            t2 = threading.Thread(target=self._attack_simulator, daemon=True)
            t2.start()
            self._threads.append(t2)
            
            # Start stats broadcaster
            t3 = threading.Thread(target=self._stats_broadcaster, daemon=True)
            t3.start()
            self._threads.append(t3)
            
            print("[+] IDS/IPS Engine started (Simulation mode)")

    def stop(self):
        self.running = False
        self._threads.clear()
        print("[-] IDS/IPS Engine stopped")

    def block_ip(self, ip, reason='Manual block'):
        self.data_store.add_blocked_ip(ip, reason, auto=False)
        self._emit_alert({
            'type': 'IP Blocked',
            'severity': 'INFO',
            'category': 'Manual Action',
            'src_ip': ip,
            'dst_ip': 'N/A',
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'N/A',
            'action': 'BLOCKED',
            'details': f'IP {ip} đã bị chặn thủ công: {reason}',
            'rule_id': None
        })
        return {'status': 'ok', 'message': f'Đã chặn IP {ip}'}

    def unblock_ip(self, ip):
        if self.data_store.remove_blocked_ip(ip):
            return {'status': 'ok', 'message': f'Đã bỏ chặn IP {ip}'}
        return {'status': 'error', 'message': f'IP {ip} không có trong danh sách chặn'}

    def _traffic_simulator(self):
        """Simulate normal network traffic"""
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        weights = [0.35, 0.20, 0.05, 0.15, 0.20, 0.05]
        
        while self.running:
            # Simulate burst of packets
            batch_size = random.randint(5, 30)
            for _ in range(batch_size):
                proto = random.choices(protocols, weights=weights)[0]
                size = random.randint(64, 1518)
                self.data_store.increment_packet(size, proto)
            
            time.sleep(random.uniform(0.1, 0.5))

    def _attack_simulator(self):
        """Simulate attack scenarios at random intervals"""
        while self.running:
            # Random delay between attacks (15-60 seconds)
            delay = random.uniform(8, 25)
            time.sleep(delay)
            
            if not self.running:
                break
            
            # Choose random attack
            scenario = random.choice(self.attack_scenarios)
            try:
                scenario()
            except Exception as e:
                print(f"[!] Attack simulation error: {e}")

    def _stats_broadcaster(self):
        """Broadcast stats via WebSocket every 2 seconds"""
        while self.running:
            time.sleep(2)
            try:
                stats = self.data_store.get_stats()
                self.socketio.emit('stats_update', stats)
            except Exception:
                pass

    def _emit_alert(self, alert_data):
        """Add alert to store and broadcast via WebSocket"""
        self.data_store.add_alert(alert_data)
        try:
            self.socketio.emit('new_alert', alert_data)
        except Exception:
            pass

    # ─── Attack Simulation Methods ───

    def _sim_port_scan(self):
        src_ip = random.choice(self.attack_ips)
        dst_ip = random.choice(self.dest_ips)
        scanned_ports = random.sample(range(1, 65535), random.randint(15, 50))
        
        alert = {
            'type': 'Port Scan',
            'severity': 'HIGH',
            'category': 'Reconnaissance',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(40000, 65535),
            'dst_port': scanned_ports[0],
            'protocol': 'TCP',
            'action': 'BLOCKED' if self.mode == 'IPS' else 'ALERT',
            'details': f'Port scan detected: {len(scanned_ports)} ports scanned in 1s. Ports: {scanned_ports[:5]}...',
            'rule_id': 1
        }
        print(f"[!] SIM: Port Scan from {src_ip}")
        self._emit_alert(alert)
        
        if self.mode == 'IPS':
            self.data_store.add_blocked_ip(src_ip, 'Auto-blocked: Port Scan')

    def _sim_syn_flood(self):
        src_ip = random.choice(self.attack_ips)
        dst_ip = random.choice(self.dest_ips)
        pps = random.randint(500, 5000)
        
        alert = {
            'type': 'SYN Flood',
            'severity': 'CRITICAL',
            'category': 'DoS/DDoS',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 22]),
            'protocol': 'TCP',
            'action': 'BLOCKED' if self.mode == 'IPS' else 'ALERT',
            'details': f'SYN Flood: {pps} SYN packets/second detected. Target port overwhelmed.',
            'rule_id': 2
        }
        print(f"[!] SIM: SYN Flood from {src_ip} ({pps} pps)")
        self._emit_alert(alert)

    def _sim_sql_injection(self):
        src_ip = random.choice(self.attack_ips)
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM passwords --",
            "admin'--",
            "1; SELECT * FROM information_schema.tables"
        ]
        payload = random.choice(payloads)
        
        alert = {
            'type': 'SQL Injection',
            'severity': 'CRITICAL',
            'category': 'Web Attack',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 8080]),
            'protocol': 'HTTP',
            'action': 'BLOCKED' if self.mode == 'IPS' else 'ALERT',
            'details': f'SQL Injection payload detected in HTTP request: {payload}',
            'rule_id': 4
        }
        print(f"[!] SIM: SQL Injection from {src_ip}")
        self._emit_alert(alert)

    def _sim_xss_attack(self):
        src_ip = random.choice(self.attack_ips)
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
            "<svg onload=alert(1)>",
        ]
        payload = random.choice(payloads)
        
        alert = {
            'type': 'XSS Attack',
            'severity': 'HIGH',
            'category': 'Web Attack',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 8080]),
            'protocol': 'HTTP',
            'action': 'BLOCKED' if self.mode == 'IPS' else 'ALERT',
            'details': f'XSS payload in HTTP request param: {payload}',
            'rule_id': 5
        }
        print(f"[!] SIM: XSS Attack from {src_ip}")
        self._emit_alert(alert)

    def _sim_ssh_brute(self):
        src_ip = random.choice(self.attack_ips)
        attempts = random.randint(20, 200)
        
        alert = {
            'type': 'Brute Force SSH',
            'severity': 'HIGH',
            'category': 'Brute Force',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': 22,
            'protocol': 'TCP',
            'action': 'BLOCKED' if self.mode == 'IPS' else 'ALERT',
            'details': f'SSH Brute Force: {attempts} failed login attempts in 60s',
            'rule_id': 6
        }
        print(f"[!] SIM: SSH Brute Force from {src_ip}")
        self._emit_alert(alert)
        
        if attempts > 100 and self.mode == 'IPS':
            self.data_store.add_blocked_ip(src_ip, 'Auto-blocked: SSH Brute Force')

    def _sim_icmp_flood(self):
        src_ip = random.choice(self.attack_ips)
        pps = random.randint(100, 1000)
        
        alert = {
            'type': 'ICMP Flood',
            'severity': 'MEDIUM',
            'category': 'DoS/DDoS',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'ICMP',
            'action': 'ALERT',
            'details': f'ICMP Flood: {pps} ICMP echo requests/second',
            'rule_id': 3
        }
        print(f"[!] SIM: ICMP Flood from {src_ip}")
        self._emit_alert(alert)

    def _sim_http_flood(self):
        src_ip = random.choice(self.attack_ips)
        rps = random.randint(200, 2000)
        paths = ['/index.php', '/login', '/api/v1/data', '/wp-admin', '/admin']
        path = random.choice(paths)
        
        alert = {
            'type': 'HTTP Flood',
            'severity': 'MEDIUM',
            'category': 'DoS/DDoS',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,
            'protocol': 'HTTP',
            'action': 'ALERT',
            'details': f'HTTP Flood: {rps} requests/second to {path}',
            'rule_id': 8
        }
        print(f"[!] SIM: HTTP Flood from {src_ip} ({rps} rps)")
        self._emit_alert(alert)

    def _sim_nmap_scan(self):
        src_ip = random.choice(self.attack_ips)
        
        alert = {
            'type': 'Nmap OS Detection',
            'severity': 'LOW',
            'category': 'Reconnaissance',
            'src_ip': src_ip,
            'dst_ip': random.choice(self.dest_ips),
            'src_port': random.randint(40000, 65535),
            'dst_port': random.choice([80, 443, 22, 3389]),
            'protocol': 'TCP',
            'action': 'ALERT',
            'details': 'Nmap OS fingerprinting detected via TCP/IP stack analysis',
            'rule_id': 10
        }
        print(f"[!] SIM: Nmap Scan from {src_ip}")
        self._emit_alert(alert)
