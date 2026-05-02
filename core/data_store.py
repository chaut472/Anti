#!/usr/bin/env python3
"""
Data Store - Lưu trữ và quản lý dữ liệu IDS/IPS
"""

import json
import random
import threading
from datetime import datetime, timedelta
from collections import deque, defaultdict
import time


class DataStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.alerts = deque(maxlen=1000)
        self.traffic_history = deque(maxlen=200)
        self.blocked_ips = {}
        self.packet_count = 0
        self.alert_count = 0
        self.bytes_total = 0
        self.start_time = datetime.now()
        
        # Protocol counters
        self.protocol_counts = defaultdict(int)
        
        # Hourly traffic
        self.hourly_traffic = defaultdict(lambda: {'packets': 0, 'threats': 0})
        
        # Top threat IPs
        self.threat_ips = defaultdict(int)
        
        # Rules
        self.rules = self._init_rules()
        
        # Initialize with some sample data
        self._init_sample_data()

    def _init_rules(self):
        return [
            {
                'id': 1, 'name': 'Port Scan Detection',
                'description': 'Phát hiện quét cổng từ một IP (>15 cổng/giây)',
                'severity': 'HIGH', 'enabled': True,
                'trigger_count': 0, 'category': 'Reconnaissance'
            },
            {
                'id': 2, 'name': 'SYN Flood Detection',
                'description': 'Phát hiện tấn công SYN Flood (>500 SYN/giây)',
                'severity': 'CRITICAL', 'enabled': True,
                'trigger_count': 0, 'category': 'DoS/DDoS'
            },
            {
                'id': 3, 'name': 'ICMP Flood Detection',
                'description': 'Phát hiện ICMP Flood (>100 ping/giây)',
                'severity': 'MEDIUM', 'enabled': True,
                'trigger_count': 0, 'category': 'DoS/DDoS'
            },
            {
                'id': 4, 'name': 'SQL Injection Detection',
                'description': 'Phát hiện chuỗi SQL Injection trong HTTP payload',
                'severity': 'CRITICAL', 'enabled': True,
                'trigger_count': 0, 'category': 'Web Attack'
            },
            {
                'id': 5, 'name': 'XSS Attack Detection',
                'description': 'Phát hiện Cross-Site Scripting trong HTTP request',
                'severity': 'HIGH', 'enabled': True,
                'trigger_count': 0, 'category': 'Web Attack'
            },
            {
                'id': 6, 'name': 'Brute Force SSH',
                'description': 'Phát hiện tấn công Brute Force vào cổng SSH (22)',
                'severity': 'HIGH', 'enabled': True,
                'trigger_count': 0, 'category': 'Brute Force'
            },
            {
                'id': 7, 'name': 'DNS Amplification',
                'description': 'Phát hiện DNS Amplification Attack',
                'severity': 'HIGH', 'enabled': False,
                'trigger_count': 0, 'category': 'DoS/DDoS'
            },
            {
                'id': 8, 'name': 'HTTP Flood Detection',
                'description': 'Phát hiện tấn công HTTP Flood (>200 req/giây)',
                'severity': 'MEDIUM', 'enabled': True,
                'trigger_count': 0, 'category': 'DoS/DDoS'
            },
            {
                'id': 9, 'name': 'FTP Brute Force',
                'description': 'Phát hiện Brute Force vào FTP (cổng 21)',
                'severity': 'MEDIUM', 'enabled': True,
                'trigger_count': 0, 'category': 'Brute Force'
            },
            {
                'id': 10, 'name': 'Nmap OS Detection',
                'description': 'Phát hiện Nmap OS fingerprinting (-O flag)',
                'severity': 'LOW', 'enabled': True,
                'trigger_count': 0, 'category': 'Reconnaissance'
            },
        ]

    def _init_sample_data(self):
        """Initialize with realistic sample data"""
        threat_types = [
            ('Port Scan', 'HIGH', 'Reconnaissance'),
            ('SYN Flood', 'CRITICAL', 'DoS/DDoS'),
            ('SQL Injection', 'CRITICAL', 'Web Attack'),
            ('XSS Attack', 'HIGH', 'Web Attack'),
            ('Brute Force SSH', 'HIGH', 'Brute Force'),
            ('ICMP Flood', 'MEDIUM', 'DoS/DDoS'),
            ('HTTP Flood', 'MEDIUM', 'DoS/DDoS'),
            ('DNS Amplification', 'HIGH', 'DoS/DDoS'),
            ('Nmap Scan', 'LOW', 'Reconnaissance'),
            ('FTP Brute Force', 'MEDIUM', 'Brute Force'),
        ]
        
        sample_ips = [
            '192.168.1.105', '10.0.0.23', '172.16.0.45',
            '203.113.45.67', '118.70.12.34', '45.33.32.156',
            '192.0.2.88', '198.51.100.42', '185.220.101.5',
            '94.102.49.190', '62.210.115.78', '91.108.4.11'
        ]
        
        dest_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '192.168.0.100']
        
        # Generate 50 sample historical alerts
        for i in range(50):
            threat = random.choice(threat_types)
            src_ip = random.choice(sample_ips)
            ts = datetime.now() - timedelta(
                minutes=random.randint(1, 1440)
            )
            alert = {
                'id': i + 1,
                'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
                'type': threat[0],
                'severity': threat[1],
                'category': threat[2],
                'src_ip': src_ip,
                'dst_ip': random.choice(dest_ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([22, 80, 443, 3389, 21, 3306, 8080]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'action': random.choice(['ALERT', 'BLOCKED', 'ALERT', 'ALERT']),
                'details': f'Detected {threat[0]} pattern from {src_ip}',
                'rule_id': random.randint(1, 10)
            }
            self.alerts.appendleft(alert)
            self.alert_count += 1
            self.threat_ips[src_ip] += random.randint(1, 15)
        
        # Protocol stats
        self.protocol_counts = {
            'TCP': random.randint(5000, 15000),
            'UDP': random.randint(2000, 8000),
            'ICMP': random.randint(500, 2000),
            'HTTP': random.randint(3000, 10000),
            'HTTPS': random.randint(4000, 12000),
            'DNS': random.randint(1000, 4000),
        }
        
        # Total packets
        self.packet_count = sum(self.protocol_counts.values()) + random.randint(10000, 50000)
        self.bytes_total = self.packet_count * random.randint(200, 1500)
        
        # Block some IPs
        blocked_sources = random.sample(sample_ips, 3)
        for ip in blocked_sources:
            self.blocked_ips[ip] = {
                'ip': ip,
                'reason': random.choice(['Port Scan', 'SYN Flood', 'Brute Force']),
                'blocked_at': (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime('%Y-%m-%d %H:%M:%S'),
                'packet_count': random.randint(100, 5000),
                'auto_blocked': True
            }
        
        # Hourly traffic (last 24 hours)
        for h in range(24):
            hour_key = (datetime.now() - timedelta(hours=23-h)).strftime('%H:00')
            self.hourly_traffic[hour_key] = {
                'packets': random.randint(100, 3000),
                'threats': random.randint(0, 20),
                'hour': hour_key
            }
        
        # Update rule trigger counts
        for rule in self.rules:
            rule['trigger_count'] = random.randint(0, 50)

    def add_alert(self, alert_data):
        with self._lock:
            self.alert_count += 1
            alert_data['id'] = self.alert_count
            alert_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.alerts.appendleft(alert_data)
            
            # Update threat IP count
            if 'src_ip' in alert_data:
                self.threat_ips[alert_data['src_ip']] += 1
            
            # Update hourly
            hour_key = datetime.now().strftime('%H:00')
            self.hourly_traffic[hour_key]['threats'] += 1
            
            # Update rule trigger
            rule_id = alert_data.get('rule_id')
            if rule_id:
                for rule in self.rules:
                    if rule['id'] == rule_id:
                        rule['trigger_count'] += 1
                        break

    def increment_packet(self, size=500, protocol='TCP'):
        with self._lock:
            self.packet_count += 1
            self.bytes_total += size
            self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
            
            hour_key = datetime.now().strftime('%H:00')
            self.hourly_traffic[hour_key]['packets'] += 1

    def get_stats(self):
        with self._lock:
            uptime = datetime.now() - self.start_time
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)
            
            recent_alerts = list(self.alerts)[:10]
            critical = sum(1 for a in self.alerts if a['severity'] == 'CRITICAL')
            high = sum(1 for a in self.alerts if a['severity'] == 'HIGH')
            medium = sum(1 for a in self.alerts if a['severity'] == 'MEDIUM')
            low = sum(1 for a in self.alerts if a['severity'] == 'LOW')
            blocked_count = sum(1 for a in self.alerts if a.get('action') == 'BLOCKED')
            
            return {
                'total_packets': self.packet_count,
                'total_alerts': self.alert_count,
                'blocked_count': blocked_count,
                'blocked_ips_count': len(self.blocked_ips),
                'bytes_total': self.bytes_total,
                'uptime': f'{hours}h {minutes}m',
                'uptime_seconds': int(uptime.total_seconds()),
                'severity': {
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low
                },
                'recent_alerts': recent_alerts,
                'threat_level': self._calculate_threat_level(),
                'packets_per_second': random.randint(50, 500),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

    def _calculate_threat_level(self):
        recent = list(self.alerts)[:20]
        if not recent:
            return 'LOW'
        critical = sum(1 for a in recent if a['severity'] == 'CRITICAL')
        high = sum(1 for a in recent if a['severity'] == 'HIGH')
        if critical >= 3:
            return 'CRITICAL'
        elif critical >= 1 or high >= 5:
            return 'HIGH'
        elif high >= 2:
            return 'MEDIUM'
        return 'LOW'

    def get_alerts(self, limit=50):
        with self._lock:
            return list(self.alerts)[:limit]

    def get_traffic_data(self):
        with self._lock:
            return list(self.traffic_history)

    def get_blocked_ips(self):
        with self._lock:
            return list(self.blocked_ips.values())

    def get_rules(self):
        with self._lock:
            return self.rules.copy()

    def toggle_rule(self, rule_id):
        with self._lock:
            for rule in self.rules:
                if rule['id'] == rule_id:
                    rule['enabled'] = not rule['enabled']
                    return {'status': 'ok', 'rule_id': rule_id, 'enabled': rule['enabled']}
            return {'status': 'error', 'message': 'Rule not found'}

    def add_blocked_ip(self, ip, reason, auto=True):
        with self._lock:
            self.blocked_ips[ip] = {
                'ip': ip,
                'reason': reason,
                'blocked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'packet_count': 0,
                'auto_blocked': auto
            }

    def remove_blocked_ip(self, ip):
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                return True
            return False

    def get_top_threats(self):
        with self._lock:
            sorted_ips = sorted(self.threat_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            return [{'ip': ip, 'count': count} for ip, count in sorted_ips]

    def get_protocol_stats(self):
        with self._lock:
            total = sum(self.protocol_counts.values()) or 1
            return [
                {'protocol': k, 'count': v, 'percentage': round(v/total*100, 1)}
                for k, v in sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)
            ]

    def get_hourly_traffic(self):
        with self._lock:
            return [
                {'hour': k, 'packets': v['packets'], 'threats': v['threats']}
                for k, v in sorted(self.hourly_traffic.items())
            ]

    def get_geo_data(self):
        """Simulated geo data for threat origins"""
        countries = [
            ('Việt Nam', 'VN', 35, 2),
            ('Trung Quốc', 'CN', 28, 45),
            ('Hoa Kỳ', 'US', 15, 12),
            ('Nga', 'RU', 8, 18),
            ('Đức', 'DE', 5, 8),
            ('Brazil', 'BR', 4, 6),
            ('Hàn Quốc', 'KR', 3, 4),
            ('Nhật Bản', 'JP', 2, 5),
        ]
        return [
            {'country': c[0], 'code': c[1], 'packets': c[2]*1000, 'threats': c[3]}
            for c in countries
        ]

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()
            self.alert_count = 0
