import json
import time
from collections import Counter

class DetectionEngine:
    def __init__(self, rules_file='rules/signatures.json'):
        self.rules = self.load_rules(rules_file)
        self.alerts = []
        self.thresholds = {
            'port_scan': 20,      # 20 unique ports in 60 seconds
            'syn_flood': 100,      # 100 SYN packets in 10 seconds
            'dns_tunnel': 50,      # 50 DNS queries in 10 seconds
            'brute_force': 30      # 30 failed connections in 60 seconds
        }
        
    def load_rules(self, rules_file):
        """Load signature rules from JSON file"""
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("[!] No rules file found, using default rules")
            return self.create_default_rules()
    
    def create_default_rules(self):
        """Create default detection rules"""
        return {
            'syn_scan': {
                'description': 'SYN Port Scan Detected',
                'condition': 'tcp_flags == 2 and unique_ports > 10',
                'severity': 'high'
            },
            'syn_flood': {
                'description': 'SYN Flood Attack Detected',
                'condition': 'tcp_flags == 2 and packet_rate > 100',
                'severity': 'critical'
            },
            'dns_tunnel': {
                'description': 'Possible DNS Tunneling Detected',
                'condition': 'dns_queries > 50',
                'severity': 'medium'
            },
            'brute_force': {
                'description': 'Brute Force Attack Detected',
                'condition': 'failed_connections > 30',
                'severity': 'high'
            }
        }
    
    def detect_port_scan(self, analyzer, src_ip):
        """Detect port scanning activity"""
        unique_ports = analyzer.get_connection_rate(src_ip)
        if unique_ports > self.thresholds['port_scan']:
            return {
                'type': 'Port Scan',
                'source': src_ip,
                'unique_ports': unique_ports,
                'severity': 'high',
                'confidence': min(100, int((unique_ports / self.thresholds['port_scan']) * 100))
            }
        return None
    
    def detect_syn_flood(self, analyzer, src_ip):
        """Detect SYN flood attacks"""
        packet_rate = analyzer.get_packet_rate(src_ip, time_window=10)
        # Check if many are SYN packets
        if packet_rate > self.thresholds['syn_flood']:
            return {
                'type': 'SYN Flood',
                'source': src_ip,
                'packet_rate': packet_rate,
                'severity': 'critical',
                'confidence': min(100, int((packet_rate / self.thresholds['syn_flood']) * 100))
            }
        return None
    
    def detect_dns_anomaly(self, analyzer):
        """Detect unusual DNS activity"""
        dns_queries = analyzer.get_dns_queries()
        if dns_queries > self.thresholds['dns_tunnel']:
            return {
                'type': 'DNS Tunneling/Suspicious DNS',
                'dns_queries_per_sec': dns_queries / 10,
                'severity': 'medium',
                'confidence': 75
            }
        return None
    
    def analyze_traffic(self, packet_data, analyzer):
        """Main analysis function"""
        src_ip = packet_data.get('src_ip')
        if not src_ip or src_ip == '0.0.0.0':
            return None
        
        alerts = []
        
        # Run various detection methods
        port_scan = self.detect_port_scan(analyzer, src_ip)
        if port_scan:
            alerts.append(port_scan)
            
        syn_flood = self.detect_syn_flood(analyzer, src_ip)
        if syn_flood:
            alerts.append(syn_flood)
            
        dns_alert = self.detect_dns_anomaly(analyzer)
        if dns_alert:
            alerts.append(dns_alert)
        
        return alerts if alerts else None
