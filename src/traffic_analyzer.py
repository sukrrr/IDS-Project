from collections import defaultdict
import time
from datetime import datetime, timedelta

class TrafficAnalyzer:
    def __init__(self, window_size=60):  # 60 second window
        self.window_size = window_size
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'packets': []
        })
        self.connection_history = []
        
    def update_flow_stats(self, packet_data):
        """Update statistics for a network flow"""
        # Create flow key (bidirectional flow)
        src = packet_data['src_ip']
        dst = packet_data['dst_ip']
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')
        
        # For port scans, we track connections to different ports
        flow_key = f"{src}:{src_port}-{dst}:{dst_port}-{protocol}"
        
        # Update stats
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += packet_data['size']
        stats['last_seen'] = time.time()
        stats['packets'].append(packet_data)
        
        # Keep only last N packets to save memory
        if len(stats['packets']) > 100:
            stats['packets'] = stats['packets'][-100:]
        
        # Track unique destination ports per source (for port scan detection)
        if src_port is not None and dst_port is not None:
            connection_key = f"{src}:{dst_port}"
            # Check if this connection already exists
            exists = False
            for conn in self.connection_history:
                if conn['src'] == src and conn['dst_port'] == dst_port:
                    exists = True
                    conn['timestamp'] = time.time()  # Update timestamp
                    break
            if not exists:
                self.connection_history.append({
                    'timestamp': time.time(),
                    'src': src,
                    'dst_port': dst_port,
                    'protocol': protocol
                })
                # Clean old connections (last 60 seconds)
                self.connection_history = [
                    c for c in self.connection_history 
                    if time.time() - c['timestamp'] < self.window_size
                ]
        
        return stats
    
    def get_connection_rate(self, src_ip, time_window=60):
        """Get number of unique destination ports from a source in time window"""
        recent_connections = [
            c for c in self.connection_history
            if c['src'] == src_ip and 
            time.time() - c['timestamp'] < time_window
        ]
        # Count unique destination ports
        unique_ports = set(c['dst_port'] for c in recent_connections)
        return len(unique_ports)
    
    def get_packet_rate(self, src_ip, time_window=10):
        """Get packet rate for a source in the last time_window seconds"""
        now = time.time()
        count = 0
        for flow_key, stats in self.flow_stats.items():
            if flow_key.startswith(src_ip):
                # Count packets from this source in last window
                recent = [p for p in stats['packets'] 
                         if isinstance(p.get('timestamp'), (int, float)) and now - p['timestamp'] < time_window]
                count += len(recent)
        return count / time_window if time_window > 0 else 0
    
    def get_dns_queries(self, time_window=10):
        """Get DNS query rate"""
        now = time.time()
        dns_count = 0
        for flow_key, stats in self.flow_stats.items():
            for p in stats['packets']:
                if isinstance(p.get('timestamp'), (int, float)) and now - p['timestamp'] < time_window:
                    if 'DNS' in str(p.get('payload', '')):
                        dns_count += 1
        return dns_count
