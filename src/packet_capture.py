import time
import threading
import queue
from scapy.all import sniff, IP, TCP, UDP, DNS
from datetime import datetime

class PacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.capturing = False
        self.stats = {'total': 0, 'tcp': 0, 'udp': 0, 'dns': 0}
        
    def packet_handler(self, packet):
        """Callback function for each captured packet"""
        self.stats['total'] += 1
        
        # Basic packet info extraction
        packet_data = {
            'timestamp': time.time(),
            'src_ip': packet[IP].src if IP in packet else None,
            'dst_ip': packet[IP].dst if IP in packet else None,
            'protocol': None,
            'size': len(packet),
            'flags': None,
            'src_port': None,
            'dst_port': None,
            'payload': None
        }
        
        if TCP in packet:
            self.stats['tcp'] += 1
            packet_data['protocol'] = 'TCP'
            packet_data['src_port'] = packet[TCP].sport
            packet_data['dst_port'] = packet[TCP].dport
            packet_data['flags'] = packet[TCP].flags
            
        elif UDP in packet:
            self.stats['udp'] += 1
            packet_data['protocol'] = 'UDP'
            packet_data['src_port'] = packet[UDP].sport
            packet_data['dst_port'] = packet[UDP].dport
            if DNS in packet:
                self.stats['dns'] += 1
                packet_data['payload'] = str(packet[DNS])
        
        # Put packet in queue for processing
        self.packet_queue.put(packet_data)
        
    def start_capture(self):
        """Start capturing packets in a separate thread"""
        self.capturing = True
        capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        capture_thread.start()
        print(f"[*] Started packet capture on {self.interface}")
        
    def _capture_loop(self):
        """Main capture loop"""
        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            store=False,
            stop_filter=lambda x: not self.capturing
        )
    
    def stop_capture(self):
        """Stop capturing packets"""
        self.capturing = False
        print(f"[*] Stopped capture. Total packets: {self.stats['total']}")
        
    def get_packet(self, timeout=1):
        """Get packet from queue (non-blocking)"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
