import time
import json
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem

class IDS:
    def __init__(self, interface='eth0'):
        self.capture = PacketCapture(interface)
        self.analyzer = TrafficAnalyzer()
        self.detector = DetectionEngine()
        self.alert_system = AlertSystem()
        self.running = False
        self.packet_count = 0
        
    def start(self):
        """Start the IDS"""
        print(f"[+] Starting IDS on interface {self.capture.interface}")
        print("[+] Press Ctrl+C to stop")
        
        self.running = True
        self.capture.start_capture()
        
        try:
            while self.running:
                # Get packet from queue
                packet = self.capture.get_packet(timeout=0.5)
                if packet:
                    self.packet_count += 1
                    
                    # Analyze traffic
                    self.analyzer.update_flow_stats(packet)
                    
                    # Run detection
                    alerts = self.detector.analyze_traffic(packet, self.analyzer)
                    
                    if alerts:
                        for alert in alerts:
                            # Add additional context
                            alert['source'] = packet.get('src_ip')
                            alert['details'] = f"Packet: {packet.get('protocol')} {packet.get('src_port')}->{packet.get('dst_port')}"
                            self.alert_system.alert(alert)
                    
                    # Print status every 100 packets
                    if self.packet_count % 100 == 0:
                        print(f"[*] Processed {self.packet_count} packets, "
                              f"TCP: {self.capture.stats['tcp']}, "
                              f"UDP: {self.capture.stats['udp']}, "
                              f"DNS: {self.capture.stats['dns']}")
                
        except KeyboardInterrupt:
            print("\n[!] Shutting down IDS...")
            self.stop()
    
    def stop(self):
        """Stop the IDS"""
        self.running = False
        self.capture.stop_capture()
        print(f"[+] IDS stopped. Total packets processed: {self.packet_count}")
        print(f"[+] Total alerts generated: {self.alert_system.alerts_count}")
        
        # Print summary
        print("\n[+] Alert Summary:")
        try:
            with open('logs/alerts.jsonl', 'r') as f:
                lines = f.readlines()
                for line in lines[-5:]:  # Show last 5 alerts
                    alert = json.loads(line)
                    print(f"  - [{alert['timestamp']}] {alert['type']} from {alert['source']}")
        except FileNotFoundError:
            print("  - No alerts generated")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', default='eth0', 
                       help='Network interface to monitor (default: eth0)')
    parser.add_argument('--wifi', action='store_true',
                       help='Use WiFi interface (e.g., wlan0)')
    
    args = parser.parse_args()
    
    # Auto-detect interface
    interface = args.interface
    if args.wifi:
        interface = 'wlan0'
    
    print("[*] Available interfaces on this system:")
    print("[*] Check with: ipconfig")
    print(f"[*] Using interface: {interface}")
    
    # Initialize and start IDS
    ids = IDS(interface=interface)
    ids.start()
