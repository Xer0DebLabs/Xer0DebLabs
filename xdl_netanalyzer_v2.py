from scapy.all import *
import os
from datetime import datetime
import matplotlib.pyplot as plt
import json
import csv
from collections import defaultdict, Counter

class NetworkAnalyzer:
    def __init__(self):
        self.packets = None
        self.results = {}

    def load_pcap_file(self):
        """Prompt user for .pcap file and load it"""
        while True:
            file_path = input("Please enter the path to your .pcap file: ")
            if os.path.isfile(file_path) and file_path.endswith('.pcap'):
                try:
                    self.packets = rdpcap(file_path)
                    print(f"Successfully loaded {len(self.packets)} packets")
                    return True
                except Exception as e:
                    print(f"Error loading file: {e}")
                    return False
            else:
                print("Invalid file path or not a .pcap file. Please try again.")

    def basic_analysis(self):
        """Perform basic analysis of the packet capture"""
        self.results['total_packets'] = len(self.packets)
        
        # Initialize counters and variables
        protocols = defaultdict(int)
        packet_sizes = []
        
        for packet in self.packets:
            if IP in packet:
                # Counting protocols
                protocols[packet[IP].proto] += 1
                
                # Collecting packet sizes
                packet_sizes.append(len(packet))
        
        # Results storage
        self.results['protocols'] = {
            'counts': dict(protocols),
            'names': {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        }
        self.results['packet_sizes'] = {
            'average': sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
            'max': max(packet_sizes) if packet_sizes else 0,
            'min': min(packet_sizes) if packet_sizes else 0
        }

    def detect_anomalies(self):
        """Advanced anomaly detection"""
        src_ip_count = defaultdict(int)
        port_scans = defaultdict(int)
        unusual_sizes = []
        tcp_flags = defaultdict(int)
        time_deltas = []

        last_time = None
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                src_ip_count[src_ip] += 1
                
                if TCP in packet or UDP in packet:
                    port_scans[(src_ip, packet.sport)] += 1
                
                if len(packet) > 1500 or len(packet) < 20:
                    unusual_sizes.append((src_ip, len(packet)))
                
                if TCP in packet:
                    tcp_flags[packet[TCP].flags] += 1
                
                if packet.time:
                    if last_time:
                        delta = packet.time - last_time
                        time_deltas.append(delta)
                    last_time = packet.time

        self.results['anomalies'] = {
            'high_volume_ips': [ip for ip, count in src_ip_count.items() if count > 1000],
            'potential_port_scans': [k for k, v in port_scans.items() if v > 50],
            'unusual_packet_sizes': unusual_sizes[:10],  # Top 10
            'tcp_flag_distribution': dict(tcp_flags),
            'avg_packet_interval': sum(time_deltas) / len(time_deltas) if time_deltas else 0
        }

    def visualize_traffic(self):
        """Create visualizations of the traffic"""
        plt.figure(figsize=(12, 8))
        
        # Protocol distribution pie chart
        plt.subplot(2, 1, 1)
        proto_counts = self.results['protocols']['counts']
        labels = [self.results['protocols']['names'].get(p, f'Unknown({p})') 
                 for p in proto_counts.keys()]
        plt.pie(proto_counts.values(), labels=labels, autopct='%1.1f%%')
        plt.title('Protocol Distribution')

        # TCP Flags distribution
        if self.results['anomalies']['tcp_flag_distribution']:
            plt.subplot(2, 1, 2)
            flags = self.results['anomalies']['tcp_flag_distribution']
            plt.bar([str(f) for f in flags.keys()], flags.values())
            plt.title('TCP Flags Distribution')
            plt.xlabel('Flags')
            plt.ylabel('Count')

        plt.tight_layout()
        plt.savefig('traffic_visualization.png')
        print("Visualization saved as 'traffic_visualization.png'")

    def export_results(self):
        """Export analysis results in multiple formats"""
        while True:
            export_format = input("Export format (csv/json/both): ").lower()
            if export_format in ['csv', 'json', 'both']:
                break
            else:
                print("Invalid format. Please enter 'csv', 'json', or 'both'.")
        
        if export_format in ['csv', 'both']:
            with open('analysis_results.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                for key, value in self.results.items():
                    writer.writerow([key, str(value)])
        
        if export_format in ['json', 'both']:
            with open('analysis_results.json', 'w') as f:
                json.dump(self.results, f, indent=2)
        
        print(f"Results exported to {'CSV and JSON' if export_format == 'both' else export_format.upper()} format")

    def display_results(self):
        """Display analysis results"""
        print("\n=== Network Traffic Analysis Results ===")
        print(f"Total Packets: {self.results['total_packets']}")
        
        print("\nProtocol Distribution:")
        for proto, count in self.results['protocols']['counts'].items():
            name = self.results['protocols']['names'].get(proto, f'Unknown({proto})')
            print(f"{name}: {count} packets")
        
        print("\nPacket Size Statistics:")
        sizes = self.results['packet_sizes']
        print(f"Average: {sizes['average']:.2f} bytes")
        print(f"Maximum: {sizes['max']} bytes")
        print(f"Minimum: {sizes['min']} bytes")
        
        print("\nAnomaly Detection:")
        anomalies = self.results['anomalies']
        if anomalies['high_volume_ips']:
            print("High volume IPs:", anomalies['high_volume_ips'])
        if anomalies['potential_port_scans']:
            print("Potential port scans:", anomalies['potential_port_scans'])
        if anomalies['unusual_packet_sizes']:
            print("Unusual packet sizes:", anomalies['unusual_packet_sizes'])

def main():
    analyzer = NetworkAnalyzer()
    
    print("=== Network Traffic Analyzer ===")
    print(f"Current date: {datetime.now().strftime('%Y-%m-%d')}")
    
    if analyzer.load_pcap_file():
        analyzer.basic_analysis()
        analyzer.detect_anomalies()
        analyzer.display_results()
        analyzer.visualize_traffic()
        analyzer.export_results()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnalysis terminated by user")
    except Exception as e:
        print(f"An error occurred: {e}")
