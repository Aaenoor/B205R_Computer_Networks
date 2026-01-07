"""
Wireshark PCAP Analyzer
Comprehensive network traffic analysis tool for security assessment
Author: B205 Computer Networks Project
Date: January 2026
"""

from scapy.all import *
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime
import json

class PCAPAnalyzer:
    """Main class for analyzing PCAP files"""

    def __init__(self, pcap_file):
        """
        Initialize the analyzer with a PCAP file

        Args:
            pcap_file (str): Path to the PCAP file
        """
        self.pcap_file = pcap_file
        self.packets = None
        self.analysis_results = {}
        print(f"[INFO] Initializing PCAP Analyzer for: {pcap_file}")

    def load_packets(self):
        """Load packets from PCAP file"""
        try:
            print(f"\n[+] Loading packets from {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            print(f"[SUCCESS] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load PCAP file: {e}")
            return False

    def analyze_protocol_distribution(self):
        """Analyze the distribution of protocols in the capture"""
        print("\n" + "=" * 70)
        print("PROTOCOL DISTRIBUTION ANALYSIS")
        print("=" * 70)

        protocol_counts = Counter()

        for pkt in self.packets:
            if pkt.haslayer(TCP):
                protocol_counts['TCP'] += 1
            elif pkt.haslayer(UDP):
                protocol_counts['UDP'] += 1
            elif pkt.haslayer(ICMP):
                protocol_counts['ICMP'] += 1
            elif pkt.haslayer(ARP):
                protocol_counts['ARP'] += 1
            else:
                protocol_counts['Other'] += 1

        self.analysis_results['protocols'] = dict(protocol_counts)

        print("\nProtocol Distribution:")
        for protocol, count in protocol_counts.most_common():
            percentage = (count / len(self.packets)) * 100
            print(f"  {protocol:10s}: {count:5d} packets ({percentage:5.2f}%)")

        return protocol_counts

    def analyze_ip_addresses(self):
        """Analyze source and destination IP addresses"""
        print("\n" + "=" * 70)
        print("IP ADDRESS ANALYSIS")
        print("=" * 70)

        src_ips = Counter()
        dst_ips = Counter()
        ip_pairs = Counter()

        for pkt in self.packets:
            if pkt.haslayer(IP):
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
                ip_pairs[(pkt[IP].src, pkt[IP].dst)] += 1

        print("\nTop 10 Source IP Addresses:")
        for ip, count in src_ips.most_common(10):
            print(f"  {ip:20s}: {count:5d} packets")

        print("\nTop 10 Destination IP Addresses:")
        for ip, count in dst_ips.most_common(10):
            print(f"  {ip:20s}: {count:5d} packets")

        self.analysis_results['src_ips'] = dict(src_ips.most_common(15))
        self.analysis_results['dst_ips'] = dict(dst_ips.most_common(15))
        self.analysis_results['ip_pairs'] = [
            {"src": k[0], "dst": k[1], "count": v}
            for k, v in ip_pairs.most_common(20)
        ]

        return src_ips, dst_ips

    def analyze_ports(self):
        """Analyze port usage and identify common services"""
        print("\n" + "=" * 70)
        print("PORT ANALYSIS")
        print("=" * 70)

        src_ports = Counter()
        dst_ports = Counter()

        port_names = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Proxy"
        }

        for pkt in self.packets:
            if pkt.haslayer(TCP):
                src_ports[pkt[TCP].sport] += 1
                dst_ports[pkt[TCP].dport] += 1
            elif pkt.haslayer(UDP):
                src_ports[pkt[UDP].sport] += 1
                dst_ports[pkt[UDP].dport] += 1

        print("\nTop 15 Destination Ports (Services):")
        for port, count in dst_ports.most_common(15):
            service = port_names.get(port, "Unknown")
            print(f"  Port {port:5d} ({service:15s}): {count:5d} packets")

        self.analysis_results['dst_ports'] = {
            port: {"count": count, "service": port_names.get(port, "Unknown")}
            for port, count in dst_ports.most_common(20)
        }

        return src_ports, dst_ports

    def detect_security_threats(self):
        """Detect potential security threats in the traffic"""
        print("\n" + "=" * 70)
        print("SECURITY THREAT DETECTION")
        print("=" * 70)

        threats = []

        # 1. Port Scan Detection
        port_scan_threshold = 10
        src_ip_ports = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].flags == 'S':  # SYN packets
                    src_ip_ports[pkt[IP].src].add(pkt[TCP].dport)

        print("\n[!] Port Scan Detection:")
        for ip, ports in src_ip_ports.items():
            if len(ports) > port_scan_threshold:
                threat = {
                    "type": "Port Scan",
                    "source_ip": ip,
                    "ports_scanned": len(ports),
                    "severity": "HIGH",
                    "description": f"Source {ip} attempted connections to {len(ports)} different ports"
                }
                threats.append(threat)
                print(f"  [HIGH] Port scan detected from {ip}: {len(ports)} ports scanned")

        # 2. DDoS Detection (SYN Flood)
        syn_flood_threshold = 50
        syn_packets = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].flags == 'S':
                    syn_packets[(pkt[IP].src, pkt[IP].dst)] += 1

        print("\n[!] DDoS Attack Detection (SYN Flood):")
        for (src, dst), count in syn_packets.items():
            if count > syn_flood_threshold:
                threat = {
                    "type": "DDoS - SYN Flood",
                    "source_ip": src,
                    "target_ip": dst,
                    "packet_count": count,
                    "severity": "CRITICAL",
                    "description": f"Potential SYN flood: {src} -> {dst} ({count} SYN packets)"
                }
                threats.append(threat)
                print(f"  [CRITICAL] SYN flood detected: {src} -> {dst} ({count} SYN packets)")

        # 3. ICMP Flood Detection
        icmp_threshold = 30
        icmp_packets = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(ICMP):
                icmp_packets[(pkt[IP].src, pkt[IP].dst)] += 1

        print("\n[!] ICMP Flood Detection:")
        for (src, dst), count in icmp_packets.items():
            if count > icmp_threshold:
                threat = {
                    "type": "ICMP Flood",
                    "source_ip": src,
                    "target_ip": dst,
                    "packet_count": count,
                    "severity": "HIGH",
                    "description": f"ICMP flood detected: {src} -> {dst} ({count} ICMP packets)"
                }
                threats.append(threat)
                print(f"  [HIGH] ICMP flood: {src} -> {dst} ({count} ICMP packets)")

        # 4. SSH Brute Force Detection
        ssh_threshold = 20
        ssh_attempts = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].dport == 22 and pkt[TCP].flags == 'S':
                    ssh_attempts[(pkt[IP].src, pkt[IP].dst)] += 1

        print("\n[!] SSH Brute Force Detection:")
        for (src, dst), count in ssh_attempts.items():
            if count > ssh_threshold:
                threat = {
                    "type": "SSH Brute Force",
                    "source_ip": src,
                    "target_ip": dst,
                    "attempt_count": count,
                    "severity": "HIGH",
                    "description": f"Possible SSH brute force: {src} -> {dst} ({count} attempts)"
                }
                threats.append(threat)
                print(f"  [HIGH] SSH brute force: {src} -> {dst} ({count} attempts)")

        # 5. Suspicious DNS Queries
        suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga']
        suspicious_keywords = ['malware', 'botnet', 'c2', 'phishing', 'hack']

        print("\n[!] Suspicious DNS Queries:")
        for pkt in self.packets:
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').lower()

                is_suspicious = any(tld in query for tld in suspicious_tlds) or \
                                any(keyword in query for keyword in suspicious_keywords)

                if is_suspicious:
                    if pkt.haslayer(IP):
                        threat = {
                            "type": "Suspicious DNS Query",
                            "source_ip": pkt[IP].src,
                            "query": query,
                            "severity": "MEDIUM",
                            "description": f"Suspicious DNS query from {pkt[IP].src}: {query}"
                        }
                        threats.append(threat)
                        print(f"  [MEDIUM] Suspicious DNS: {pkt[IP].src} querying {query}")

        # 6. Insecure Protocol Usage (Telnet)
        print("\n[!] Insecure Protocol Detection:")
        telnet_count = 0
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].dport == 23:
                telnet_count += 1

        if telnet_count > 0:
            threat = {
                "type": "Insecure Protocol",
                "protocol": "Telnet",
                "packet_count": telnet_count,
                "severity": "MEDIUM",
                "description": f"Insecure Telnet protocol detected ({telnet_count} packets)"
            }
            threats.append(threat)
            print(f"  [MEDIUM] Insecure Telnet usage: {telnet_count} packets")

        # 7. Excessive Outbound SMTP (Spam Detection)
        smtp_threshold = 15
        smtp_connections = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].dport == 25:
                    smtp_connections[pkt[IP].src] += 1

        print("\n[!] Spam Detection (Excessive SMTP):")
        for src_ip, count in smtp_connections.items():
            if count > smtp_threshold:
                threat = {
                    "type": "Possible Spam",
                    "source_ip": src_ip,
                    "smtp_connections": count,
                    "severity": "MEDIUM",
                    "description": f"Excessive SMTP connections from {src_ip} ({count} connections)"
                }
                threats.append(threat)
                print(f"  [MEDIUM] Possible spam source: {src_ip} ({count} SMTP connections)")

        self.analysis_results['threats'] = threats
        print(f"\n[SUMMARY] Total threats detected: {len(threats)}")

        return threats

    def analyze_traffic_patterns(self):
        """Analyze traffic patterns and statistics"""
        print("\n" + "=" * 70)
        print("TRAFFIC PATTERN ANALYSIS")
        print("=" * 70)

        # Packet size analysis
        packet_sizes = [len(pkt) for pkt in self.packets]

        print("\nPacket Size Statistics:")
        print(f"  Total Packets: {len(self.packets)}")
        print(f"  Average Size: {np.mean(packet_sizes):.2f} bytes")
        print(f"  Min Size: {np.min(packet_sizes)} bytes")
        print(f"  Max Size: {np.max(packet_sizes)} bytes")
        print(f"  Total Traffic: {sum(packet_sizes) / 1024:.2f} KB")

        # TCP Flags analysis
        tcp_flags = Counter()
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                tcp_flags[str(flags)] += 1

        print("\nTCP Flags Distribution:")
        for flag, count in tcp_flags.most_common():
            flag_name = {
                'S': 'SYN',
                'A': 'ACK',
                'F': 'FIN',
                'R': 'RST',
                'P': 'PSH',
                'SA': 'SYN-ACK',
                'FA': 'FIN-ACK',
                'PA': 'PSH-ACK'
            }.get(flag, flag)
            print(f"  {flag_name:10s}: {count:5d} packets")

        self.analysis_results['traffic_stats'] = {
            "total_packets": len(self.packets),
            "average_size": float(np.mean(packet_sizes)),
            "total_traffic_kb": sum(packet_sizes) / 1024
        }

        return packet_sizes

    def generate_visualizations(self, output_dir="../output"):
        """Generate visualization charts"""
        print("\n" + "=" * 70)
        print("GENERATING VISUALIZATIONS")
        print("=" * 70)

        import os
        os.makedirs(output_dir, exist_ok=True)

        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)

        # 1. Protocol Distribution Pie Chart
        print("\n[+] Creating protocol distribution chart...")
        protocols = self.analysis_results.get('protocols', {})
        if protocols:
            fig, ax = plt.subplots(figsize=(10, 8))
            colors = sns.color_palette("Set3", len(protocols))
            wedges, texts, autotexts = ax.pie(
                protocols.values(),
                labels=protocols.keys(),
                autopct='%1.1f%%',
                colors=colors,
                startangle=90
            )
            ax.set_title('Protocol Distribution', fontsize=16, fontweight='bold')
            plt.tight_layout()
            plt.savefig(f"{output_dir}/01_protocol_distribution.png", dpi=300, bbox_inches='tight')
            plt.close()
            print(f"  Saved: 01_protocol_distribution.png")

        # 2. Top Source IPs Bar Chart
        print("[+] Creating top source IPs chart...")
        src_ips = self.analysis_results.get('src_ips', {})
        if src_ips:
            fig, ax = plt.subplots(figsize=(12, 8))
            ips = list(src_ips.keys())[:10]
            counts = list(src_ips.values())[:10]
            bars = ax.barh(ips, counts, color=sns.color_palette("viridis", len(ips)))
            ax.set_xlabel('Packet Count', fontsize=12, fontweight='bold')
            ax.set_ylabel('Source IP Address', fontsize=12, fontweight='bold')
            ax.set_title('Top 10 Source IP Addresses', fontsize=16, fontweight='bold')
            ax.invert_yaxis()

            # Add value labels
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax.text(width, bar.get_y() + bar.get_height()/2, f' {int(width)}',
                        ha='left', va='center', fontweight='bold')

            plt.tight_layout()
            plt.savefig(f"{output_dir}/02_top_source_ips.png", dpi=300, bbox_inches='tight')
            plt.close()
            print(f"  Saved: 02_top_source_ips.png")

        # 3. Top Destination Ports
        print("[+] Creating destination ports chart...")
        dst_ports = self.analysis_results.get('dst_ports', {})
        if dst_ports:
            fig, ax = plt.subplots(figsize=(12, 8))
            ports = [f"Port {p} ({dst_ports[p]['service']})" for p in list(dst_ports.keys())[:10]]
            counts = [dst_ports[p]['count'] for p in list(dst_ports.keys())[:10]]
            bars = ax.bar(range(len(ports)), counts, color=sns.color_palette("rocket", len(ports)))
            ax.set_xticks(range(len(ports)))
            ax.set_xticklabels(ports, rotation=45, ha='right')
            ax.set_ylabel('Packet Count', fontsize=12, fontweight='bold')
            ax.set_title('Top 10 Destination Ports (Services)', fontsize=16, fontweight='bold')

            # Add value labels
            for i, bar in enumerate(bars):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}',
                        ha='center', va='bottom', fontweight='bold')

            plt.tight_layout()
            plt.savefig(f"{output_dir}/03_destination_ports.png", dpi=300, bbox_inches='tight')
            plt.close()
            print(f"  Saved: 03_destination_ports.png")

        # 4. Security Threats Summary
        print("[+] Creating security threats chart...")
        threats = self.analysis_results.get('threats', [])
        if threats:
            threat_types = Counter([t['type'] for t in threats])

            fig, ax = plt.subplots(figsize=(12, 8))
            types = list(threat_types.keys())
            counts = list(threat_types.values())
            colors_map = {'Port Scan': 'red', 'DDoS - SYN Flood': 'darkred',
                         'ICMP Flood': 'orange', 'SSH Brute Force': 'orangered',
                         'Suspicious DNS Query': 'gold', 'Insecure Protocol': 'yellow',
                         'Possible Spam': 'lightyellow'}
            colors = [colors_map.get(t, 'gray') for t in types]

            bars = ax.barh(types, counts, color=colors)
            ax.set_xlabel('Occurrence Count', fontsize=12, fontweight='bold')
            ax.set_ylabel('Threat Type', fontsize=12, fontweight='bold')
            ax.set_title('Security Threats Detected', fontsize=16, fontweight='bold')
            ax.invert_yaxis()

            # Add value labels
            for i, bar in enumerate(bars):
                width = bar.get_width()
                ax.text(width, bar.get_y() + bar.get_height()/2, f' {int(width)}',
                        ha='left', va='center', fontweight='bold')

            plt.tight_layout()
            plt.savefig(f"{output_dir}/04_security_threats.png", dpi=300, bbox_inches='tight')
            plt.close()
            print(f"  Saved: 04_security_threats.png")

        # 5. Traffic Volume Over Time (simulated)
        print("[+] Creating traffic timeline chart...")
        fig, ax = plt.subplots(figsize=(14, 6))
        packet_indices = range(len(self.packets))
        packet_sizes = [len(pkt) for pkt in self.packets]

        # Create bins
        bin_size = max(1, len(packet_indices) // 50)
        binned_packets = []
        binned_sizes = []

        for i in range(0, len(packet_indices), bin_size):
            binned_packets.append(i + bin_size // 2)
            binned_sizes.append(sum(packet_sizes[i:i+bin_size]))

        ax.fill_between(binned_packets, binned_sizes, alpha=0.6, color='steelblue')
        ax.plot(binned_packets, binned_sizes, color='darkblue', linewidth=2)
        ax.set_xlabel('Packet Sequence', fontsize=12, fontweight='bold')
        ax.set_ylabel('Traffic Volume (bytes)', fontsize=12, fontweight='bold')
        ax.set_title('Network Traffic Volume Over Capture Period', fontsize=16, fontweight='bold')
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(f"{output_dir}/05_traffic_timeline.png", dpi=300, bbox_inches='tight')
        plt.close()
        print(f"  Saved: 05_traffic_timeline.png")

        print("\n[SUCCESS] All visualizations generated!")

    def save_analysis_report(self, output_file="../output/analysis_report.json"):
        """Save analysis results to JSON file"""
        print(f"\n[+] Saving analysis report to {output_file}...")

        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)

        print(f"[SUCCESS] Analysis report saved!")

    def run_full_analysis(self):
        """Run complete analysis pipeline"""
        print("\n" + "=" * 70)
        print("STARTING COMPREHENSIVE NETWORK TRAFFIC ANALYSIS")
        print("B205 Computer Networks - Task 2")
        print("=" * 70)

        if not self.load_packets():
            return False

        self.analyze_protocol_distribution()
        self.analyze_ip_addresses()
        self.analyze_ports()
        self.analyze_traffic_patterns()
        self.detect_security_threats()
        self.generate_visualizations()
        self.save_analysis_report()

        print("\n" + "=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)
        print("\nGenerated files:")
        print("  - Visualizations: Task2/output/*.png")
        print("  - Analysis report: Task2/output/analysis_report.json")
        print("\n")

        return True


def main():
    """Main execution function"""
    pcap_file = "../data/network_capture.pcap"

    analyzer = PCAPAnalyzer(pcap_file)
    analyzer.run_full_analysis()


if __name__ == "__main__":
    main()
