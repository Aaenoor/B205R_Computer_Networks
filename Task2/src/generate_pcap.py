"""
PCAP File Generator for Network Analysis
Generates realistic network traffic with security threats for analysis
Author: B205 Computer Networks Project
Date: January 2026
"""

from scapy.all import *
import random
import time
from datetime import datetime

def generate_normal_traffic():
    """Generate normal HTTP/HTTPS traffic"""
    packets = []

    # Normal web browsing
    internal_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25"]
    web_servers = ["93.184.216.34", "142.250.185.46", "104.16.132.229"]

    for i in range(50):
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(web_servers)

        # HTTP GET requests
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(49152, 65535), dport=80, flags="S")
        packets.append(pkt)

        # HTTPS traffic
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(49152, 65535), dport=443, flags="S")
        packets.append(pkt)

    return packets

def generate_port_scan():
    """Generate port scanning activity (security threat)"""
    packets = []

    attacker_ip = "203.0.113.45"  # External attacker
    target_ip = "192.168.1.10"    # Internal target

    # SYN scan across multiple ports
    for port in range(20, 1025, 10):
        pkt = IP(src=attacker_ip, dst=target_ip)/TCP(sport=54321, dport=port, flags="S")
        packets.append(pkt)

    return packets

def generate_ddos_attack():
    """Generate DDoS attack pattern"""
    packets = []

    # Multiple external IPs targeting internal server
    target_ip = "192.168.1.100"  # Internal web server

    for i in range(200):
        # Randomized source IPs (spoofed)
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        # SYN flood
        pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packets.append(pkt)

    return packets

def generate_dns_traffic():
    """Generate DNS queries including suspicious ones"""
    packets = []

    internal_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
    dns_server = "8.8.8.8"

    # Normal DNS queries
    normal_domains = ["google.com", "facebook.com", "twitter.com", "amazon.com"]

    for domain in normal_domains * 3:
        src_ip = random.choice(internal_ips)
        pkt = IP(src=src_ip, dst=dns_server)/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)

    # Suspicious DNS queries (potential C&C communication)
    suspicious_domains = ["malware-c2-server.ru", "botnet-command.cn", "phishing-site.tk"]

    for domain in suspicious_domains * 5:
        src_ip = random.choice(internal_ips)
        pkt = IP(src=src_ip, dst=dns_server)/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)

    return packets

def generate_icmp_traffic():
    """Generate ICMP traffic including ping floods"""
    packets = []

    # Normal pings
    internal_ips = ["192.168.1.10", "192.168.1.15"]

    for i in range(10):
        pkt = IP(src=internal_ips[0], dst="8.8.8.8")/ICMP()
        packets.append(pkt)

    # ICMP flood attack
    attacker_ip = "198.51.100.33"
    target_ip = "192.168.1.10"

    for i in range(100):
        pkt = IP(src=attacker_ip, dst=target_ip)/ICMP()
        packets.append(pkt)

    return packets

def generate_ssh_bruteforce():
    """Generate SSH brute force attack pattern"""
    packets = []

    attacker_ip = "185.220.101.50"  # External attacker
    ssh_server = "192.168.1.50"      # Internal SSH server

    # Multiple connection attempts (brute force)
    for i in range(50):
        pkt = IP(src=attacker_ip, dst=ssh_server)/TCP(sport=random.randint(49152, 65535), dport=22, flags="S")
        packets.append(pkt)

    return packets

def generate_ftp_traffic():
    """Generate FTP traffic"""
    packets = []

    internal_ip = "192.168.1.15"
    ftp_server = "192.168.1.60"

    # FTP connection attempts
    for i in range(15):
        pkt = IP(src=internal_ip, dst=ftp_server)/TCP(sport=random.randint(49152, 65535), dport=21, flags="S")
        packets.append(pkt)

    return packets

def generate_smtp_spam():
    """Generate SMTP spam traffic"""
    packets = []

    # Internal compromised host sending spam
    compromised_host = "192.168.1.25"
    external_mail_servers = ["74.125.193.27", "209.85.128.27", "64.233.163.27"]

    for i in range(30):
        dst_ip = random.choice(external_mail_servers)
        pkt = IP(src=compromised_host, dst=dst_ip)/TCP(sport=random.randint(49152, 65535), dport=25, flags="S")
        packets.append(pkt)

    return packets

def generate_telnet_traffic():
    """Generate Telnet traffic (insecure protocol)"""
    packets = []

    # Telnet connections (insecure, should be blocked)
    internal_ip = "192.168.1.30"
    telnet_server = "192.168.1.70"

    for i in range(10):
        pkt = IP(src=internal_ip, dst=telnet_server)/TCP(sport=random.randint(49152, 65535), dport=23, flags="S")
        packets.append(pkt)

    return packets

def generate_database_traffic():
    """Generate database traffic"""
    packets = []

    # Normal database connections
    app_server = "192.168.1.40"
    db_server = "192.168.1.80"

    # MySQL traffic
    for i in range(20):
        pkt = IP(src=app_server, dst=db_server)/TCP(sport=random.randint(49152, 65535), dport=3306, flags="S")
        packets.append(pkt)

    # PostgreSQL traffic
    for i in range(15):
        pkt = IP(src=app_server, dst=db_server)/TCP(sport=random.randint(49152, 65535), dport=5432, flags="S")
        packets.append(pkt)

    return packets

def main():
    """Main function to generate comprehensive PCAP file"""
    print("=" * 70)
    print("B205 Computer Networks - PCAP Generator")
    print("Generating realistic network traffic with security threats...")
    print("=" * 70)

    all_packets = []

    # Generate different types of traffic
    print("\n[+] Generating normal web traffic...")
    all_packets.extend(generate_normal_traffic())

    print("[+] Generating port scan attack...")
    all_packets.extend(generate_port_scan())

    print("[+] Generating DDoS attack pattern...")
    all_packets.extend(generate_ddos_attack())

    print("[+] Generating DNS traffic (including suspicious)...")
    all_packets.extend(generate_dns_traffic())

    print("[+] Generating ICMP traffic (including flood)...")
    all_packets.extend(generate_icmp_traffic())

    print("[+] Generating SSH brute force attack...")
    all_packets.extend(generate_ssh_bruteforce())

    print("[+] Generating FTP traffic...")
    all_packets.extend(generate_ftp_traffic())

    print("[+] Generating SMTP spam traffic...")
    all_packets.extend(generate_smtp_spam())

    print("[+] Generating Telnet traffic (insecure)...")
    all_packets.extend(generate_telnet_traffic())

    print("[+] Generating database traffic...")
    all_packets.extend(generate_database_traffic())

    # Shuffle packets to make it more realistic
    random.shuffle(all_packets)

    # Write to PCAP file
    output_file = "../data/network_capture.pcap"
    print(f"\n[+] Writing {len(all_packets)} packets to {output_file}...")
    wrpcap(output_file, all_packets)

    print(f"\n[SUCCESS] PCAP file generated successfully!")
    print(f"File location: {output_file}")
    print(f"Total packets: {len(all_packets)}")
    print("\nSummary of traffic types:")
    print("  - Normal HTTP/HTTPS traffic")
    print("  - Port scanning attack")
    print("  - DDoS attack (SYN flood)")
    print("  - DNS queries (normal and suspicious)")
    print("  - ICMP traffic (including flood)")
    print("  - SSH brute force attempts")
    print("  - FTP connections")
    print("  - SMTP spam traffic")
    print("  - Telnet connections (insecure)")
    print("  - Database connections (MySQL, PostgreSQL)")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
