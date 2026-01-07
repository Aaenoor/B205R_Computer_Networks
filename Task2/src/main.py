"""
Main Execution Script for Task 2
Wireshark Analysis and Firewall Configuration
Author: B205 Computer Networks Project
Date: January 2026
"""

import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from generate_pcap import main as generate_pcap_main
from pcap_analyzer import PCAPAnalyzer
from firewall_rules_generator import FirewallRulesGenerator


def print_banner():
    """Print application banner"""
    print("\n")
    print("=" * 80)
    print("|" + "=" * 78 + "|")
    print("|" + " " * 20 + "B205 COMPUTER NETWORKS - TASK 2" + " " * 27 + "|")
    print("|" + " " * 16 + "WIRESHARK ANALYSIS & FIREWALL CONFIGURATION" + " " * 19 + "|")
    print("|" + " " * 19 + "Gisma University of Applied Sciences" + " " * 23 + "|")
    print("|" + "=" * 78 + "|")
    print("=" * 80)
    print()


def main():
    """Main execution function"""
    print_banner()

    print("TASK 2: Network Traffic Analysis and Firewall Configuration")
    print("\nThis program will:")
    print("  1. Generate realistic network traffic (PCAP file)")
    print("  2. Analyze the traffic for security threats")
    print("  3. Generate comprehensive firewall rules")
    print("  4. Create visualizations and reports")
    print()
    print("=" * 80)

    try:
        # Step 1: Generate PCAP file
        print("\n[STEP 1/3] Generating Network Traffic Capture...")
        print("-" * 80)
        generate_pcap_main()

        # Step 2: Analyze PCAP file
        print("\n[STEP 2/3] Analyzing Network Traffic...")
        print("-" * 80)
        pcap_file = "../data/network_capture.pcap"
        analyzer = PCAPAnalyzer(pcap_file)
        analyzer.run_full_analysis()

        # Step 3: Generate firewall rules
        print("\n[STEP 3/3] Generating Firewall Rules...")
        print("-" * 80)
        firewall_generator = FirewallRulesGenerator()
        firewall_generator.generate_all_rules()

        # Final Summary
        print("\n" + "=" * 80)
        print("ALL TASKS COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        print("\n[+] Generated Files:")
        print("  |-- Data/")
        print("  |   |-- network_capture.pcap (Network traffic capture)")
        print("  |-- Output/")
        print("  |   |-- 01_protocol_distribution.png")
        print("  |   |-- 02_top_source_ips.png")
        print("  |   |-- 03_destination_ports.png")
        print("  |   |-- 04_security_threats.png")
        print("  |   |-- 05_traffic_timeline.png")
        print("  |   |-- analysis_report.json")
        print("  |   |-- firewall_rules.txt")
        print("  |   |-- firewall_rules.json")
        print()
        print("[+] Next Steps:")
        print("  1. Review the analysis report in output/analysis_report.json")
        print("  2. Examine the visualizations in the output/ folder")
        print("  3. Review firewall rules in output/firewall_rules.txt")
        print("  4. Complete the Word documentation with findings")
        print()
        print("=" * 80)
        print("\n[SUCCESS] Task 2 execution complete!\n")

    except Exception as e:
        print(f"\n[ERROR] An error occurred during execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
