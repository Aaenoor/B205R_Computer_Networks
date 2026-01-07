"""
Firewall Rules Generator
Generates DROP/PERMIT firewall rules based on network analysis
Author: B205 Computer Networks Project
Date: January 2026
"""

import json
from datetime import datetime


class FirewallRulesGenerator:
    """Generate firewall rules based on security analysis"""

    def __init__(self, analysis_file="../output/analysis_report.json"):
        """
        Initialize with analysis results

        Args:
            analysis_file (str): Path to analysis JSON file
        """
        self.analysis_file = analysis_file
        self.analysis_data = None
        self.rules = []

    def load_analysis(self):
        """Load analysis results from JSON file"""
        try:
            with open(self.analysis_file, 'r') as f:
                self.analysis_data = json.load(f)
            print(f"[SUCCESS] Loaded analysis data from {self.analysis_file}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load analysis: {e}")
            return False

    def generate_baseline_rules(self):
        """Generate baseline security rules"""
        print("\n" + "=" * 70)
        print("GENERATING BASELINE FIREWALL RULES")
        print("=" * 70)

        baseline_rules = [
            {
                "rule_id": "BASE-001",
                "action": "PERMIT",
                "protocol": "TCP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "ANY",
                "dst_port": "80",
                "description": "Allow outbound HTTP traffic from internal network",
                "justification": "Required for web browsing and application access"
            },
            {
                "rule_id": "BASE-002",
                "action": "PERMIT",
                "protocol": "TCP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "ANY",
                "dst_port": "443",
                "description": "Allow outbound HTTPS traffic from internal network",
                "justification": "Required for secure web browsing and encrypted communications"
            },
            {
                "rule_id": "BASE-003",
                "action": "PERMIT",
                "protocol": "UDP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "8.8.8.8, 8.8.4.4",
                "dst_port": "53",
                "description": "Allow DNS queries to trusted servers",
                "justification": "Required for domain name resolution (limited to trusted DNS servers)"
            },
            {
                "rule_id": "BASE-004",
                "action": "PERMIT",
                "protocol": "TCP",
                "src_ip": "192.168.1.40",
                "src_port": "ANY",
                "dst_ip": "192.168.1.80",
                "dst_port": "3306",
                "description": "Allow application server to MySQL database",
                "justification": "Required for application database connectivity"
            },
            {
                "rule_id": "BASE-005",
                "action": "PERMIT",
                "protocol": "TCP",
                "src_ip": "192.168.1.40",
                "src_port": "ANY",
                "dst_ip": "192.168.1.80",
                "dst_port": "5432",
                "description": "Allow application server to PostgreSQL database",
                "justification": "Required for application database connectivity"
            },
            {
                "rule_id": "BASE-006",
                "action": "PERMIT",
                "protocol": "ICMP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "ANY",
                "dst_port": "ANY",
                "description": "Allow ICMP echo requests (ping) from internal network",
                "justification": "Required for network diagnostics and troubleshooting",
                "rate_limit": "10 packets/second per source"
            },
            {
                "rule_id": "BASE-007",
                "action": "PERMIT",
                "protocol": "TCP",
                "src_ip": "TRUSTED_ADMIN_IPS",
                "src_port": "ANY",
                "dst_ip": "192.168.1.50",
                "dst_port": "22",
                "description": "Allow SSH access from trusted administrator IPs only",
                "justification": "Required for remote administration (restricted to admin IPs)"
            }
        ]

        self.rules.extend(baseline_rules)
        print(f"[+] Added {len(baseline_rules)} baseline PERMIT rules")

        return baseline_rules

    def generate_threat_based_rules(self):
        """Generate DROP rules based on detected threats"""
        print("\n" + "=" * 70)
        print("GENERATING THREAT-BASED DROP RULES")
        print("=" * 70)

        if not self.analysis_data:
            print("[WARNING] No analysis data available")
            return []

        threats = self.analysis_data.get('threats', [])
        threat_rules = []
        rule_counter = 1

        # Track unique threat sources
        malicious_ips = set()
        port_scan_sources = set()
        ddos_sources = set()

        for threat in threats:
            threat_type = threat.get('type')
            source_ip = threat.get('source_ip')

            if source_ip:
                malicious_ips.add(source_ip)

            # Port Scan Rules
            if threat_type == "Port Scan":
                port_scan_sources.add(source_ip)
                rule = {
                    "rule_id": f"THREAT-{rule_counter:03d}",
                    "action": "DROP",
                    "protocol": "TCP",
                    "src_ip": source_ip,
                    "src_port": "ANY",
                    "dst_ip": "192.168.1.0/24",
                    "dst_port": "ANY",
                    "description": f"Block port scanning activity from {source_ip}",
                    "justification": f"Source detected scanning {threat.get('ports_scanned', 'multiple')} ports - suspicious reconnaissance activity",
                    "threat_severity": threat.get('severity', 'HIGH'),
                    "log": True
                }
                threat_rules.append(rule)
                rule_counter += 1

            # DDoS Rules
            elif threat_type == "DDoS - SYN Flood":
                ddos_sources.add(source_ip)
                rule = {
                    "rule_id": f"THREAT-{rule_counter:03d}",
                    "action": "DROP",
                    "protocol": "TCP",
                    "src_ip": source_ip,
                    "src_port": "ANY",
                    "dst_ip": threat.get('target_ip', 'ANY'),
                    "dst_port": "ANY",
                    "description": f"Block DDoS SYN flood from {source_ip}",
                    "justification": f"Source sent {threat.get('packet_count', 'excessive')} SYN packets - DDoS attack pattern",
                    "threat_severity": "CRITICAL",
                    "log": True
                }
                threat_rules.append(rule)
                rule_counter += 1

            # ICMP Flood Rules
            elif threat_type == "ICMP Flood":
                rule = {
                    "rule_id": f"THREAT-{rule_counter:03d}",
                    "action": "DROP",
                    "protocol": "ICMP",
                    "src_ip": source_ip,
                    "src_port": "ANY",
                    "dst_ip": threat.get('target_ip', 'ANY'),
                    "dst_port": "ANY",
                    "description": f"Block ICMP flood from {source_ip}",
                    "justification": f"Source sent {threat.get('packet_count', 'excessive')} ICMP packets - flood attack",
                    "threat_severity": "HIGH",
                    "log": True
                }
                threat_rules.append(rule)
                rule_counter += 1

            # SSH Brute Force Rules
            elif threat_type == "SSH Brute Force":
                rule = {
                    "rule_id": f"THREAT-{rule_counter:03d}",
                    "action": "DROP",
                    "protocol": "TCP",
                    "src_ip": source_ip,
                    "src_port": "ANY",
                    "dst_ip": threat.get('target_ip', '192.168.1.50'),
                    "dst_port": "22",
                    "description": f"Block SSH brute force from {source_ip}",
                    "justification": f"Source made {threat.get('attempt_count', 'multiple')} SSH connection attempts - brute force attack",
                    "threat_severity": "HIGH",
                    "log": True
                }
                threat_rules.append(rule)
                rule_counter += 1

        self.rules.extend(threat_rules)
        print(f"[+] Added {len(threat_rules)} threat-based DROP rules")
        print(f"[+] Blocked {len(malicious_ips)} unique malicious IP addresses")

        return threat_rules

    def generate_protocol_security_rules(self):
        """Generate rules for blocking insecure protocols"""
        print("\n" + "=" * 70)
        print("GENERATING PROTOCOL SECURITY RULES")
        print("=" * 70)

        protocol_rules = [
            {
                "rule_id": "PROTO-001",
                "action": "DROP",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "23",
                "description": "Block all Telnet traffic (insecure protocol)",
                "justification": "Telnet transmits credentials in plaintext - use SSH instead",
                "threat_severity": "MEDIUM",
                "log": True
            },
            {
                "rule_id": "PROTO-002",
                "action": "DROP",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "21",
                "description": "Block FTP control connections from external sources",
                "justification": "FTP is insecure - use SFTP or FTPS instead",
                "threat_severity": "MEDIUM",
                "log": True
            },
            {
                "rule_id": "PROTO-003",
                "action": "DROP",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "139",
                "description": "Block NetBIOS Session Service",
                "justification": "NetBIOS is vulnerable to various attacks",
                "threat_severity": "MEDIUM",
                "log": True
            },
            {
                "rule_id": "PROTO-004",
                "action": "DROP",
                "protocol": "UDP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "137",
                "description": "Block NetBIOS Name Service",
                "justification": "NetBIOS can leak sensitive network information",
                "threat_severity": "MEDIUM",
                "log": True
            },
            {
                "rule_id": "PROTO-005",
                "action": "DROP",
                "protocol": "TCP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "ANY",
                "dst_port": "25",
                "description": "Block outbound SMTP except from designated mail server",
                "justification": "Prevents spam and compromised hosts from sending mass emails",
                "threat_severity": "MEDIUM",
                "exception": "Allow from 192.168.1.100 (mail server)",
                "log": True
            }
        ]

        self.rules.extend(protocol_rules)
        print(f"[+] Added {len(protocol_rules)} protocol security rules")

        return protocol_rules

    def generate_rate_limiting_rules(self):
        """Generate rate limiting rules to prevent resource exhaustion"""
        print("\n" + "=" * 70)
        print("GENERATING RATE LIMITING RULES")
        print("=" * 70)

        rate_limit_rules = [
            {
                "rule_id": "RATE-001",
                "action": "RATE_LIMIT",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "80",
                "description": "Rate limit HTTP connections",
                "justification": "Prevent HTTP flood attacks",
                "rate_limit": "100 connections/minute per source IP",
                "log": True
            },
            {
                "rule_id": "RATE-002",
                "action": "RATE_LIMIT",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "443",
                "description": "Rate limit HTTPS connections",
                "justification": "Prevent HTTPS flood attacks",
                "rate_limit": "100 connections/minute per source IP",
                "log": True
            },
            {
                "rule_id": "RATE-003",
                "action": "RATE_LIMIT",
                "protocol": "TCP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.50",
                "dst_port": "22",
                "description": "Rate limit SSH connection attempts",
                "justification": "Prevent SSH brute force attacks",
                "rate_limit": "5 connections/minute per source IP",
                "log": True
            },
            {
                "rule_id": "RATE-004",
                "action": "RATE_LIMIT",
                "protocol": "ICMP",
                "src_ip": "ANY",
                "src_port": "ANY",
                "dst_ip": "192.168.1.0/24",
                "dst_port": "ANY",
                "description": "Rate limit ICMP echo requests",
                "justification": "Prevent ICMP flood attacks while allowing legitimate ping",
                "rate_limit": "10 packets/second per source IP",
                "log": True
            },
            {
                "rule_id": "RATE-005",
                "action": "RATE_LIMIT",
                "protocol": "UDP",
                "src_ip": "192.168.1.0/24",
                "src_port": "ANY",
                "dst_ip": "ANY",
                "dst_port": "53",
                "description": "Rate limit DNS queries",
                "justification": "Prevent DNS amplification attacks and excessive queries",
                "rate_limit": "50 queries/minute per source IP",
                "log": True
            }
        ]

        self.rules.extend(rate_limit_rules)
        print(f"[+] Added {len(rate_limit_rules)} rate limiting rules")

        return rate_limit_rules

    def generate_default_deny_rule(self):
        """Generate default deny rule"""
        print("\n" + "=" * 70)
        print("GENERATING DEFAULT DENY RULE")
        print("=" * 70)

        default_rule = {
            "rule_id": "DEFAULT-001",
            "action": "DROP",
            "protocol": "ANY",
            "src_ip": "ANY",
            "src_port": "ANY",
            "dst_ip": "192.168.1.0/24",
            "dst_port": "ANY",
            "description": "Default deny all traffic not explicitly permitted",
            "justification": "Security best practice - whitelist approach, deny all by default",
            "log": True
        }

        self.rules.append(default_rule)
        print(f"[+] Added default DENY rule")

        return default_rule

    def save_rules(self, output_file="../output/firewall_rules.txt"):
        """Save firewall rules to text file"""
        print("\n" + "=" * 70)
        print("SAVING FIREWALL RULES")
        print("=" * 70)

        with open(output_file, 'w') as f:
            f.write("=" * 90 + "\n")
            f.write("COMPREHENSIVE FIREWALL RULES CONFIGURATION\n")
            f.write("B205 Computer Networks - Task 2\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 90 + "\n\n")

            f.write("FIREWALL RULES SUMMARY\n")
            f.write("-" * 90 + "\n")
            f.write(f"Total Rules: {len(self.rules)}\n")
            permit_count = len([r for r in self.rules if r['action'] == 'PERMIT'])
            drop_count = len([r for r in self.rules if r['action'] == 'DROP'])
            rate_limit_count = len([r for r in self.rules if r['action'] == 'RATE_LIMIT'])
            f.write(f"PERMIT Rules: {permit_count}\n")
            f.write(f"DROP Rules: {drop_count}\n")
            f.write(f"RATE_LIMIT Rules: {rate_limit_count}\n\n")

            # Group rules by category
            categories = {
                "BASELINE PERMIT RULES": [r for r in self.rules if r['rule_id'].startswith('BASE')],
                "THREAT-BASED DROP RULES": [r for r in self.rules if r['rule_id'].startswith('THREAT')],
                "PROTOCOL SECURITY RULES": [r for r in self.rules if r['rule_id'].startswith('PROTO')],
                "RATE LIMITING RULES": [r for r in self.rules if r['rule_id'].startswith('RATE')],
                "DEFAULT RULES": [r for r in self.rules if r['rule_id'].startswith('DEFAULT')]
            }

            for category, rules in categories.items():
                if rules:
                    f.write("\n" + "=" * 90 + "\n")
                    f.write(f"{category}\n")
                    f.write("=" * 90 + "\n\n")

                    for rule in rules:
                        f.write(f"Rule ID: {rule['rule_id']}\n")
                        f.write(f"Action: {rule['action']}\n")
                        f.write(f"Protocol: {rule['protocol']}\n")
                        f.write(f"Source: {rule['src_ip']}:{rule['src_port']}\n")
                        f.write(f"Destination: {rule['dst_ip']}:{rule['dst_port']}\n")
                        f.write(f"Description: {rule['description']}\n")
                        f.write(f"Justification: {rule['justification']}\n")

                        if 'threat_severity' in rule:
                            f.write(f"Threat Severity: {rule['threat_severity']}\n")
                        if 'rate_limit' in rule:
                            f.write(f"Rate Limit: {rule['rate_limit']}\n")
                        if 'log' in rule and rule['log']:
                            f.write("Logging: ENABLED\n")
                        if 'exception' in rule:
                            f.write(f"Exception: {rule['exception']}\n")

                        f.write("-" * 90 + "\n\n")

            # Implementation guide
            f.write("\n" + "=" * 90 + "\n")
            f.write("IMPLEMENTATION GUIDE\n")
            f.write("=" * 90 + "\n\n")
            f.write("1. Rule Order:\n")
            f.write("   - Rules are processed in order: Baseline -> Threat-based -> Protocol -> Rate Limiting -> Default\n")
            f.write("   - More specific rules should be placed before general rules\n\n")
            f.write("2. Logging:\n")
            f.write("   - All security-related rules have logging enabled\n")
            f.write("   - Regular review of logs is essential for security monitoring\n\n")
            f.write("3. Rate Limiting:\n")
            f.write("   - Implement at network edge or using specialized DDoS protection\n")
            f.write("   - Adjust thresholds based on legitimate traffic patterns\n\n")
            f.write("4. Maintenance:\n")
            f.write("   - Review and update rules regularly based on new threats\n")
            f.write("   - Remove or adjust rules as network requirements change\n")
            f.write("   - Monitor false positives and adjust accordingly\n\n")
            f.write("5. Testing:\n")
            f.write("   - Test rules in monitoring mode before enforcement\n")
            f.write("   - Verify legitimate traffic is not blocked\n")
            f.write("   - Document any changes or exceptions\n\n")

        print(f"[SUCCESS] Firewall rules saved to: {output_file}")

        # Also save as JSON for programmatic use
        json_file = output_file.replace('.txt', '.json')
        with open(json_file, 'w') as f:
            json.dump(self.rules, f, indent=2)
        print(f"[SUCCESS] Firewall rules saved to: {json_file}")

    def generate_all_rules(self):
        """Generate all firewall rules"""
        print("\n" + "=" * 70)
        print("FIREWALL RULES GENERATOR")
        print("B205 Computer Networks - Task 2")
        print("=" * 70)

        # Load analysis if available
        if self.analysis_file:
            self.load_analysis()

        # Generate all rule categories
        self.generate_baseline_rules()
        self.generate_threat_based_rules()
        self.generate_protocol_security_rules()
        self.generate_rate_limiting_rules()
        self.generate_default_deny_rule()

        # Save rules
        self.save_rules()

        print("\n" + "=" * 70)
        print("FIREWALL RULES GENERATION COMPLETE")
        print("=" * 70)
        print(f"\nTotal Rules Generated: {len(self.rules)}")
        print(f"PERMIT Rules: {len([r for r in self.rules if r['action'] == 'PERMIT'])}")
        print(f"DROP Rules: {len([r for r in self.rules if r['action'] == 'DROP'])}")
        print(f"RATE_LIMIT Rules: {len([r for r in self.rules if r['action'] == 'RATE_LIMIT'])}")
        print("\n")


def main():
    """Main execution function"""
    generator = FirewallRulesGenerator()
    generator.generate_all_rules()


if __name__ == "__main__":
    main()
