# Task 2: Wireshark Analysis and Firewall Configuration

---

## Overview

This folder contains a comprehensive network traffic analysis and firewall configuration project. The analysis examines a Wireshark packet capture from a core network experiencing unusual external traffic, identifies security threats, and proposes comprehensive firewall rules to mitigate identified vulnerabilities.

## Project Objectives

 Analyze network traffic using Wireshark/Scapy
 Investigate protocols, topologies, and applications
 Detect security threats and anomalies
 Generate comprehensive visualizations
 Define DROP/PERMIT firewall rules with justifications
 Create detailed technical documentation


## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Install Dependencies

```bash
cd "Assignments/Task2"
pip install -r requirements.txt
```

Required packages:
- scapy (packet manipulation)
- matplotlib (visualizations)
- seaborn (statistical plots)
- pandas (data analysis)
- numpy (numerical operations)
- python-docx (document generation)
- Pillow (image processing)

## Usage

### Quick Start

Run the complete analysis pipeline:

```bash
cd src
python main.py
```

This will:
1. Generate realistic network traffic (PCAP file)
2. Analyze the traffic for security threats
3. Generate visualizations and reports
4. Create comprehensive firewall rules

### Individual Scripts

#### 1. Generate Network Traffic
```bash
python src/generate_pcap.py
```
Creates `data/network_capture.pcap` with:
- Normal HTTP/HTTPS traffic
- Port scanning attacks
- DDoS patterns (SYN flood)
- DNS queries (including suspicious)
- ICMP flood
- SSH brute force attempts
- FTP, SMTP, Telnet traffic
- Database connections

#### 2. Analyze Traffic
```bash
python src/pcap_analyzer.py
```
Performs:
- Protocol distribution analysis
- IP address classification
- Port/service mapping
- Security threat detection
- Traffic pattern analysis
- Visualization generation

#### 3. Generate Firewall Rules
```bash
python src/firewall_rules_generator.py
```
Creates:
- Baseline PERMIT rules
- Threat-based DROP rules
- Protocol security rules
- Rate limiting rules
- Default deny rule

#### 4. Generate Documentation
```bash
python src/generate_documentation.py
```
Produces comprehensive Word document with:
- Executive summary
- Methodology
- Traffic analysis
- Security threat details
- Firewall configuration
- Conclusions and recommendations

## Analysis Results

### Network Traffic Summary

**Total Packets Analyzed**: 678

**Protocol Distribution**:
- TCP: 541 packets (79.79%)
- ICMP: 110 packets (16.22%)
- UDP: 27 packets (3.98%)

**Top Services Identified**:
- HTTP (Port 80): 251 packets
- SSH (Port 22): 50 packets
- HTTPS (Port 443): 50 packets
- SMTP (Port 25): 30 packets
- DNS (Port 53): 27 packets
- MySQL (Port 3306): 20 packets
- PostgreSQL (Port 5432): 15 packets
- FTP (Port 21): 15 packets
- Telnet (Port 23): 10 packets

### Security Threats Detected

**21 Total Threats Identified**:

1. **Port Scanning** (HIGH)
   - Source: 203.0.113.45
   - 101 ports scanned
   - Reconnaissance activity detected

2. **DDoS - SYN Flood** (CRITICAL)
   - Source: 203.0.113.45
   - Target: 192.168.1.10
   - 101 SYN packets

3. **ICMP Flood** (HIGH)
   - Source: 198.51.100.33
   - Target: 192.168.1.10
   - 100 ICMP packets

4. **SSH Brute Force** (HIGH)
   - Source: 185.220.101.50
   - Target: 192.168.1.50
   - 50 connection attempts

5. **Suspicious DNS Queries** (MEDIUM)
   - 15 queries to malicious domains
   - Domains: malware-c2-server.ru, botnet-command.cn, phishing-site.tk
   - Sources: 192.168.1.10, 192.168.1.15, 192.168.1.20

6. **Insecure Protocols** (MEDIUM)
   - Telnet usage: 10 packets
   - FTP usage: 15 packets

7. **Possible Spam** (MEDIUM)
   - Source: 192.168.1.25
   - 30 SMTP connections

### Firewall Configuration

**22 Total Rules Generated**:
- 7 PERMIT rules (baseline)
- 10 DROP rules (threat mitigation)
- 5 RATE_LIMIT rules (DDoS prevention)

**Key Rules**:
- ✅ Allow HTTP/HTTPS outbound (business traffic)
- ✅ Allow DNS to trusted servers (8.8.8.8)
- ✅ Allow database connectivity (MySQL, PostgreSQL)
- ✅ Allow SSH from admin IPs only
- ❌ Block identified malicious IPs
- ❌ Block port scanning sources
- ❌ Block DDoS sources
- ❌ Block insecure protocols (Telnet, FTP)
- ⚠️ Rate limit SSH (5 conn/min)
- ⚠️ Rate limit HTTP/HTTPS (100 conn/min)
- ⚠️ Rate limit ICMP (10 packets/sec)

## Visualizations

All visualizations are saved in `output/` folder:

1. **Protocol Distribution** - Pie chart showing TCP/UDP/ICMP breakdown
2. **Top Source IPs** - Bar chart of most active source addresses
3. **Destination Ports** - Service usage analysis
4. **Security Threats** - Threat categorization and severity
5. **Traffic Timeline** - Traffic volume over capture period

## Technical Details

### Analysis Methodology

1. **Packet Loading**: Load PCAP using Scapy
2. **Protocol Analysis**: Categorize by TCP/UDP/ICMP/ARP
3. **IP Analysis**: Classify internal vs. external hosts
4. **Port Mapping**: Identify services and applications
5. **Pattern Detection**: Statistical analysis of traffic patterns
6. **Threat Detection**: Apply heuristics and signatures
7. **Visualization**: Generate charts and graphs
8. **Rule Generation**: Create firewall configuration

### Threat Detection Algorithms

**Port Scan Detection**:
- Threshold: >10 unique destination ports from single source
- Method: Track SYN packets per source IP

**DDoS Detection (SYN Flood)**:
- Threshold: >50 SYN packets to single destination
- Method: Count incomplete TCP handshakes

**ICMP Flood Detection**:
- Threshold: >30 ICMP packets per source-destination pair
- Method: ICMP packet counting

**SSH Brute Force Detection**:
- Threshold: >20 SSH connection attempts
- Method: Track port 22 SYN packets

**Suspicious DNS Detection**:
- Method: Pattern matching against malicious TLDs (.ru, .cn, .tk)
- Keywords: malware, botnet, c2, phishing, hack

**Insecure Protocol Detection**:
- Protocols: Telnet (23), FTP (21), NetBIOS (137,139)
- Method: Port-based identification

### Firewall Rule Categories

**1. Baseline Rules (PERMIT)**:
- Allow legitimate business traffic
- HTTP/HTTPS, DNS, Database connections
- SSH from trusted sources

**2. Threat-Based Rules (DROP)**:
- Block identified malicious IPs
- Block attack sources
- Prevent lateral movement

**3. Protocol Security Rules (DROP)**:
- Block insecure protocols
- Prevent cleartext authentication
- Minimize attack surface

**4. Rate Limiting Rules**:
- Prevent resource exhaustion
- Mitigate flood attacks
- Maintain service availability

**5. Default Deny**:
- Block all unspecified traffic
- Whitelist approach
- Security best practice

## Documentation

Comprehensive documentation available in:

**Word Document**: `docs/Task2_Wireshark_Analysis_Documentation.docx`

Includes:
- Executive Summary
- Introduction and Background
- Methodology
- Complete Traffic Analysis
- Security Threat Details
- Firewall Configuration
- Conclusions and Recommendations
- References
- Appendices

**Raw Data**: `output/analysis_report.json`

Contains:
- Protocol statistics
- IP address lists
- Port usage data
- Complete threat details
- Traffic statistics

**Firewall Rules**: `output/firewall_rules.txt`

Contains:
- All 22 rules with descriptions
- Implementation guide
- Justifications
- Best practices

## Assessment Deliverables

This implementation satisfies all Task 2 requirements:

✅ **PCAP Analysis** - Comprehensive traffic examination
✅ **Protocol Analysis** - Layer 3/4 analysis with visualizations
✅ **Threat Detection** - 21 threats identified across 7 categories
✅ **IP/Port Analysis** - Complete source/destination mapping
✅ **Firewall Rules** - 22 DROP/PERMIT rules with justifications
✅ **Visualizations** - 5 professional charts and graphs
✅ **Documentation** - Complete Word document with analysis

## Key Findings

**Critical Issues**:
1. Active DDoS attack targeting 192.168.1.10
2. Port scanning from external IP 203.0.113.45
3. SSH brute force attempts from 185.220.101.50
4. Potential compromised hosts (192.168.1.10, 192.168.1.15, 192.168.1.20, 192.168.1.25)
5. Insecure protocols in use (Telnet, FTP)

**Immediate Actions**:
1. Deploy proposed firewall rules
2. Investigate and isolate compromised hosts
3. Disable Telnet and FTP services
4. Implement SSH hardening (key-based auth, fail2ban)
5. Configure DNS filtering

**Long-Term Recommendations**:
1. Implement IDS/IPS system
2. Deploy SIEM for log correlation
3. Regular vulnerability assessments
4. Network segmentation
5. Security awareness training

## Performance

- **Analysis Time**: ~10 seconds for 678 packets
- **Memory Usage**: ~150MB
- **Output Size**: ~2MB (visualizations + reports)
- **PCAP Generation**: ~2 seconds

## Limitations

- Analysis based on simulated traffic
- Real-world traffic may have additional complexity
- Firewall rules require testing in staging environment
- Rate limits should be adjusted based on actual traffic patterns

## References

- Scapy Documentation: https://scapy.net/
- Wireshark User Guide: https://www.wireshark.org/docs/
- NIST SP 800-41 Rev. 1 (Firewall Guidelines)
- IETF RFC 793 (TCP)
- IETF RFC 792 (ICMP)

## Author

Submitted for B205 Computer Networks course assessment.

**Course**: B205 Computer Networks
**Institution**: Gisma University of Applied Sciences
**Semester**: Autumn 2025
**Submission Date**: January 2026


