Attack Plan: Week 2 - Nmap Reconnaissance Scans
This document contains the official commands used to generate network scan traffic for testing our NIDS rules.

Target IP: 199.168.70.20 (Windows 10 Victim)
Source IP: 199.168.70.10 (Kali Linux Attacker)

1. TCP SYN Scan (Stealth Scan)
Purpose: To identify open TCP ports without completing the three-way handshake, making the scan less likely to be logged by basic firewalls.

Command:

sudo nmap -sS -Pn 199.168.70.20

Flag Explanation:

sudo: Executes Nmap with root privileges, which is required for crafting raw packets for a SYN scan.

-sS: Specifies a TCP SYN scan.

-Pn: Instructs Nmap to skip the initial host discovery (ping) phase and proceed directly to port scanning. This is necessary to bypass firewalls that block pings.

2. TCP FIN Scan
Purpose: To identify open ports by sending a TCP packet with only the FIN flag set. Open ports on a target system will typically respond with an RST packet.

Command:

sudo nmap -sF -Pn 199.168.70.20

Flag Explanation:

-sF: Specifies a TCP FIN scan.

3. TCP Xmas Scan
Purpose: To identify open ports by sending a malformed TCP packet with the FIN, PSH, and URG flags set simultaneously (like a lit-up Christmas tree). Open ports will typically respond with an RST packet.

Command:

sudo nmap -sX -Pn 199.168.70.20

Flag Explanation:

-sX: Specifies a TCP Xmas scan.

4. TCP Null Scan
Purpose: To identify open ports by sending a TCP packet with no flags set at all. This is another type of malformed packet that will elicit an RST response from an open port.

Command:

sudo nmap -sN -Pn 199.168.70.20

Flag Explanation:

-sN: Specifies a TCP Null scan.
