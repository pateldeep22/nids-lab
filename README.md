🌐 Network Intrusion Detection System (NIDS) - Custom Rules Lab
This repository contains the complete work for a cybersecurity project focused on the practical implementation of a Network Intrusion Detection System. The project involves building a virtual security lab, deploying Suricata as the NIDS engine, and developing a custom ruleset to detect a variety of simulated cyberattacks.

🚀 Project Overview
The primary goal of this project is to bridge the gap between theoretical knowledge of cyberattacks and the practical skills required to detect them. By creating a controlled lab environment, we can safely simulate real-world threats and write high-fidelity NIDS rules to generate timely and accurate alerts. This hands-on approach is fundamental to the roles of a Security Analyst in a Security Operations Center (SOC).

Key Features & Detections Implemented:
🌐 Network Reconnaissance: Detection of stealthy Nmap scans (SYN, FIN, Xmas, Null).

🔑 Application-Level Attacks: Detection of brute-force login attempts against SSH and FTP services using Hydra.

📞 Malware C2 Simulation: Detection of a simulated malware "beacon" communicating with its Command & Control server over HTTP.

🛠️ Lab Environment & Topology
The project operates within a safe, isolated virtual environment created using VMware. This ensures that all simulated attack traffic is contained and does not affect the host machine or external networks.

Virtualization: VMware Workstation

NIDS / Attacker Machine: Kali Linux (192.168.70.10)

Victim Machine: Windows 10 (192.168.70.20)

Network Mode: Host-Only (VMnet1) on a 192.168.70.0/24 subnet.


⚙️ Tech Stack
NIDS Engine: Suricata

Attack & Testing Tools: Nmap, Hydra, PowerShell, Python http.server

Operating Systems: Kali Linux, Windows 10

Virtualization: VMware Workstation

Version Control: Git & GitHub


📖 Quick Start & Replication Guide
This guide provides the steps to replicate the lab environment and run the tests. All commands are run from the Kali Linux VM unless specified otherwise.

1. Lab Setup
Configure VMware Network: Create a Host-Only network with the subnet 192.168.70.0/24 and DHCP disabled.

Assign Static IPs:

Set the Kali VM's IP to 192.168.70.10.

Set the Windows 10 VM's IP to 192.168.70.20.

Install Suricata on Kali:

sudo apt update && sudo apt install suricata -y

Configure Suricata:

Edit /etc/suricata/suricata.yaml.

Set HOME_NET to "[192.168.70.0/24]".

Add all files from the rules/ directory in this repository to the rule-files section.

2. Running a Test (Example: Nmap SYN Scan)
Start the NIDS: On the Kali VM, start Suricata in the foreground to see live alerts.

# Ensure the rules from this repo are in /etc/suricata/rules/
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

Launch the Attack: In a new Kali terminal, run the Nmap SYN scan against the victim.

sudo nmap -sS -Pn 192.168.70.20

Observe: The Suricata terminal will display the "NMAP TCP SYN Scan Detected" alert in real-time.

📜 Custom Rules Showcase
Below are a few examples of the custom rules developed during this project.

SSH Brute-Force Detection
This rule uses a rate-based filter to detect 5 connection attempts from the same source IP within 60 seconds, which is characteristic of an automated attack.

alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute-Force Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000006; rev:1;)

Malware C2 Beacon Detection
This rule uses Suricata's HTTP parser to inspect the User-Agent field for a non-standard string, a common signature for malware beacons.

alert http any any -> $HOME_NET 80 (msg:"Malware C2 Beacon Detected (Suspicious User-Agent)"; flow:to_server; http.user_agent; content:"C2-Beacon-Client"; sid:1000009; rev:1;)


Feel free to explore the repository. All rules, reports, and attack plans are documented in their respective folders.

