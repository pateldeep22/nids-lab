# 🚀 Project: Network Intrusion Detection System (NIDS) Lab

This repository contains the complete Proof of Concept (PoC) for deploying a **Suricata-based Network Intrusion Detection System (NIDS)** as part of a cybersecurity internship project. It demonstrates how to detect various types of network intrusions and application-level attacks using a custom-written ruleset.

It includes:

- Suricata **custom rules** for detecting Nmap scans, SSH/FTP brute-force attempts, and simulated malware C2 beacons.  
- A **step-by-step guide** to reproduce the lab environment and all test scenarios.  
- A full set of **weekly reports** and **attack plans** in the repository.

> **Lab Setup:** NIDS/Attacker: Kali Linux — Target: Windows 10 — Network: Host-Only LAN

## 📌 Project Overview

The goal is to configure Suricata with a custom ruleset to detect:  
✔️ Network Reconnaissance (Nmap SYN, FIN, Xmas, and Null Scans)  
✔️ Application-Level Attacks (SSH & FTP Brute-Force Attempts)  
✔️ Simulated Malware C2 Beacons (Suspicious HTTP User-Agent)

### **Key Features**

* **Virtual Security Lab:** A safe, isolated environment built with VMware for hands-on attack simulation.  
* **Custom Rule Development:** A full ruleset written from scratch to detect specific attack signatures.  
* **Real-time Detection:** Use of Suricata to analyze live traffic and generate immediate alerts.  
* **Comprehensive Documentation:** Includes weekly reports, attack plans, and a full guide to replicate the project.

## 📂 Repository Structure
```
nids-lab/  
│  
├── .gitignore  
├── README.md  
│  
├── configs/  
│   ├── suricata.yaml  
│   └── network-settings.md  

├── docs/  
│   ├── week1-lab-setup.md  
│   ├── week2-nmap-rules.md  
│   ├── week3-bruteforce-rules.md  
│   └── week4-c2-detection.md  
│  
├── rules/  
│   ├── local.rules  
│   ├── week2.rules  
│   ├── week3.rules  
│   └── week4.rules  
│  
└── attacks/  
    ├── nmap-tests.md  
    ├── hydra-tests.md  
    └── c2-simulations.md
```

---

## 🛠️ Setup & Replication Guide

### 1️⃣ On Target (Windows 10\)

1. **Set Static IP:** 192.168.70.20.  
2. **Enable OpenSSH Server:**  
   * Go to Settings \> Apps \> Optional features \> Add a feature.  
   * Install "OpenSSH Server".  
   * Go to services.msc, set "OpenSSH SSH Server" to Automatic, and start it.  
3. **Enable FTP Server:**  
   * Go to Turn Windows features on or off.  
   * Enable Internet Information Services \> FTP Server \> FTP Service.  
   * Go to IIS Manager, right-click Sites \> Add FTP Site..., and configure a basic site.  
   * Go to services.msc and ensure "Microsoft FTP Service" is running.  
4. **Disable Windows Firewall** for the test environment to ensure attacks are not blocked before reaching the services.

### 2️⃣ On Attacker/NIDS (Kali Linux)

1. **Set Static IP:** 192.168.70.10.  
```bash
2. # Install Tools:  
   sudo apt update && sudo apt install \-y suricata nmap hydra
```
3. **Deploy Custom Rules:**  
   * Copy all .rules files from this repository's rules/ directory into /etc/suricata/rules/.  
   * Edit /etc/suricata/suricata.yaml and add the rule files (local.rules, week2.rules, etc.) to the rule-files section.  
   * Ensure HOME\_NET is set to "\[192.168.70.0/24\]".

## 🚀 Attack Scenarios & Verification

For each test, run Suricata in one terminal and the attack command in another.

* **To Start Suricata (Terminal 1):**
```bash
# Run in the foreground to see live alerts
  sudo suricata \-c /etc/suricata/suricata.yaml \-i \<INTERFACE\>
```
* **To Verify After a Test:**  
```bash
# Search the log file for the specific alert message  
  grep "ALERT\_MESSAGE" /var/log/suricata/eve.json
```
### **1\) Nmap Scan Detection**

* **Attacker (Terminal 2):**  
```bash
# SYN Scan (-sS), FIN Scan (-sF), Xmas Scan (-sX), Null Scan (-sN)  
  sudo nmap \-sS \-Pn \<TARGET\_IP\>  
  sudo nmap \-sF \-Pn \<TARGET\_IP\>
```
* **Expected Alerts:** NMAP TCP SYN Scan Detected, NMAP FIN Scan Detected, etc.

### **2\) SSH Brute-Force Detection**

* **Attacker (Terminal 2):**  
```bash
# Create a password list  
  echo \-e "password\\nadmin\\nroot\\n123456" \> pass.txt  
  \# Launch the attack  
  hydra \-l \<USERNAME\> \-P pass.txt ssh://\<TARGET\_IP\>
```
* **Expected Alert:** SSH Brute-Force Attempt Detected

### **3\) FTP Brute-Force Detection**

* **Attacker (Terminal 2):**  
```bash
# Use a list of incorrect passwords  
  hydra \-l \<USERNAME\> \-P badpasswords.txt ftp://\<TARGET\_IP\>
```
* **Expected Alert:** FTP Brute-Force Attempt (Login Failed)

### **4\) Malware C2 Beacon Detection**

* **C2 Server (Kali Terminal 1):**  
```bash
# Start a simple web server to act as the C2  
  sudo python3 \-m http.server 80
```
* **NIDS (Kali Terminal 2):**  
```bash
# Start Suricata to monitor for the beacon  
  sudo suricata \-c /etc/suricata/suricata.yaml \-i \<INTERFACE\>
```
* **Infected Host (Windows PowerShell):**  
```bash
# Send the fake beacon with a suspicious User-Agent  
  Invoke-WebRequest \-Uri http://\<KALI\_IP\> \-Headers @{ "User-Agent" \= "C2-Beacon-Client" }
```
* **Expected Alert:** Malware C2 Beacon Detected (Suspicious User-Agent)

## **📜 Custom Rules Showcase**

#### **SSH Brute-Force Detection (Rate-Based)**

- This rule uses a detection\_filter to track connection attempts by source IP and only alerts after 5 attempts in 60 seconds.
```bash
alert tcp any any \-\> $HOME\_NET 22 (msg:"SSH Brute-Force Attempt Detected"; flow:to\_server,established; detection\_filter:track by\_src, count 5, seconds 60; sid:1000006; rev:1;)
```
#### **Malware C2 Beacon Detection (HTTP Content)**

- This rule uses Suricata's HTTP parser to inspect the User-Agent field for a specific, non-standard string.
```bash
alert http any any \-\> $HOME\_NET 80 (msg:"Malware C2 Beacon Detected (Suspicious User-Agent)"; flow:to\_server; http.user\_agent; content:"C2-Beacon-Client"; sid:1000009; rev:1;)
```
**Note:** Replace \<INTERFACE\>, \<TARGET\_IP\>, \<USERNAME\>, and \<KALI\_IP\> with your specific lab values (e.g., eth0, 192.168.70.20, etc.).

---

### 📑 Deliverables

*   **Weekly Lab Reports** → /docs/ (setup steps, attack scenarios, observations)
    
*   **Custom Rule Files** → /rules/ (local.rules, week-wise detection rules)
    
*   **Attack Simulation Plans** → /attacks/ (Nmap tests, Hydra brute-force, C2 beaconing)
    
*   **Configuration Files** → /configs/ (Suricata YAML, network settings for VMware)
    
*   **Complete GitHub Repository** → central location with rules, docs, configs, and evidence
    
---

### 📝 Notes

*   Update placeholders like , , , with actual values (e.g., eth0, 192.168.70.20).
    
*   Use **local SIDs in the 1000000+ range** to avoid conflicts with default Suricata rules.
    
*   Suricata logs are stored in /var/log/suricata/eve.json by default.
    
*   For extra validation, traffic can be captured with tcpdump or viewed in Wireshark.
    
---

### ⚖️ License

This project is distributed under the **MIT License**.You are free to **use, adapt, and share** the content with proper credit to the author.

---

### 🙌 Acknowledgements

*   **Suricata IDS** (OISF project) for open-source intrusion detection.
    
*   **Kali Linux toolkit** (Nmap, Hydra) for providing penetration testing utilities.
    
*   **Windows 10 services** (OpenSSH, FTP Server) as practical attack targets.
    
*   **VMware Workstation Pro** for enabling isolated virtual lab environments.
    
*   Internship mentors and project guidelines for direction and evaluation.
