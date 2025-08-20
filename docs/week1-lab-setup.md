# NIDS Project - Week 1 Report: Lab Setup & Baseline Testing

**Author:** Deep Patel  

---

## 1. Executive Summary

This report documents the successful setup and verification of a virtualized **Network Intrusion Detection System (NIDS)** laboratory.
The primary objective for this initial phase was to establish a controlled environment, install and configure the **Suricata** NIDS engine, and conduct a baseline test to confirm its operational status.

All objectives for Week 1 were met, resulting in a fully functional lab environment ready for advanced rule development and attack simulation.

---

## 2. Virtual Lab Environment Configuration

A secure, isolated network is essential for conducting intrusion detection tests safely.
We constructed a **private virtual network** using VMware Workstation, ensuring all traffic is contained within the lab.

### 2.1 VMware Virtual Network Setup

- **Mode:** Host-Only networking
- **Tool:** VMware Workstation – Virtual Network Editor
- **Network:** VMnet1 (Host-Only)
- **Configuration:**
  - **Subnet IP:** `192.168.70.0` – Defines the private network's address space.
  - **Subnet Mask:** `255.255.255.0` – Defines the range of available addresses.
  - **DHCP Service:** Disabled – Prevents automatic IP assignment and allows predictable static IPs.

### 2.2 Virtual Machine Network Configuration

Two VMs were configured for the lab: a **Kali Linux** machine (NIDS host) and a **Windows 10** machine (victim).

#### 2.2.1 Kali Linux (Attacker & NIDS Platform)

- **IP Address:** `192.168.70.10`
- **Static IP Configuration:**
```bash
sudo nmcli connection modify 'Wired connection 1' ipv4.method manual ipv4.addresses 192.168.70.10/24
sudo nmcli connection up 'Wired connection 1'
```
- **Verification Command:**
```bash
ip a
```

#### 2.2.2 Windows 10 (Victim Machine)

- **IP Address:** `192.168.70.20`
- **Static IP Configuration:**  
`Control Panel → Network and Sharing Center → Change adapter settings → Properties → IPv4 Settings`
- **Firewall:** Temporarily disabled on all profiles to ensure connectivity testing.
- **Verification Command:**
```cmd
ipconfig
```

---

## 3. NIDS Engine: Suricata Installation & Configuration

Suricata was selected for its modern architecture, stability, and active community.

### 3.1 Installation
```bash
sudo apt install suricata -y
```

### 3.2 Core Configuration

Main config file: `/etc/suricata/suricata.yaml`  
Key modifications:
1. **HOME_NET:** Set to the lab subnet:
   ```yaml
   HOME_NET: "[192.168.70.0/24]"
   ```
2. **Interface:** Confirmed `eth0` as monitoring interface.

---

## 4. System Verification & Baseline Test

A baseline test was conducted with a custom ICMP ping detection rule.

### 4.1 Custom Rule Definition
Rule file: `/etc/suricata/rules/local.rules`
```
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

### 4.2 Rule Activation
Added to `suricata.yaml`:
```yaml
rule-files:
  - suricata.rules
  - local.rules
```

### 4.3 Test Procedure
1. **Clear old logs:**
   ```bash
   sudo rm /var/log/suricata/eve.json
   ```
2. **Start Suricata:**
   ```bash
   sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
   ```
3. **Generate traffic:** Ping from Windows → Kali.
4. **Stop Suricata:**
   ```bash
   sudo killall suricata
   ```
5. **Verify alert:**
   ```bash
   grep "ICMP Ping Detected" /var/log/suricata/eve.json
   ```

**Result:** Alert successfully generated and logged.

---

## 5. Conclusion

Week 1 objectives have been met:
- Isolated lab environment configured.
- Suricata installed and tailored to lab settings.
- Custom ICMP rule tested and verified.

The project is ready to progress to **Week 2**, where advanced rules will be developed to detect various Nmap scans.

---

## References & Tools Used
- VMware Workstation (Host-Only networking)
- Kali Linux
- Windows 10
- Suricata (NIDS)
- nmcli, ip, ipconfig, grep
