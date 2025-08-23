**NIDS Project** - Week 4 Report: Detecting C2 Beaconing
**Author:** Deep Patel

**1.0 Introduction**
**1.1 Objective**
The objective for the final week of rule development was to create a rule capable of identifying a simulated malware Command and Control (C2) beacon. Modern malware often disguises its "phone home" traffic as legitimate HTTP web requests. This phase focused on using Suricata's HTTP protocol parser to inspect specific parts of a web request to find anomalous signatures that indicate malicious activity.

**1.2 Methodology**
**C2 Server Simulation:** A simple Python web server was run on the Kali machine to act as the C2 server, listening for incoming beacons.

**Rule Development:** A Suricata rule was written to inspect the User-Agent field within HTTP requests for a custom, non-standard string.

**Beacon Simulation:** A beacon was generated from the Windows 10 VM using PowerShell, which allowed for the crafting of a custom HTTP request with the suspicious User-Agent.

**Verification:** The Suricata log files were analyzed to confirm the alert was triggered.

**2.0 Malware C2 Beacon Detection
2.1 Concept & Strategy**
Malware beaconing is the process by which an infected machine periodically contacts an attacker-controlled C2 server to receive commands. This traffic is often disguised as normal web browsing. A common indicator of a malicious beacon is a non-standard or unique User-Agent string. A User-Agent identifies the client (e.g., "Mozilla Firefox," "Chrome") making a web request. Malware often uses a custom string that no legitimate browser would use. Our strategy is to write a rule that specifically looks for this custom User-Agent.

**2.2 Rule Development**
The following rule was added to /etc/suricata/rules/week4.rules. It uses Suricata's http keyword to efficiently parse web traffic.

**Rule:**

alert http any any -> $HOME_NET 80 (msg:"Malware C2 Beacon Detected (Suspicious User-Agent)"; flow:to_server; http.user_agent; content:"C2-Beacon-Client"; sid:1000009; rev:1;)

**Rule Explanation:
**
alert http: Use the built-in HTTP protocol parser and generate an alert.

http.user_agent;: A specific keyword that tells the rule to look only within the User-Agent field of the HTTP header.

content:"C2-Beacon-Client";: The core signature. The rule will only trigger if it finds this exact string within the User-Agent field.

**2.3 Testing & Verification
**The attack was simulated by sending a single crafted web request from the Windows 10 victim.

**C2 Server Command (on Kali):
**
sudo python3 -m http.server 80

Beacon Simulation Command (on Windows PowerShell):

Invoke-WebRequest -Uri http://192.168.70.10 -Headers @{ "User-Agent" = "C2-Beacon-Client" }

Verification Command (on Kali):

grep "Malware C2 Beacon" /var/log/suricata/eve.json

Result: The alert was successfully generated, confirming that the HTTP-aware rule correctly identified the suspicious User-Agent string in the beacon traffic.

3.0 Week 4 Conclusion
The objectives for Week 4 were successfully met. A rule was developed that demonstrated the ability to detect a simulated malware C2 beacon by inspecting application-layer protocol data (HTTP). This completes the final phase of rule development for this project, covering network reconnaissance, application-level brute-force attacks, and malware traffic signatures.
