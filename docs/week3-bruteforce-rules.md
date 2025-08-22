NIDS Project - Week 3 Report: Detecting Application-Level Attacks
Author: Deep Patel

1.0 Introduction
1.1 Objective
The objective for Week 3 was to develop and test custom Suricata rules to identify active brute-force attacks against two common network services: SSH (Secure Shell) and FTP (File Transfer Protocol). This phase focused on implementing two key detection methodologies: rate-based analysis for encrypted traffic and content-based inspection for unencrypted traffic.

1.2 Tools Used
NIDS Engine: Suricata

Attack Tool: Hydra

Analysis Tool: tcpdump

2.0 SSH Brute-Force Attack Detection
2.1 Concept & Strategy
An SSH brute-force attack involves an automated tool attempting to log in repeatedly with a large list of passwords. As SSH traffic is encrypted, detection cannot rely on packet content. Instead, a rate-based rule was developed to detect the suspicious behavior of many rapid login attempts from a single source IP address.

2.2 Rule Development
The following rule was added to /etc/suricata/rules/week3.rules to trigger an alert after 5 connection attempts from the same source within 60 seconds.

Rule:

alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute-Force Attempt Detected"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; sid:1000006; rev:1;)

2.3 Testing & Verification
The attack was simulated using Hydra, and the log files were checked for the corresponding alert.

Attack Command:

hydra -l admin -P passwords.txt ssh://192.168.70.20

Verification Command:

grep "SSH Brute-Force" /var/log/suricata/eve.json

Result: The alert was successfully generated, confirming the rate-based rule was effective.

3.0 FTP Brute-Force Attack Detection
3.1 Concept & Strategy
An FTP brute-force attack follows the same principle as the SSH attack. However, because FTP is an unencrypted protocol, a more precise content-based detection rule can be used. The initial strategy was to look for the server's "login failed" message.

3.2 Rule Development & Refinement
Initial tests failed, requiring analysis with tcpdump. The packet capture revealed that a more reliable detection signature was the attacker's initial USER command rather than the server's variable response.

Final Rule: The following rule was added to /etc/suricata/rules/week3.rules to detect any FTP login attempt.

alert tcp any any -> $HOME_NET 21 (msg:"FTP Brute-Force Attempt (Login Failed)"; flow:to_server,established; content:"USER"; sid:1000008; rev:1;)

3.3 Testing & Verification
The attack was simulated using Hydra with a list of incorrect passwords to ensure failed login attempts were generated.

Attack Command:

hydra -l admin -P badpasswords.txt ftp://192.168.70.20

Verification Command:

grep "FTP Brute-Force" /var/log/suricata/eve.json

Result: The content-based rule successfully triggered an alert for each login attempt.

4.0 Week 3 Conclusion
The objectives for Week 3 were successfully met. The team demonstrated the ability to detect two distinct types of application-level brute-force attacks using both rate-based and content-based rule-writing techniques. The lab is prepared for the final phase of rule development.
