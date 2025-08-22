Attack Plan: Week 3 - Brute-Force Attacks
This document contains the official Hydra commands used to generate brute-force attack traffic for testing our NIDS rules.

Target IP: 192.168.70.20 (Windows 10 Victim)
Source IP: 192.168.70.10 (Kali Linux Attacker)

1. SSH Brute-Force Attack
Purpose: To simulate an attacker attempting to guess the password for the admin user on the SSH service running on port 22.

Command:

hydra -l admin -P passwords.txt ssh://192.168.70.20

Flag Explanation:

hydra: The command to run the tool.

-l admin: Specifies the login name (username) to target.

-P passwords.txt: Specifies the Password list file to use for the attack.

ssh://192.168.70.20: Defines the target service (ssh) and the IP address.

2. FTP Brute-Force Attack
Purpose: To simulate an attacker attempting to guess the password for the admin user on the FTP service running on port 21.

Command:

hydra -l admin -P badpasswords.txt ftp://192.168.70.20

Flag Explanation:

-l admin: Specifies the login name (username).

-P badpasswords.txt: Specifies the Password list file. For this test, a list of known incorrect passwords was used to guarantee that failed login attempts would be generated.

ftp://192.168.70.20: Defines the target service (ftp) and the IP address.
