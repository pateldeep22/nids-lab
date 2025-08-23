Attack Plan: Week 4 - Malware C2 Beacon Simulation
This document contains the official commands and procedures used to simulate malware Command and Control (C2) traffic for testing our NIDS rules.

C2 Server IP: 192.168.70.10 (Kali Linux)
Infected Host IP: 192.168.70.20 (Windows 10 Victim)

1. C2 Server Simulation
Purpose: To create a simple listener that acts as the C2 server, waiting for incoming HTTP beacons from the infected host.

Tool: Python's built-in HTTP server module.

Command (run on the Kali VM):

sudo python3 -m http.server 80

Explanation:

sudo: Executes the command with root privileges, which is necessary to bind to a privileged port like port 80.

python3 -m http.server: Runs the built-in HTTP server module.

80: Specifies that the server should listen on port 80, the standard port for HTTP traffic.

2. C2 Beacon Simulation
Purpose: To generate a single, crafted HTTP GET request from the victim machine to the C2 server. This request is disguised with a custom User-Agent string that acts as our malware signature.

Tool: Windows PowerShell.

Command (run on the Windows 10 VM):

Invoke-WebRequest -Uri http://192.168.70.10 -Headers @{ "User-Agent" = "C2-Beacon-Client" }

Explanation:

Invoke-WebRequest: The PowerShell cmdlet for sending web requests.

-Uri http://192.168.70.10: Specifies the destination URL of our C2 server.

-Headers @{ "User-Agent" = "C2-Beacon-Client" }: This is the crucial part of the simulation. It creates a custom HTTP header, specifically setting the User-Agent to our unique, suspicious string "C2-Beacon-Client", which our NIDS rule is designed to detect.
