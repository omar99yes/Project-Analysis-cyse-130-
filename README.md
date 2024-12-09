# Project-Analysis-cyse-130-
Project overview: The CyberSecuritySystem is a comprehensive variety of scripts designed for monitoring network traffic, running vulnerability scans and analyzing security data. It uses tools like Scapy for network monitoring and Nmap with OpenVAS for vulnerability scanning aswell as it integrates various checks to ensure system security. The goal of this system is to automate routine security checks, monitor network traffic for anomalies and detect potential vulnerabilities in the system, that way it saves alot of time for the user.

Installation:


Instructions for running the code
1) clone the repository: git clone (https://github.com/omar99yes/Project-Analysis-cyse-130-) cd ProjectAnalysiscyse130
2) This project requires Python and several libraries. Install the required dependencies: pip install -r scripts/requirements.txt.
3) Ensure Nmap and OpenVAS are installed: sudo apt install nmap, and sudo apt install openvas
TO RUN THE SCRIPT IN THE REPOSITORY:
1) To start monitoring the network traffic, run the following script: python scripts/network_monitoring.py
2) To perform a scan with Nmap, use the following script: Run a Vulnerability Scan: python scripts/nmap_scan.py
3) For a script that runs both monitoring and vulnerability scanning, use: python scripts/combined_scan_monitor.py
4) To view results, Logs and scan results are saved under the /results/logs and /results/scan_results directories.

