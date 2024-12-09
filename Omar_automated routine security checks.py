import subprocess
import logging
from scapy.all import sniff, IP, TCP

# Setup logging
logging.basicConfig(filename='security_check_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to run vulnerability scan using nmap
def run_vulnerability_scan(target_ip='127.0.0.1'):
    try:
        logging.info("Starting vulnerability scan on IP: %s", target_ip)
        # Run nmap as a subprocess and capture the output
        result = subprocess.run(['nmap', '-sV', target_ip], capture_output=True, text=True)
        logging.info("Vulnerability scan results:\n%s", result.stdout)
        print("Vulnerability scan completed. Results logged.")
    except Exception as e:
        logging.error("Error running vulnerability scan: %s", e)
        print("Error in running vulnerability scan. Check logs for details.")

# Function to monitor network traffic and detect anomalies
def monitor_network_traffic():
    logging.info("Starting network traffic monitoring...")

    # Defines a callback function for packet sniffing
    def packet_callback(packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flags = packet[TCP].flags
            # Detects SYN packets to log connection attempts
            if flags == "S":
                logging.info("Detected connection attempt from %s to %s", src_ip, dst_ip)
                print(f"Connection attempt from {src_ip} to {dst_ip}")

    # Starts sniffing packets
    try:
        print("Monitoring network traffic. Press Ctrl+C to stop.")
        sniff(filter="ip", prn=packet_callback, store=0)
    except Exception as e:
        logging.error("Error during network traffic monitoring: %s", e)
        print("Error in monitoring network traffic. Check logs for details.")

# Schedule the scans and monitoring tasks
def main():
    target_ip = input("Enter the IP address for vulnerability scan: ")
    run_vulnerability_scan(target_ip)
    monitor_network_traffic()

if __name__ == "__main__":
    main()
