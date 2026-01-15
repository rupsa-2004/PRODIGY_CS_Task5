from scapy.all import sniff, IP, TCP, UDP
import logging

# Define log file for captured data
logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format='%(message)s')

def packet_handler(packet):
    """
    Function to analyze and log relevant information from each packet.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        payload = bytes(packet[IP].payload) # Extract the payload data

        # Map protocol number to name
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        else:
            protocol_name = f"Other ({protocol})"

        log_message = f"Protocol: {protocol_name} | Source IP: {src_ip} -> Destination IP: {dst_ip} | Payload length: {len(payload)} bytes"
        print(log_message)
        logging.info(log_message)

    # Return True to continue sniffing
    return True

# Start packet sniffing
print("[*] Starting packet capture. Press Ctrl+C to stop.")
# You may need to run this with administrative privileges (sudo on Linux)
sniff(prn=packet_handler, store=0, count=0) # Sniff indefinitely until manually stopped