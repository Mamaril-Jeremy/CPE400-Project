import pyshark
from collections import Counter
import matplotlib.pyplot as plt

def analyze_ip_addresses(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    source_ip_counter = Counter()
    destination_ip_counter = Counter()

    for packet in capture:
        # Check if the packet has an IP layer
        if 'IP' in packet:
            # Exclude packets with duplicate acknowledgments (dup ACKs) and resets
            if 'TCP' in packet and ('RST' in packet['TCP'].flags or 'DUP ACK' in packet['TCP'].flags):
                print("ignored")
                continue

            source_ip = packet.ip.src
            destination_ip = packet.ip.dst

            source_ip_counter[source_ip] += 1
            destination_ip_counter[destination_ip] += 1

    # Visualize the summary of IP addresses
    visualize_ip_summary(source_ip_counter, "Source IP Addresses")
    visualize_ip_summary(destination_ip_counter, "Destination IP Addresses")

def visualize_ip_summary(ip_counter, title):
    ips, counts = zip(*ip_counter.items())

    plt.figure(figsize=(10, 6))
    plt.bar(ips, counts, color='skyblue')
    plt.xlabel('IP Addresses')
    plt.ylabel('Packet Count')
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Show the plot
    plt.show()

if __name__ == "__main__":
    pcap_file = "clash_data.pcapng"  # Replace with the path to your pcapng file
    analyze_ip_addresses(pcap_file)
