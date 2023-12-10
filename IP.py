import pyshark
from collections import Counter

def analyze_ip_addresses(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    source_ip_counter = Counter()
    destination_ip_counter = Counter()

    for packet in capture:
        # Check if the packet has an IP layer
        if 'IP' in packet:
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst

            source_ip_counter[source_ip] += 1
            destination_ip_counter[destination_ip] += 1

    # Print the summary of IP addresses
    print("Summary of Source IP Addresses:")
    print_ip_summary(source_ip_counter)

    print("\nSummary of Destination IP Addresses:")
    print_ip_summary(destination_ip_counter)

def print_ip_summary(ip_counter):
    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")

if __name__ == "__main__":
    pcap_file = "clash_data.pcapng"  # Replace with the path to your pcapng file
    analyze_ip_addresses(pcap_file)
