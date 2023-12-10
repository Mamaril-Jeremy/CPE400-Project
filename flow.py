import pyshark
import matplotlib.pyplot as plt
from collections import defaultdict

def analyze_flow(pcap_file):
    capture = pyshark.FileCapture(pcap_file)

    connections = defaultdict(int)

    for packet in capture:
        if 'IP' in packet and 'TCP' in packet:
            if 'TCP' in packet and ('RST' in packet['TCP'].flags or 'DUP ACK' in packet['TCP'].flags):
                continue
            
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

            connection = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            connections[connection] += 1

    # Extract data for plotting
    labels = list(connections.keys())
    values = list(connections.values())

    # Plot the flow diagram
    plt.figure(figsize=(10, 6))
    plt.barh(labels, values, color='skyblue')
    plt.xlabel('Packet Count')
    plt.title('Flow Analysis')
    plt.tight_layout()

    # Show the plot
    plt.show()

if __name__ == "__main__":
    pcap_file = "clash_data.pcapng" 
    analyze_flow(pcap_file)
