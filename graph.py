from scapy.all import rdpcap
import matplotlib.pyplot as plt

def plot_packet_count_over_time(pcap_file):
    packets = rdpcap(pcap_file)

    # Extract timestamps
    timestamps = [packet.sniff_timestamp for packet in packets]

    # Count the number of packets for each unique timestamp
    packet_counts = {}
    for timestamp in timestamps:
        packet_counts[timestamp] = packet_counts.get(timestamp, 0) + 1

    # Plot the data
    plt.plot(packet_counts.keys(), packet_counts.values(), marker='o')
    plt.xlabel('Time')
    plt.ylabel('Number of Packets')
    plt.title('Packet Count Over Time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    input_capture_file = 'your_file.pcapng'
    plot_packet_count_over_time(input_capture_file)
