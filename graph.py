import scapy.all as scapy
import matplotlib.pyplot as plt
from datetime import datetime

def analyze_packets(file_path):
    packets = scapy.rdpcap(file_path)

    # Extract timestamps from packets and convert to floating-point numbers
    timestamps = [float(packet.time) for packet in packets]

    # Convert timestamps to datetime objects for better visualization
    datetime_objects = [datetime.utcfromtimestamp(ts) for ts in timestamps]

    # Plot the graph
    plt.figure(figsize=(10, 5))
    plt.plot(datetime_objects, range(len(packets)), marker='o', linestyle='-', color='b')
    plt.title('Packet Analysis Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Show the plot
    plt.show()

# Replace 'your_file_path.pcapng' with the actual path to your pcapng file
analyze_packets('clash_data.pcapng')
