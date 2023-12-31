# Graph Script File

import scapy.all as scapy
import matplotlib.pyplot as plt
from datetime import datetime

def analyze_packets(file_path):
    packets = scapy.rdpcap(file_path)

    timestamps = [float(packet.time) for packet in packets]

    datetime_objects = [datetime.utcfromtimestamp(ts) for ts in timestamps]

    plt.figure(figsize=(10, 5))
    plt.plot(datetime_objects, range(len(packets)), marker='o', linestyle='-', color='b')
    plt.title('Packet Analysis Over Time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.show()

analyze_packets('clash_data.pcapng')
