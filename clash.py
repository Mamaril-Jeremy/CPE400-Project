#Jeremy Mamaril and Brandon Yu

import pyshark

def analyze_packet(packet):
    # Add your analysis logic here
    print(packet)

def main():
    # Replace 'your_capture_file.pcap' with the path to your Wireshark capture file
    capture_file = 'your_capture_file.pcap'
    
    try:
        # Read packets from the capture file
        packets = pyshark.FileCapture(capture_file, display_filter='your_display_filter')
        
        # Analyze each packet in the capture file
        for packet in packets:
            analyze_packet(packet)
    
    except FileNotFoundError:
        print(f"Error: File '{capture_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
