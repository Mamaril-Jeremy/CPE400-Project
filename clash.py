#Jeremy Mamaril and Brandon Yu

import pyshark

def analyze_packet(packet):
    # Add your analysis logic here
    print(packet)

def main():
    capture_file = 'your_capture_file.pcap'
    
    try:
        packets = pyshark.FileCapture(capture_file, display_filter='your_display_filter')
       
        for packet in packets:
            analyze_packet(packet)
    
    except FileNotFoundError:
        print(f"Error: File '{capture_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
