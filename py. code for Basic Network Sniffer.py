"""
Basic Network Sniffer
Captures and analyzes network traffic packets
"""

from scapy.all import sniff, IP, ICMP, TCP, UDP, Raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
import sys
import textwrap


class NetworkSniffer:
    """Captures and analyzes network packets"""

    def __init__(self, packet_count=0, filter_protocol=None):
        """
        Initialize the network sniffer
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            filter_protocol: Filter by protocol ('TCP', 'UDP', 'ICMP', or None for all)
        """
        self.packet_count = packet_count
        self.filter_protocol = filter_protocol
        self.packet_num = 0

    def start_sniffing(self):
        """Start capturing packets"""
        print(f"\n{'='*60}")
        print("Starting Network Sniffer")
        print(f"{'='*60}\n")
        
        if self.filter_protocol:
            print(f"Filtering by protocol: {self.filter_protocol}")
        
        try:
            sniff(
                prn=self.packet_callback,
                count=self.packet_count if self.packet_count > 0 else 0,
                store=False
            )
        except PermissionError:
            print("Error: This program requires root/administrator privileges!")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nSniffer stopped by user")
            sys.exit(0)

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packet_num += 1
        
        # Check if packet matches filter
        if not self._should_process_packet(packet):
            return
        
        print(f"\n{'='*60}")
        print(f"Packet #{self.packet_num}")
        print(f"{'='*60}")
        
        # Display Ethernet layer info
        self._display_ethernet_info(packet)
        
        # Display IP layer info
        if IP in packet:
            self._display_ip_info(packet[IP])
        
        # Display protocol-specific info
        if TCP in packet:
            self._display_tcp_info(packet[TCP])
        elif UDP in packet:
            self._display_udp_info(packet[UDP])
        elif ICMP in packet:
            self._display_icmp_info(packet[ICMP])
        
        # Display payload
        if Raw in packet:
            self._display_payload(packet[Raw].load)

    def _should_process_packet(self, packet):
        """Check if packet matches filter criteria"""
        if self.filter_protocol is None:
            return True
        
        if self.filter_protocol == 'TCP' and TCP in packet:
            return True
        elif self.filter_protocol == 'UDP' and UDP in packet:
            return True
        elif self.filter_protocol == 'ICMP' and ICMP in packet:
            return True
        
        return False

    def _display_ethernet_info(self, packet):
        """Display Ethernet frame information"""
        if Ether in packet:
            ether = packet[Ether]
            print(f"\n📡 Ethernet Frame:")
            print(f"  └─ Source MAC: {ether.src}")
            print(f"  └─ Destination MAC: {ether.dst}")
            print(f"  └─ Protocol: {ether.type}")

    def _display_ip_info(self, ip_layer):
        """Display IP packet information"""
        print(f"\n🌐 IPv4 Packet:")
        print(f"  ├─ Source IP: {ip_layer.src}")
        print(f"  ├─ Destination IP: {ip_layer.dst}")
        print(f"  ├─ TTL: {ip_layer.ttl}")
        print(f"  ├─ Protocol: {ip_layer.proto}")
        print(f"  ├─ Header Length: {ip_layer.ihl * 4} bytes")
        print(f"  ├─ Total Length: {ip_layer.len} bytes")
        print(f"  └─ Flags: {ip_layer.flags}")

    def _display_tcp_info(self, tcp_layer):
        """Display TCP segment information"""
        print(f"\n🔌 TCP Segment:")
        print(f"  ├─ Source Port: {tcp_layer.sport}")
        print(f"  ├─ Destination Port: {tcp_layer.dport}")
        print(f"  ├─ Sequence Number: {tcp_layer.seq}")
        print(f"  ├─ Acknowledgment Number: {tcp_layer.ack}")
        print(f"  ├─ Flags: {tcp_layer.flags}")
        print(f"  ├─ Window Size: {tcp_layer.window}")
        print(f"  └─ Checksum: {tcp_layer.chksum}")

    def _display_udp_info(self, udp_layer):
        """Display UDP datagram information"""
        print(f"\n📦 UDP Datagram:")
        print(f"  ├─ Source Port: {udp_layer.sport}")
        print(f"  ├─ Destination Port: {udp_layer.dport}")
        print(f"  ├─ Length: {udp_layer.len} bytes")
        print(f"  └─ Checksum: {udp_layer.chksum}")

    def _display_icmp_info(self, icmp_layer):
        """Display ICMP packet information"""
        print(f"\n❄️  ICMP Packet:")
        print(f"  ├─ Type: {icmp_layer.type}")
        print(f"  ├─ Code: {icmp_layer.code}")
        print(f"  └─ Checksum: {icmp_layer.chksum}")

    def _display_payload(self, payload):
        """Display packet payload"""
        print(f"\n📄 Payload ({len(payload)} bytes):")
        print(f"  Hex Dump:")
        
        # Display hex dump in readable format
        hex_str = payload.hex() if isinstance(payload, bytes) else payload.encode().hex()
        for i in range(0, len(hex_str), 32):
            chunk = hex_str[i:i+32]
            # Format as: offset | hex bytes | ASCII
            formatted = ' '.join([chunk[j:j+2] for j in range(0, len(chunk), 2)])
            print(f"    {formatted}")
        
        # Try to display as ASCII if possible
        try:
            ascii_str = payload.decode('utf-8', errors='ignore').strip()
            if ascii_str:
                print(f"\n  ASCII:")
                for line in textwrap.wrap(ascii_str, width=50):
                    print(f"    {line}")
        except:
            pass


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Basic Network Sniffer - Capture and analyze network traffic'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (0 = infinite)'
    )
    parser.add_argument(
        '-p', '--protocol',
        choices=['TCP', 'UDP', 'ICMP'],
        default=None,
        help='Filter packets by protocol'
    )
    
    args = parser.parse_args()
    
    sniffer = NetworkSniffer(packet_count=args.count, filter_protocol=args.protocol)
    sniffer.start_sniffing()


if __name__ == '__main__':
    main()
