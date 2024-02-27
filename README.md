Description:
This project demonstrates how to capture, analyze, and manipulate TCP packets in a controlled environment using Scapy, a powerful Python library for network packet manipulation and sniffing. The setup involves two Docker containers acting as a client and server, specifically configured for telnet communication. The Python script included in this repository captures TCP packets transmitted between these containers, identifies the packet with the highest sequence number (considered the "last" packet in a transmission sequence for this demonstration), and then creates and sends a spoofed packet based on the captured packet's details and attempts to execute a reverse shell on the telnet server and hence hijacking Telnet connection to the attacker's machine.
