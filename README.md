This project showcases the capabilities of capturing, analyzing, and manipulating TCP packets in a controlled Docker-based environment, utilizing the Scapy library for network interaction. With two Docker containers set up to represent a client-server model using telnet, this script focuses on intercepting TCP packets to understand and manipulate TCP communication dynamics, especially focusing on the manipulation based on sequence and acknowledgment numbers.

The core of this demonstration revolves around the TCP protocol's sequence and acknowledgment numbers, crucial for maintaining the order and integrity of data transmission. Here's a brief overview of these concepts:

Sequence Number (32 bits): This number specifies the sequence of the first byte in the TCP segment. If the SYN flag is set, this represents the initial sequence number, playing a pivotal role in establishing a new connection and ensuring that data is delivered in order and without duplication.

Acknowledgment Number (32 bits): Valid only when the ACK flag is set, this number indicates the next sequence number that the sender of the segment is expecting. This mechanism is essential for the reliability of the TCP protocol, allowing the receiver to inform the sender about the successful receipt of bytes and what it expects next.

This Python script leverages Scapy to sniff ongoing TCP packets between these containers, identifies the packet with the highest sequence number as the "last" packet, and crafts and sends a spoofed packet based on the captured packet's details, including its sequence and acknowledgment numbers and attempts to execute a reverse shell on the telnet server which should give remote shell to the threat actor.
