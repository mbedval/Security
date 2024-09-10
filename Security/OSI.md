#OSI Open system Interconnection

Open Systems Interconnection model defines seven layers that help in understanding how a network operates and how data is exchanged between systems. Each layer plays a specific role in the communication process and can be vulnerable to various security attacks. Here is breakdown of the different levels of security in the OSI model based on the provided sources:

![[OSI-model-layers-attacks-Stackscale.jpg.avif]]

#### Seven Layers

1. Physical Layer: This layers deals with the physcial components of the network like cables and routers. Security measures at this layers physical security such a biometrics access, camera surveillances, and keys cards to prevent physical breaches . Attacks at this layers can include Denial of Services (DoS) attacks aimed at disrupting network functions by cutting wires or interrupting wireless connections.
2. Data Link Layers: The Data link layer manages data packets and their transmission. Security mechanism at this layer include MAC address filtering, encryption standards, and wireless applications assessments to prevent attacks like MAC address spoofing. Attacks at this layers can include DoS attacks like ping floods or ICMP attacks
3. Network Layers: The network layers handles addressing and routing of packets. Security measures include anti-spoofing techniques, firewall implementations and secure routing protocols to prevent IP address spoofing attacks.
4. Transport Layers: The transport layer co-coordinates data transfer between systems. Security at this layer involves firewalls. strict transmission protocol controls, and port number management to prevent port scanning attacks.
5. Session Layers: The session layer manages communication sessions between devices. Security measures include encrypted key exchanges and session termination controls to prevent brute force attacks and unauthorised access.
6. Presentation Layer: The presentation layer standardizes data formats and handles encryption. Security practices involve input validation and sanitized input to prevent cybercriminals from exploiting systems or causing crashes
7. Application Layer: The application layer is where users interact directly with applications. Security breaches at this layer can lead to network shutdowns, data theft, and application crashes. Proper security measures are crucial at this layer to prevent a wide range of cyber attacks

  

#### Common vulnerabilities at the transport layer include:

1. Fingerprinting: This involves discovering open ports and services running on a target system. This technique is used by both hackers and network administrators to gather information about a system before attempting to exploit it
2. TCP Reassembly and Sequencing: An attacker can attempt to guess the sequencing numbers of packets and inject malicious packets into the network. When the target receives the packets, it assumes they came from the real sender, which can lead to unauthorized access
3. Insufficient Transport Layer Protection: This vulnerability exposes sensitive data and can lead to account theft. It occurs when applications do not properly encrypt network traffic, making it susceptible to interception by malicious actors
4. TLS Issues and Protocol: Although TLS provides enhanced security, it still has its share of attacks. These include man-in-the-middle (MITM) attacks, where an attacker intercepts communications between parties, and vulnerabilities like the Raccoon attack, which allows threat actors to decrypt server and client communications
5. BREACH: This vulnerability targets HTTP compression and can be exploited even if TLS compression is turned off. It involves forcing a victim's browser to connect to a TLS-enabled third-party website and monitoring the traffic between the victim and the server using a man-in-the-middle attack

#### TCP Reassembly and sequencing vulnerability
1. Initial Sequence Number (ISN): TCP uses a random 32-bit sequence number for each connection. The ISN is used to identify packets in a TCP stream and ensure that packets are reassembled correctly. However, if the ISN is not chosen randomly or if it is incremented in a non-random manner, an attacker can predict the sequence numbers and inject packets into the session
2. Sequence Number Prediction: An attacker can predict the sequence numbers by analyzing the pattern of sequence numbers used in previous connections. This can be done by exploiting vulnerabilities in the TCP implementation that allow an attacker to guess the sequence numbers
3. Sequence Number Guessing: If the attacker can guess the sequence number correctly, they can inject a packet into the session with a forged source IP address and TCP port. The receiving host will accept the packet as genuine if it falls within the acceptable window size

#### TCP Reassembly and Sequencing

1. Reassembly Window: The receiving host maintains a "window" of sequence numbers that it expects to receive. This window is used to prevent the receipt and reassembly of duplicate or late packets in a TCP stream
2. Sequence Number Acceptance: If a packet arrives with a sequence number within the acceptable window, the receiving host will accept it as genuine. If the sequence number is outside the window, the packet is dropped

#### Attack Scenario

1. Flood and Spoof: An attacker floods the target host with packets to prevent it from receiving legitimate packets. This can be done using various denial-of-service attacks
2. Sequence Number Guessing: The attacker then connects to the target host and obtains the sequence number data. If the sequence number is guessable, the attacker can extrapolate the next sequence number(s) that the host will use
3. Spoofed Packet: The attacker then sends a packet to the target host with a forged source IP address and TCP port, using the guessed sequence number. If the sequence number is correct, the host will accept the packet as genuine and reset the connection

#### Mitigation

1. Random ISN Generation: Implementing random ISN generation can significantly reduce the likelihood of sequence number prediction attacks
2. Secure TCP Implementations: Using secure TCP implementations that prevent sequence number prediction can also mitigate these attacks
3. Access Control Lists: Implementing access control lists to prevent the injection of packets with forged source or destination IP addresses can also help mitigate these attacks


## Conclusion

TCP reassembly and sequencing vulnerability is a critical security issue that can be exploited by attackers to inject packets into a TCP session and cause denial-of-service attacks. Implementing secure TCP implementations, random ISN generation, and access control lists can help mitigate these attacks.