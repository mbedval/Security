Network Administrators can use NMAP for inventory a network managing services upgrade schedules, and monitoring host or service uptime.
It is used to extract information such as live hosts on the network, open ports, services (Application name and version), types of packet filters/firewalls, as well as operating systems and versions used.
By Creating map of network, It sends specially crafted packets to the target host and then analyzes the responses to accomplish its goal.
Nmap includes many mechanisms for port scanning TCP and UDP, OS detection, version detection, ping sweeps and so on.

installation on UBUNTU
```
sudo apt install ettercap-graphical nmap -y
```

NMAP Allows
1. Host Discovery
2. Port and Service Discovery
3. 

#### Hosts Discover (with NMAP)
It is primary task in the network scanner process. Host discovery provides an accurate status of the systems in the network to avoid scanning every port on every system.

This Section highlight how to check for live system in network using various ping scan techniques with various ping sweep tools.

##### TCP Ping Scan
- Used to determine if the host is active without creating any connection
- Logs are not recorded at the system or network level, enabling the attacker to leave no traces for detection.

###### ICMP Ping Scan
- Usefull for locating active devices or determining if the ICMP message passes through a firewall

###### IP Protocol Ping Scan

#### ARP Ping Scan:
```
nmap -sn -PR <Target-IP-ADDRESS> 
```
Request: ARP request probe
Response: if host is active than ARP response else no response
Advantages
- ARP packets are sent for discovering all active devices in the IPv4 range even though the presence of such devices is hidden by restrictive firewalls. 
- When ARP request is send, OS determine the hardware destination address corresponding to the target IP. 
- \More efficient and accurate than other host discovery techniques
- Useful for systems discovery where only may need to scan large address spaces
- to disable ARP Ping in NMAP which is default, use option --disable-arp-ping

#### UDP Ping Scan
```
nmap -sn -PU <Target-IP-ADDRESS> 
```
Request: ARP request probe
Response: if host is active than UDP response else error message in {host/network unreachable , TTL exceeded}
Advantages
-  The default port number used by NMAP for UDP ping scan is '40125'/
- DEFAULT_UDP_PROBE_PORT_SPEC can be configured to change the default port
- Detects systems behind firewalls with strict TCP filtering, leaving the UDP traffic forgotten


#### ICMP ECHO Ping Scan
```
nmap -sn -PE <Target-IP-ADDRESS> 
```
Request: ICMP ECHO request
Response: If host is active ICMP ECHO reply else no response
Advantages
- This method help to gather all necessary information about destination host. because ICMP does not include port abstraction.
- This scan is useful for locating active devices or determining if ICMP is passing through a firewall.

Disadvantage:
- Does not work on Windows-based networks


### Host Scanning
#### ICMP ECHO Ping Sweep
```
nmap -sn -PE <Target-IP-RANGE> 
```
Request: ICMP ECHO request to multiple hosts
Response: if host is active ICMP ECHO reply else no response
Advantages
- Determines the lives hosts from a range of IP addresses
- Useful for creating an inventory of live system in the subnet

Disadvantage:
- Oldest and slowest method used to scan a network. and its acts as roll call for systems.

#### ICMP Timestamp Ping Scan
```
nmap -sn -PP <Target-IP-ADDRESS> 
```
Request: ICMP timestamp request
Response: ==Conditional depending on configuration==***  may give response with Timestamp reply to each timestamp request
Advantages
- Alternative for the conventional ICMP ECHO ping scan
- Determines whether the target host is live, specifically when the administrators block ICMP ECHO pings
- This method is used to acquire information related to the current time from the target, and inf


#### ICMP Address Mask Ping Scan
```
nmap -sn -PM <Target-IP-ADDRESS> 
```
Request: ICMP address mask request
Response: ==Conditional depending on configuration==*** may give response with appropriate subnet value.
Advantages
- Alternative for the conventional ICMP ECHO ping scan
- Determines whether the target host is live, specifically when the administrators block ICMP ECHO pings

#### TCP SYN Ping Scan
```
nmap -sn -PS <Target-IP-ADDRESS>
``` 
Request: Empty TCP SYN request
Response: If host is active than ACK response else no response
Advantages
- Used to determine if the host is active without creating any connection
- Logs are not recorded at the system or network level, enabling the attacker to leave no trace for detection.
- It help to determine if the port is online and to check if it encounters any firewall rules sets.
- This is three-way handshake method by SYN-ACK-RST 

#### TCP ACK Ping Scan
```
nmap -sn -PA <Target-IP-ADDRESS> 
```
Request: Empty TCP ACK request
Response: If host is active Than RST Response else No response
Advantages
- Maximizes the chances of bypassing the firewall
- This is 2-way method, when probing machine send ACK to Target, Live target machine will send RST flag as there is no existing connection.

#### IP Protocol Ping Scan
```
nmap -sn -PO <Target-IP-ADDRESS> 
```
Request: IP Ping request using different IP Protocols (ICMP, IGMP, TCP and UDP)
Response: If host is active than any response else no response
Advantages
- Sends different packets using different IP protocols in the hope of receiving a response indicating that a host is online.
- Probe machines sent multiple IP packets like {1 ICMP, 2 IGMP and 4 IP-IN-IP } when no protocol is specified.
- 'DEFAULT_PROTO_PROBE_PORT_SEC' is to be specified in 'nmap.h' during compile time.







### Port Scanning

#### TCP Connect/Full Open Scan: 
**Syntax**:
```
nmap -sT -v Target-IP
```
**Request**: SYN Packets
**Response**: If SYN+ACK packet responded than port is Open, else RST package is responded by target
**Advantage**:
- Does not require Super-user privileges
**Dis-Advantage**:
- Easily detectable and filterable
- The Logs in the target system disclose the connection

	
#### Stealth Scan (Half-Open Scan):
**Syntax**: 
```
nmap -sS -v Target-IP
```
**Request**: Single SYN Packet
**Response**: If SYN+ACK packet responded than port is Open, else RST package is responded by target for closed port
**Advantage**:
- By-passes firewall rules and logging mechanism
-
**Dis-Advantage**:
- N/A
#### Inverse TCP Flag Scan
**Syntax**: 
	command : nmap -(sF, -sN, -sX) -v Target-IP
**Request**: Probe Packet with (FIN/URG/PSH/NULL) flag
**Response**: If no response than Port is Open, else RST package is responded by target  for closed port	
**Advantage**:
- Avoids many IDS and logging systems, Highly stealthy
**Dis-Advantage**:
	- Requires raw access to network sockets and super-user privileges'
	- Not Effective against Microsoft windows hosts, in particular.

#### XMAS Scan
**Syntax**
```
nmap -sX -v Target-IP
```
**Request**: Probe Packet with (FIN + URG + PSH)
**Response**: If no response than Port is Open, Else RST package is responded by target for closed port
**Advantage**:
- Avoids many IDS and the TCP Three-way handshakes
**Dis-Advantage**:
	- Works only when systems are compliant with the RFC 793-based TCP/IP Implementation 
	- Works on the Unix platform only
	- Does not work against any current version of Microsoft windows

#### FIN Scan
**Syntax**:
```
nmap -sF -v Target-IP
```
**Request**: Probe Packet (FIN)
**Response**: If no Response than port is Open, else RST package is responded by target  for closed port

#### NULL Scan
**Syntax**:
```
nmap -sN -v Target-IP
```
**Request**: Probe Packet (NULL)
**Response**: If no Response than port is open, else RST flag is responded by target  for closed port

#### TCP Maimon Scan
**Syntax**:
```
nmap -sM -v Target-IP
```
**Request**: Probe Packet (FIN/ACK)
**Response**: If no Response than port is open, If response includes unreachable error than port is filtered, else RST flag is responded by target  for closed port


**Advantage**:  #FIN_NULL_TCPAdvantage
- Probe packets enabled with TCP Flags can pass through filters undetected, depending on the security mechanisms installed
- Works Only when systems are complaint with the RFC 793-based TCP/IP Implementation

**Dis-advantage**:
- Effective only when used with unix-based OSes
- Does not work against any current version of Microsoft windows.

#### Ack Flag Probe
**Syntax**
```
nmap -sA -v Target-IP
```
**Request**: Probe Packet with (ACK)
**Response**: If no response than Port is Open (Stateful firewall is present), Else RST package is responded by target for closed port  (Means no firewall is present)
**Advantage**:
- Can evade IDS in most cases
- Helps in checking the filtering systems of target networks
**Dis-Advantage**:
	Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks
#### TTL-Based ACK Flag Probe Scan
**Syntax**
```
nmap -sA --ttl 100 -v Target-IP
```
**Request**: Probe Packet with (FIN + URG + PSH)
**Response**: if Responded with RST packet port is open (TTL value on a port <64), Else RST package (TTL value on port > 64) is responded by target for closed port
**Advantage**:
- Can evade IDS in most cases
- Helps in checking the filtering systems of target networks
**Dis-Advantage**:
	Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks
#### Window-Based ACK Flag Probe Scan
**Syntax**
```
nmap -sA -sW -v Target-IP
```
**Request**: Probe several thousand Packet with (ACK) to different ports
**Response**: If responded with RST packet than port is open, Else if ICMP unreachable error response than port is filtered, Else RST package is responded by target for closed port
**Advantage**:
- Can evade IDS in most cases
- Helps in checking the filtering systems of target networks
**Dis-Advantage**:
	Extremely slow and can exploit only older OSes with vulnerable BSD-derived TCP/IP stacks


#### IDLE/IPID Header Scan
**Syntax**
```
nmap -Pn -p- -sl  Zombie-Host-IP  Target-IP
```
**Request**: Probe Packet with (SYN)
**Response**: If responded with SYN+ACK packet than Port is Open, Else RST package is responded by target for closed port
**Advantage**:
- Offers the complete blind scanning of a remote host
**Dis-Advantage**:
- Requires the identification of sequence numbers of the zombie host




#### UDP Scan
**Syntax**
```
nmap -sU-v Target-IP
```
**Request**: Probe Packet with (UDP)
**Response**: If no response than Port is Open, Else RST package is responded by target for closed port
**Advantage**:
- Less informal with regards to an open port because there is no overhead of a TCP handshake
- Microsoft-based OSes do not usually Implement any ICMP rate Limiting: hence, this scan operates very efficiently on windows-based devices.
**Dis-Advantage**:
- Slow because it limits the ICMP error message rates as a form of compensation to machines that apply RFC 1812 section 4.3.2.8
- A Remote host will require access to the raw ICMP socket to distinguish closed ports from unreachable ports
- Requires Priviledge access

#### SCTP INIT Scan
**Syntax**
```
nmap -sY -v Target-IP
```
**Request**: Probe Packet with (INIT ) chunk
**Response**: If response include (INIT +ACK) than Port is Open, Else if ICMP Unreachable error than port is filtered, Else ABORT package is responded by target for closed port
**Advantage**:
- An INIT Scan is performed quickly by scanning thousands of ports per seconds thousands of ports per second on fast network not obstructed by a firewall, offering as strong sense of security
- Can clearly differentiate between various ports such as open, closed and filtered states
**Dis-Advantage**:

#### SCTP Cookie
**Syntax**
```
nmap -sZ -v Target-IP
```
**Request**: Probe Packet with COOKIE ECHO chunk
**Response**: If no response than Port is Open, Else ABORT chunk is responded by target for closed port
**Advantage**:
- Avoids many IDS and the TCP Three-way handshakes
**Dis-Advantage**:
- Cannot Differentiate clearly between open and filtered ports, showing the output as open/filtered/ in both cases

#### SSDP and List Scan
Syntax
Advantage:
- A list scan can perform a good sanity check
- A list Scan detects incorrectly defined IP address in the command lineor in an option file. It primarily repairs the detected errors to run any 'active' scan.


#### IPV6Scan
Syntax
```
nmap -6 scanme.nmap.org
```
Dis-Advantage
- because IPv6 give more IP address space, computationally less feasible.( with one probe per second whole scan take 5 billion years to complete)
- Many Traditional scanning tool do not support sweeps on IPv6 networks.
- But if one host can be targeted and compromised, attacker can probe 'all hosts' in the subnet .



### Service Version Discovery
Syntax
```
nmap -sV 10.10.1.11
```
- Service version detection helps attackers to obtain information about running services and their versions on a target system.
- Obtaining an accurate service version number allows attackers to determine the vulnerability of target system to particular exploits


### NMAP Scanning Time Reduction Techniques

Performance and accuracy can be achieved by reducing the scan timing by techniques

1. Omit Non-Critical Tests
	- Avoid intense scan if only minimal amount of information is required
	- The number of ports scanned can be limited using specific commands
	- The port -sn can be skipped if and only if one has to check whether the hosts are online or not
	- Advanced scan types (-sC, -sV, -O, --traceroute, and -A) can be avoided)
	- The DNS resolution should be turned on only when it is necessary
2. Optimise Timing Parameter
	To Control the scan activity, NMAP provides -T option for scanning ranging from high-level to low-level timing aggressiveness. This can be extremely useful for scanning highly filtered network
3. Separate and Optimise UDP Scans
	Many vulnerable services uses the UDP protocol, scanning the UDP protocol is vital and it should be scanned separately, as TCP scans have different performance requirements and timing characteristics. Moreover, the UDP scan is more affected by the ICMP error rate-limiting compared to the TCP scan.
4. Upgrade NMap
	IT is always advisable to use the upgraded version as it contains many bug fixes important algorithmic enhacements, and high-performance features such as local network ARP scanning.
5. Execute Concurrent Nmap Instances
	Running Nmap against the whole network usually makes the system slower and less efficient. Nmap support parallelization and it can be customized according to specific needs. It becomes very efficient by getting an idea of the network reliability while scanning a larger group. The overall speed of the scan can be improved by dividing into many groupd and running them simultaneously.
6. Scan from a favorable Network Location:
	It is always advisable to run Nmap from the host's local network to the target within internal network, External Scanning is obligatory when performing firewall testing or when the network should be monitored from the external attacker's viewpoint.
7. Increase Available Bandwidth and CPU Time
	By Increasing the available bandwidth or CPU power, the NMap scan time can be reduced. This can be done by installing a new data line or stopping any running applications. Nmap is controlled by its own congestion control algorithms, so that network flooding can be prevented. This improves its accuracy. The Nmap bandwidth usage can be tested by running it in the verbose mode -v.
8. 