
 
After identifying the target and performing the initial reconnaissance. Scanning is the an extended form of reconnaissance in which attackers learns more about target {OS, Services, Configuration lapses}

This gleans (little information) helps attackers to select right strategies for attacking the target system or network.

In Scanning we use various tools to discover live system, ports and OS even if it is beyond Intrusion Detection System (IDS) and Firewalls 



Network Scanning refers to set of procedures used for identifying hosts, ports, and services in a network. It is the process of gathering additional detailed information about target using highly complex and aggressive reconnaissance techniques.. By collecting this information attacker creates a profile of the target organization. The purpose of the scanning is to discover exploitable communication channels, probe as many listeners as possible. Than Track the ones that are responsive or useful for attack.

Objectives of Network Scanning:

- To Discover live hosts, IP address, and open ports of live hosts
- To discover operating systems and system architecture
- To discover services running on hosts
- To discover vulnerabilities in live hosts

#### Type Of Scanning:
- Port Scanning: #portscanning Process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in. Process involves probing TCP/ UDP ports to check if services are running in listening state.  Sometime active services allow unauthorized users access due to misconfiguration or use of default credential shipped with product.
- Network Scanning: #networkScanning Process to identify active hosts on the network with objective to attack it or to assess the security of the network it is in.
- Vulnerability Scanning: #vulnerabilityScanning Process to check whether system is exploitable by identifying its vulnerability. Tools used for vulnerability scanning common scanning engine and catalog. 
	- The catalogs includes a list of common files with known vulnerabilities and common exploits for range of servers. 
	- The Scanning engine maintain logic for reading the exploit list, transferring the request to the web server, and analyzing the request to ensure the safety of the server.
	- 

TCP Communication Flags: TCP header contains various flags that control the transmission of data across a TCP connection. TCP Header is of 32 Bit.
Header Includes :  {*Source Port, Destination Port, Sequence No, Acknowledgement No, Offset, Res, TCP Flags, Window, TCP Checksum, Urgent Pointer, Options*}

6 flags manage the connection between hosts and give instruction to the system. The Size of each six flags is 1 bit. So Flag is set to '1' that flag is considered turned ON.

1. SYN: It notifies the transmission of a new sequence number. This flag generally represents the establishment of a connectio (three-way handshake) between two hosts.
2. ACK: It confirms the receipt of the transmission and identifies the next expected sequence number. When System successfully receives a packet, it sets the value of its flag to '1' and thus imply that the receivers should pay attention to it.
3. PSH: Indicates that the sender has raised the push operation to the receiver and implies that the remote system should inform the receiving application about the buffered data coming from sender. The Systems raises PSH flag at the start and end of data transfer and sets its on the last segment of a file to prevent buffer deadlocks.
4. URG: It instructs the system to process the data contained in packets as soon as possible. When the system sets the flag to '1', Priority is given to processing the urgent data first and all the other data processing is stopped.
5. FIN: It is set to '1' to announce that no more transmissions will be sent to the remote system and the connection established by the SYN flag is terminated.
6. RST: Value is set to '1' when their is an error in the current connection to abort. 

- SYN, ACK, FIN, RST : Governs the establishment, maintenance and termination of a connection.
- PSH and URG: provide instructions to the system

SYN, ACK, RST are mainly 3 flags used while SYN scanning

A TCP session initiates using a three-way handshake mechanism
- Source Send SYNC to destination
- Destination responds to source with SYN/ACK Packet
- Source sends ACK packet for ACK/SYN packet transmitted by destination
- This will trigger a "Open" Connection between until FIN or RST packet closes the connection/

#### Scanning Tools #tool 

##### Host Discovery
- 

- SX: #github 
- UnicornScan #sourceforge 
- 
- PRTG Network Monitor #website https://www.paessler.com/network_traffic_analyzer 
- OmniPeek Network Protocol Analyzer https://www.liveaction.com
- [[NMAP]]: 
- [[Hping3]] 
- [[Metasploit]] 
- **Ping Sweep Tools** : are tools to ping an entire range of network IP Addresses to identify the live systems. It Enables us to determine live hosts on the target network by sending multiple ICMP ECHO requests to various hosts on the network at a time
	- **Angry IP Scanne**r: with this tool, we can ping each IP address to check if any of these addresses are live. Then it optionally resolves hostname, determines the MAC address, scans ports, etc. The amount of data gathered about target can increase by using plugins. Additional features includes NetBIOS info like {computer name, workgroup name, currently logged in windows users}, Favorite IP address ranges, web server detection, and customizable openers. IT allow users to save the scanning results to CSV, TXT, XML, or IP-Port list files. It uses multi-threaded for each scanned IP address. 
	- **NetScanTools** Pro:  https://www.netscantools.com : NetScanTools Pro assists attackers in automatically or manually listing IPV4/IPV6 addresses, hostnames, domain names, and URLs. It is collection of many network tools and utilities categorized by their functions, such as active, passive, DNS and local computer
	- SolarWinds.com #website https://www.solarwinds.com/ 
	- Calasoft Ping Tools Pro: https://www.colasoft.com
	- Visual Ping Tester: http://www.pingtester.net
	- OpUtils: https://www.manageengine.com
- 
###### Scanning Tools for Mobile

- IP Scanner: https://10base-t.com #iphone
- Fing : https://www.fing.io #freesubscription #android #iphone It allows attackers to discover all devices connected to wifi network along with their IP and MAc address as well as the name of the vendor/device manufacturer. It also allows attacker to perform network pinging and traceroutes activities through specific ports such as SSH FTP, NetBIOS, etc.
- Network Scanner: #Android Network scanner to identify the active hosts in the range of possible address in a network. It also displays IP addresses, MAC addresses, Host names , and vendor details of all the available devices in the network. It also allow Port Scan Targets with specific port numbers
- 





##### Port and Service Discovery
The Port scanning techniques are categorized according to the type of protocol used for communication.
- TCP Scanning
	- Open TCP Scanning : TCP Connect / Full Open Scan
	- Stealth TCP Scanning : 
		- Half-Open Scan
		- Inverse TCP Flag Scan
			- Xmas Scan
			- FIN Scan
			- NULL Scan
			- Maimon Scan
		- ACK Flag Probe Scan
			- TTL-based Scan
			- Window Scan
	- Third Party and spoofed TCP 
		- IDLE/ IPID Header Scan
- UDP Scanning
- SCTP Scanning
	- SCTP INIT Scanning
	- SCTP COOKIE ECHO Scanning
- SSDP Scanning :  msf6  > use auxiliary/scanner/upnp/ssdp_msearh	

	- The Simple Service Discovery Protocol is a network protocol that works in conjunction with the UPnP to detect plug and play devices
	- Vulnerabilities in UPnP may allow attackers to launch Buffer overflow or DoS attack
	- Attacker may use the UPnP SSDP M-Search information discovery tool to check if the machine is vulnerable to UPnP exploits or not.
	- SSDP Scanning is used to detect UPnP vulnerabilities that may allow him/her to launch buffer overflow or DoS attacks.
	- List Scan simply generates and prints a list of IPs/Name without actually pining them.
	- A reverse DNS resolution is performed to identify the host names.
- 
- IPV6 Scanning : IPv6 increase the IP address size from 32 bits to 128 bits to support more levels of address hierarchy. So Attackers need to harvest IPv6 address from network traffic, recorded logs, or received from : header lines in archived emails.
- 

List of Common Ports and Services 
[[Popular Ports]] to remember



##### OS Discovery (Banner Grabbing / OS Fingerprinting)
- Banner grabbing or OS Finger printing is the method used to determine the operating system running on a remote target system. There are two types of banner grabbing.
	- **Active Grabbing:** Specially crafted packets are sent to the remote OS and the responses are noted. The responses are then compared with a database to determine the OS. Responses from different OSes vary due to differences in the TCP/IP stack implementation.
	- **Passive Grabbing**: Banners grabbing from error messages. Sniffing the network traffic, extension in the URLs may assist in determining's application version.
- Identify the OS used on the target host allows and attacker to figure out the vulnerabilities possessed by the system and the exploits that might work on system to further carry out additional attacks.

**info**: Nmap uses a series of nine tests to determine an OS fingerprint or banner grabbing. 

There can be many Signatures of response, major 4 are as below

1. **TTL** (Time to Live) of the packets set on the outbound packet. for stealthily scan trace-route ttl can be set fewer than remote host with -m option.
2. **Window Size** : What is the window size set by OS: The  window size for Cisco routers and Microsoft windows NT constantly change. The Window size is more accurate when measured after the initial 3-way handshake. due to TCP slow start.
3. Whether **DF** (Don't Fragment) bit is set: Does the OS set the DF Bit?: This is of limited use, as some system don't use DF Flag , it can help in filtering out based on set bit value.
4. **TOS** (Type of Service) : Does the OS set the TOS, what setting is it. This is also of less value, because its more session based. 

*Attackers tools to Sniff/Capture the response generated from the target machine using packet-sniffing tools like Wireshark and observe the TTL and TCP window size fields.*

Attacker can use tools lie { Wireshark, NMap, Unicornscan, NMap Script Engine}

| Operating System | Time to Live | TCP Window Size |
| ---------------- | ------------ | --------------- |
| Linux            | 64           | 5840            |
| FreeBSD          | 64           | 65535           |
| OpenBSD          | 255          | 16384           |
| Windows          | 128          | 65535 to 1 GB   |
| Cisco Routers    | 255          | 4118            |
| Solaris          | 255          | 8760            |
| AIX              | 255          | 16384           |


##### Scanning Beyond  IDS and Firewall

##### Network Scanning Counter-measures


#### Module Summary:



links
[[00_toolsList]]