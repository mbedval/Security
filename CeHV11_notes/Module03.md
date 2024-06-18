### 3.1 Scanning Concepts
#### What is SCANNING
- first step in active reconnaissance
- Search the network for potential targets

#### SCANNING OBJECTIVES
- Discover live hosts
- Discover services and listening ports
- Fingerprint OSes and services
- Identify targets for a vulnerability scan
> Fingerprinting : identifying an OS or service version through actively engaging the target. The goal of scanning is to ultimately find vulnerable target that you can explot

#### SCAN TYPE
- Can be Active or Passive
- Discovering Scan : Find potential targets
- PORT Scan : see what services hosts are running
- Vulnerability Scan: See if those services are vulnerable to hacking
- Other Scans: 
	- Map hostnames, IP Addresses - MAC addresses
	- Identify additional supported protocol
	- Stealthy alternatives to port scans.


#### COMMON SCANNING TASKS

| TASKS                    | DESCRIPTION                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| check for live syste     | Ping or ARP to discover live hosts                                                  |
| Check for open ports     | Scan live IPs for listening ports                                                   |
| Evade IDS and Firewalls  | If necessary, evade detection using proxies spooging fragmented packets, etc.       |
| Perform banner grabbing  | Grab from servers Perform OS and service fingerprinting                             |
| Scan for Vulnerabilities | Test services and OSes for vulnerabilities                                          |
| Draw network diagrams    | show logical and physcial pathways into networks                                    |
| Pentest Report           | Document everthing that you find Identify next steps for exploiting vulnerabilities |
|                          |                                                                                     |

#### PACKET CRAFTING
- Used in more advanced scanning
- Doesn't create packets from scratch
- You take a typical IP/ICMP/TCP/UDP packet and:
	- Specify what settings or values should be in the header fields or payload
	- Send the packet to the target
	- See how the target responds to illegal or unexpected packet settings
- Different OSes Respond in different ways.
	- You can often identify the OS based on the response:
		- IP - TTL, Don't Fragement (DF) flag / Don't Fragment ICMP (DFI)
		- TCP - Starting window size, Explicit congestion notification (ECN) Flag
		- Sequence number generation
		- ICMP - echo request / echo reply padding

##### Packet Crafting tools
#Nmap #hping3 #colasoft #netScanToolsPro #CatKarat #Ostinato #WANKiller #Packeth #LANforgeFire #BitTwist #WireEdit

#### SCANNING IN IPV6 NETWORKS
- IPv6 address are 128 bits
- Traditional scanning techniques are not feasible because of the larger search space (64 bits)
- Some scanning tools do not support scanning IPV6 networks
- Attackers may gather IPv6 address from
	- network traffic
	- recorded logs
	- header lines in archived emails
	- Usenet news messages
- IF an attacker does discover and compromise on host
	- They can probe the "all hosts" link local multicase address FF01::1
	- Discover additional targets on the link
- 

# =================================
### - 3.2 Discovery Scans

#### WHAT IS A DISCOVERY SCAN
- A type of scan that discovers live IP addresses on a network
- A Ping Sweep is the simplest network scanning method
	- It uses ICMP ECHO REQUEST packets to search for live hosts
- Many discovery scans uses some form of ARP instead of ICMP to bypass host-based firewalls
- Can also use specially crafted TCP or UDP packets

#### ICMP
- Internet Control Messaging Protocol
- Layer 3 protocl
- Direct payload of IP
- Protocol ID 1
- Has messages types
- Each message type in turn may have codes for further information

#### IMPORTANT ICMP TYPES

| ICMP Message Type          | DESCRIPTION and codes                                                                                                                                                                                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0: Echo Reply              | Answer to a Type 8 Echo Request                                                                                                                                                                                                                                                             |
| 3: Destination unreachable | Error Message followed by these codes:<br>0- Destination network unreachable<br>1- Destination host unreachable<br>6- Network unknown<br>7- Host unknown<br>9- Network administratively prohibited<br>10- Host administratively prohibited<br>13- Communication administratively prohibited |
| 4: Source Quench           | A congestion control message                                                                                                                                                                                                                                                                |
| 5: Redirect                | Sent when there are two or more gateways available for the sender to use. Followed by these codes<br>0 - Redirect datagram for the network<br>1 - Redirect datagram for the host                                                                                                            |
| 8: Echo (Request)          | A ping message, requesting an echo reply                                                                                                                                                                                                                                                    |
| 11: Time Exceeded          | Packet tool too long to be routed (code 0 is TTL expired)                                                                                                                                                                                                                                   |

#### ICMP SCANNING
- The easiest protocol to use to scan for live systems
	- Scanner sends ICMP ECHO request to one or more IP Addreses
	- IF live, hosts will return an ICMP ECHO REPLY
- Useful for locating local devices
- Often blocked by:
	- Software firewall on the host
	- Packet filtering router/firewall between the scanner and target network
- Useful for determining if a firewall is permitting ICMP
	- Example:
		- ICMP ECHO returns Type 3 code of 13 "Destination unreachable administratively prohibited"
		- This type of message is typically returned from a deviced blocking a port
		- Indicates a firewall that was poorly configured - the firewall should send no response at all

#### PING SWEEP
- Send ICMP ECHO requests to multiple hosts
	- Traditionally used ICMP ECHO
	- Now uses ARP, TCP or other protocols
	- Usually Swiftly in numerical order
- Only a live host will reply
- You can use the subnet mask to determine the range of addresses to scan
- You can record the live hosts in a list for further scanning

##### PING SWEEP TOOL EXAMPLES
	#nmap #hping3 #angryIPScanner #solarwindsEngineerToolkit #colasoftpingtool #superScan #VisualTester #pingScannerPro #OpUtils #pingInfoView #advancedIPScanner #PingSweep #NetworkPinger #pingmonitor #pinkie

#### ARP DISCOVERY
- Use ARP request/replies to discover live hosts
- Cannot be blocked by a personal firewall
	- ARP is required to discover MAC addresses and map them to IP Addresses 
	- Used on an Ethernet or wi-fi LAN
- Tools include
	- #nmap  #ettercap #metasploit #Cain_and_Abel

#### OTHER DISCOVERY TECHNIQUES
-  TCP SYN, ACK, FIN, etc. packets to common ports such as 80 or 443
- ICMP timestamp
	- Used by network routers to synchronize their system clocks for time and date
- SCTP Init
	- A newer layer 4 protocol that can manage sessions
	- Uses a heartbeat to immediately notify if a connection is down
	- Available in some versions of Linux and solaris
- You could also
	- Start port scanning a host without first checking if it is up or down
	- Perform an IP protocol scan to see if the host responds to other Layer 3/4 protocols


# =================================
### - 3.3 Port Scans
- A number (0 - 65535) that represents a process on a network
	- well-known services use specific port numbers by convention
	- There is no technical reason for a particular service to use a particular port number
- Both TCP and UDP use port numbers
	- Source and destination each have a port
	- Embedded in the header
	- Indicates the payload
- A Client and server will each have its own port in a conversation
	- Usually not the same port
- Some services are only "loosely bound" to a port
	- It is possible for another process to "get in front of" that services
	- Take over the port
	- This happens in hacking
	- Example : #netcat getting in front of IIS : intercepts and redirect web traffic

##### PORT Types
- Well-known
	- 9- 1023 
	- 0 is not used
	- Reserved by convention for well-known services
- Registered
	- 1024 - 49151
	- Services can additionally request the use of these ports from the operating system
- Dynamic 
	- 49152 - 65525
	- Operating system temporarily assigns a dynamic port to a client process
	- The Port is "returned" to the OS when the client process ends

#### COMMUNICATION USING PORTS
- Client and server ports are usually not the same
- Server Listens on well-known port for incoming connection attemps
- Client process, identified by its own port, attempts to make a connection
- The server can accept or reject the connection attempt
	- Usually based on if there is a listening service on that port
	- Can also have firewall filtering or other policies the block connection from specific clients


##### COMMON PORT NUMBERS AND SERVICES\

[[Popular Ports]]

##### SCANNING FOR OPEN PORTS
- Look for open TCP or UDP ports
- An Open port indicates a listening service
	- might have exploitable vulnerabilities
- TCP and UDP respond differently to scans
- Attacker sends TCP packets to the target 
	- Various TCP header flags are raised (bit set to 1)
- Response can indicate 
	- Listening service
	- OS Version
	- Firewall settings

##### TCP Header
![[Pasted image 20240618180348.png]]


##### TCP Flags

| FLAG | NAME            | Functions                                                                  |
| ---- | --------------- | -------------------------------------------------------------------------- |
| SYN  | Synchronize     | Set during initial communication Negotiate parameters and sequence numbers |
| ACK  | Acknowledgement | Set as an acknowledgement to the SYN flag. Always set after initial SYN    |
| RST  | Reset           | Forces the termination of a connection ( in both directions)               |
| FIN  | Finish          | Part of the close session handshake                                        |
| PSH  | Push            | Forces the delivery of data without concern for buffering                  |
| URG  | Urgent          | Data inside is being sent out of band. Example is cancelling message       |

##### TCP FLAGS EXAMPLE
![[Pasted image 20240618180826.png]]

##### TCP 3-way handshake
- SYN - SYN-ACK - ACK
- Establish session
- Set starting sequence numbers

##### TCP 4-way GOODBYE handshake
- FIN-ACK - FIN-ACK
- Properly end a session
- Both sides FIN and ACK the other


##### TCP SYN SCAN
- MOST common type of port scan
- A.K.A stealth scan or half-open scan
	- Client sends SYN packet to server
	- Server responds with SYN/ACK packet
	- Server responds with RST packet and remote port is closed
	- Client sends RST packet to close the initiation before connection is established
- Resets TCP connection between client and server in midstream

##### TCP CONNECT SCAN
- A.K.A. TCP full scan or TCP open scan, because it complete 3-way handshake and establish a full connection and then close connection by sending RST packet
- It Does not require super use privilege's on Linux
- Appears normal to intrusion detection and is less probable to rouse suspicion

##### TCP ACK SCAN
- Used to determine if the host is protected by filtering/ firewall
- Since (nearly) every TCP segment contains a raised ACK flag, an ACK scan appears normal 
	- Can evade IDS in most cases
	- Can be used against packet filtering routers to see what's behind it
- Attacker sends ACK probe packet with a random sequence number to target
	- No response = protected (filtered ) by firewall
	- RST = port is closed
- TTL-based
	- Send 1000s of ACKs to different TCP ports
	- Analyze TTL fields in RST packets received
	- If Less than the boundary value of 64, then port is open
	- If greater than 64, then port is closed
- Window-based
	- Send 1000s of ACKS to different TCP ports
	- If Window value of RST received has non-zero value, then port is open

##### INVERSE TCP FLAG SCANNING
- Stealthier than a SYN scan
- Does not attempt to start a TCP connection-
- Used to discover firewall rules / evade detection by IDS
- TCP Flags are raised in an unusual / illegal pattern
- Types Include:
	- XMAS Scan (PSH,URG, FIN)
	- Null Scan
	- FIN Scan
- 


UDP PORT SCAN
- No handshake involved
	- UDP is a stateless protocol
- You can send a UDP datagram
	- You often won't get a response
	- UDP itself cannot determine if host is alive, dead or filtered
- Sometimes a UDP closed port will return an ICMP port unreachable message
- 




# =================================
### - 3.4 Other Scan Types

- Headers
- Banner grabbing
- List Scan
- Zombie Scan
- FTP Bounce
- SSDP Scan

#### FingerPrinting Via Header Information
- TCP: 
	- "Window Size"  is constant for linux (0x7D78 (32120)) While Cisco & Microsoft Constantly changes
- IP:
	- TTL: 64 represents it linux or FreeBSD
	- Don't Fragment (DF) bit , SCO & OpenBSD donot use the DF flag
	- Type of Service (ToS): indicates the protocol priority more than the OS

#### What is BANNER GRABBING
- AKA OS fingerprinting
- A way to determine the operating system running on the remote target system
- Some Services identify themselves when queried
- Error messages can reveal information about the services or OS
	- you can use banner grabbing to identify the service and/or OS version
- Can also examine TCP and ICMP messages to identify OS

#### BANNER GRABBING TYPES

| **Active Banner Grabbing**                                                         | **Passive Banner Grabbing**                                                                         |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Specially Constructed packets are sent to the remote OS and responses are captured | Error message provide information including type of server, type of OS and SSL tools used by target |
| Responses are compared with a database to determine the OS                         | Sniffing network traffic on the target allows attacker to determine OS                              |
| Response from different OSes vary because of difference in the TCP/IP stack        | Page extension in a URL may assist the attacker in determining versions                             |

##### BANNER GRABBING TOOLS
There are many tools, which can be used to grab banners from various services. Services like FTP, SSH, HTTP, SMTP POP3, IMAP4, DNS, Telnet, Microsoft-DS, Microsoft netbios-ssn, etc

- IDServe #IDServe #windows
	- identifies the make model and version of any web site's server software
	- Can also used to identify non-http (non-web) Internet Servers : FTP. SMTP, POP, NEWS, etc.
- Netcraft #netcraft
	- Reports a site's operating system, web server, and netblocker owner together with a graphical view at the time of the last reboot for each computer in the site.
- Netcat #netcat
	- A Command-line utility
```
	nc --vv "TargeIPAddress" "PortNumer"
```
- Telnet
	- A Command-line utility
	- Will attempt to open a session to whatever port you specify
	- Will display any response received from the server
```
	telnet "TargetIpAddress" "PortNumber"
```
 - NMAP #nmap
``` 
	nmap -sV "TargetIpAddress" "PortNumer"
	nmap -sV --script=banner "TargetIpAddress"

```

#### ZOMBIE SCAN
-  AKA "BLIND" scan or 'IDLE' scan
-  Map open ports on a remote system without producing any evidence that you have interacted with that system
- Force target to interact with a third machine (zombie)
- Check Zombie's IPID to see if it incremented
	- IP identification (IPID) identifies a packet in a communication session
	- Its primary purpose is to recover from IP fragementation

#### FTP BOUNCE SCAN
- Abuses the FTP PORT command and File Exchange Protocol (FXP)
	- An Attacker sends the PORT command to an FTP server to redirect the data connection to a third (target) device
	- Target device can be anything the FTP server is capable of reaching
- Used to anonymously scan ports of a target system
- The Returned error message indicates whether the target port is open or not 
- Used to bypass firewalls
	- Organizational FTP Servers are often
		- Accessible to the Internet
		- Able to access otherwise protected internal hosts
- Most modern FTP servers now have the PORT Command Disabled

#### Universal Plug and Play (UPNP)
- TCP 1900
- Enables devices like personal computers, wi-fi, mobile devices, printers etc. to discover each other
	- Establish connections for sharing services and data
	- Also for entertainment purposes 
	- Intended to be used on residential networks
- Enabled by default on millions of systems
- UPnP-exposed systems connected to the Internet with exploitable vulnerabilities result in a severe security impact
	- These issues potentially expose millions of users to remote attacks
	- Could result in theft of sensitive information or further assaults on connected machines

#### SSDP (Simple Service Discovery Protocol)
- Used to advertise and discover network services and presence information
- The basis for UPnP device discovery
- Accomplishes this without assistance of server-based configuration mechanisms 
	- Such as DHCP or DNS
	- Without special static configuration of a network host
- Intended for use in use in residential or small office evironments

##### Tool #evilSSDP 
- from #github can be used to discover plug and play devices on the network.
- Can discover vulnerabilities you can use to launch Buffer overflow or DoS attacks
- Check if a machine can be exploited
- Usually works when machine is not firewalled
- Can be sent over IPv4 or IPv6



# =================================
### - 3.5 Scanning Tools

[[Nmap]]

HPING2 / [[Hping3]]
#### OTHER SCANNING TOOLS
#AngryIPScanner #SuperScan #PRTG #OmniPeek #MiTeCNetworkScanner #NEWTProfessional #MegaPing #SlitherisNetworkDiscovery #TamoSoftCommView #IPTools #NetworkScanner #GlobalNetworkInvestory #AdvancedPortScanner #CurrPorts #Masscan #DRACENMAP #NEET

#### SCANNING TOOLS for Mobile
#IPScanner #Fing #Hackode #zANTI #cSplit #faceNiff #PortDroidNetworkAnalysis #PamnIPScanner


# =================================
### - 3.6 NMAP
- A highly flexible open source tool for scanning networks
- Command-line based for Linux and Windows
- Also a GUI version (Zenmap) for Windows

[[Nmap]]
- 3.6.1 Activity - Nmap Basic Scans
- 3.6.2 Activity - Host Discovery with Nmap
- 3.6.3 - Activity - Nmap Version Detection
- 3.6.4 Activity - Nmap Idle (Zombie) Scan
- 3.6.5 Activity - Nmap FTP Bounce Scan
- 3.6.6 - Activity - NMAP Scripts
### - 3.7 Firewall and IDS Evasion
- 3.7.1 Activity - Nmap Advanced Scans
### - 3.8 Proxies
### - 3.9 Scanning Countermeasures
### - 3.10 Scanning Networks Review