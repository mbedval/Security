Usage: #Enumeration

NMAP Features
- Host discovery
- Port and service discovery
- Operating system and service fingerprinting
- Enumeration
- MAC address detection
- Vulnerability and exploit detection

NAMP Hel


#### NMAPS Options

| Scan Option                                | Description                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -h                                         |                                                                                                                                                                                                                                                                                                                     |
| -V                                         |                                                                                                                                                                                                                                                                                                                     |
| -d                                         | Enable debugging to view all steps                                                                                                                                                                                                                                                                                  |
| -PR                                        | - Send an ARP (Address resolution protocol ) request to a target for a response<br>- ARPs are not usually blocked by firewalls<br>- Defaults discovery method for any nmap scan on an ethern                                                                                                                        |
| -PS\<portlist\>                            | - Disover hosts by sending a TCP SYNC to specified port/s <br>- Default is port 80<br>- Any response (SYN, ACK, RST ) demonstrates the target is up<br>- Syntax indicates no space between -PS and the port list<br>- Will be followed by port scan unless the '-sn' opti                                           |
| -sn                                        | - No Port Scan<br>- Discovery only <br>- Use combination of <br>-  -  - ICMP ECHO<br>-  -  - TCP SYN to port 443<br>-  -  - TCP ACK to port 80<br>-  -  -  ICMP timestamp reques                                                                                                                                    |
| -sS<br><br>\** Requires root privilege \** | - TCP SYN Scan<br>- Send TCP SYN to target for response to check<br>- Check for TCP 3-way handshake<br>- - - If port is open, will respond with SYN ACK<br>- - - RST if port                                                                                                                                        |
| -sT                                        | TCP connect scan<br>- Complete TCP 3-way handshake for non-                                                                                                                                                                                                                                                         |
| -sU                                        | UDP Scan<br>- Can be very slow<br>- Ports that respond are open<br>- Ports that donot respond are displayed as open \| filtered (unknown)<br>- A port might be open but not respond to an empty UDP probe packet<br>Port that send ICMP unreachable (type 3 code 3)                                                 |
| -sL                                        | List Scan<br>- List the target(s) that will be scanned<br>- Attempts to return IP addresses and names for targets<br>- Good for passive reco                                                                                                                                                                        |
| -sV                                        | Probe open ports for service version<br>- Can help disambiguate                                                                                                                                                                                                                                                     |
| -p \<portRange\>                           | Scan Only Specified p                                                                                                                                                                                                                                                                                               |
| -p U:PortRange T:PortRange                 | U Represents UDP Ports<br>T Represents                                                                                                                                                                                                                                                                              |
| -r                                         | Scan ports consecutively and no                                                                                                                                                                                                                                                                                     |
| --top-ports \<Num\>                        | where 'Num' how many ports to be scanned example top                                                                                                                                                                                                                                                                |
| -6                                         | Scan IPv6                                                                                                                                                                                                                                                                                                           |
| -iL \<inputFileName.txt\>                  | scan host list                                                                                                                                                                                                                                                                                                      |
| --exclude 192.168.1.100                    | Exclude certain hosts from provided ip range                                                                                                                                                                                                                                                                        |
| -n                                         | Do not resolve names (t                                                                                                                                                                                                                                                                                             |
| -R                                         | Try to resolve all name with re                                                                                                                                                                                                                                                                                     |
| -F  (Fast mode)                            | scan fewer ports th                                                                                                                                                                                                                                                                                                 |
| -O                                         | Enable OS detection, now alway                                                                                                                                                                                                                                                                                      |
| -A                                         | Enable OS detection, services version detection, script scanning, and                                                                                                                                                                                                                                               |
| --version-intensity                        | Use with -sV<br>--- Specified level of interrogation from 0 (light), to 9 (Attempt a                                                                                                                                                                                                                                |
| --script =\<scriptName\>                   | Use NSE script (ie. b                                                                                                                                                                                                                                                                                               |
| -sC                                        | Scan using all defau                                                                                                                                                                                                                                                                                                |
| -v                                         | Increase verbosity                                                                                                                                                                                                                                                                                                  |
| -vv                                        | Very verb                                                                                                                                                                                                                                                                                                           |
| -oN  / -oX / -oS / -oG / -oA               | Save output file into type N= normal, X=XML, S=Script Kiddie, G=Grepable                                                                                                                                                                                                                                            |
| -sA                                        | ACK Scan<br>Find out if a host/network is protected by a firewall<br>--- Filtered results indicate firewall is ON<br>--- Unfiltered results indicates port is accessible but might be open or closed<br>-- Run with -A option to determine if accessible ports are actually open or closed (name -sA -A scanme.org) |

```
nmap -p 80 192.168.1.50
nmap -p 1024-3000 192.168.1.0/24 
nmap -p U:53,111,137   T:21-25,80,443 192.168.1.0/24
```
#### NMAP STEALTH SCAN

| Stealth Options | Description                                                                                                                                                                                                    |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -sS             | The Original "Stealth" scan<br>Half-Open Scan<br>--- Do not Complete TCP handshake<br>--- if response is SYN_ACK send RST<br>--- This is less likely to be logged by the target<br>--- Might, however, be noti |
| -Pn             | Skip discovery<br>--- Assume all hosts are online for port scan<br>--- Useful if targets have their firewall up and only offer services on unu                                                                 |
|                 |                                                                                                                                                                                                                |
```
nmaps -sS 192.168.1.50
nmaps -Pn -p- 192.168.1.0/24
```


#### NMAP FIN, NULL and XMAS SCANS

|     |                                                                                                                                                                                     |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -sF | FIN scan<br>--- Raises only a FIN flag<br>--- Can be used to disambiguate results of other scans                                                                                    |
| -sN | Null Scan<br>--- No flags rasied<br>--- Can sometimes penetrate firewall and edge routers<br>--- An open port will discard with no response<br>--- A closed port will send a RST    |
| -sX | XMAS Scan<br>--- Raise FIN, URG, PSH Flags <br>Note: Useful to sneak through some stateless firewalls. Works against most UNIX-based systems, but not Microsoft and only some Cisco |
#### NMAP ZOMBIE and BOUNCE SCANS

| Stealth Option                              | Description                                                                                                                                                                                                                                                          |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -sI \<zombilCandidate\>                     | Find a zombie <br>-- The target is the zombie candidate                                                                                                                                                                                                              |
| -sI \<zombieTarget> \<zombieTarget><br><br> | Conduct a blind TCP Port Scan(idle scan)<br>--- Assume the target is UP<br>--- Scan all TCP ports<br>--- Use the "zombie" host to obtain information about open ports on the targets.                                                                                |
| -b \<ftpRelay\> \<FtpTarget\>               | Conduct an FTP bounce scan<br>--- Exploit FTP proxy connections (usingthe port command)<br>--- A user asks a "middle man" FTP server to send files to another FTP server<br>--- Because of widespread abuse, the FTP relay feature has been disabled by most vendors |

```
nmap -sI server.example.com

nmap -sI -Pn -p- zombie.example.com www.company.com

namp -Pn -b ftp.microsoft.com google.com

```


#### NMAP DECOYS and SPOOFING

| Stealth option                               | Decription                                                                                                                                                                                                                              |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -f                                           | Split packets (include pings) into 8-byte fragments<br>--- make it more difficult for packet filtering firewalls and intrusion detection to detect the purpose of packets<br>--- MTU is the maximum fragement size                      |
| -D                                           | Used to mask a port scan by using decoys <br>--- Creates bogus packets from the decoys so the actual attacker blends in with the crowd<br>--- Appears that both the decoys and the actual attackers are performing attacks              |
| -e \<interface\>                             | specify the interface NMAP should use                                                                                                                                                                                                   |
| -S \<spoofed source address \>               | Spoof the source address<br>--- Will not return useful reports to you<br>--- Can be used to confuse and IDS or the target administrator                                                                                                 |
| --spoof-mac \[ vendor Type \| MAC Address \] | Use  bogus source hardware address<br>--- You can specify a random MAC based on vendor, or explicitly specify the MAC Address<br>--- Hides actual source of Scan<br>--- Good with ARP ping scan (since ARP will broadcast its response) |
| --Source-port \<portNumber\>                 | Use a specific source port number (spoof source port)<br>--- Dupes packet filters configured to trust that port <br>--- Same as -g \<Port number\> options                                                                              |
| --randomize-hosts                            | Randomize the order of the hosts being scanned                                                                                                                                                                                          |
| --proxies \<proxy1 : port , proxy2 : port \> | Relay TCP connections through a chain of HTTP or SOCKS4 proxies<br>--- Especially useful on the Internet                                                                                                                                |
```
namp -D 192.168.1.10 192.168.1.15 192.168.1.30 192.200.1.100
nmap -e eth0 192.200.1.100
nmap -e eth0 -S www.google.com 192.200.1.100
nmap -sT -Pn -spoof-mac apple 192.200.1.100
nmap -sT -PN -spoof-mac B7:B1:F9:A0:D4:28 192.200.1.100
nmap -source-port 53 192.200.1.100
nmap --randomize-hosts 192.168.1.36
nmap --proxies http://192.168.1.30:8080 http://192.168.1.40 192.200.1.100

```

#### NMAP TIMING

| Stealth Option | Example                                                                                                                                                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -T \<0-5\>     | Use different timing templates to throttle the speed of your queries<br>--- T3 is default<br>--- T0 is slowest while T5 if fastest<br><br>names labels this T0=paranoid, T1=sneaky, T2=polite, T3=normal , T4=Aggressive and T5=insane |
|                |                                                                                                                                                                                                                                        |
```
nmap 192.200.1.0/24 -T 2
```


#### NMAP REPORTED PORT STATES

| Reported State  | Description                                                                                                                                                                                         |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Open            | This port is actively accepting TCP, UDP and SCTP connections<br>Open ports are the ones that are directly vulnerable to attacks<br>They show available services on a network                       |
| Closed          | Target responds (usually with RST) but there is no application listening on that port<br>Useful for identifying that the host exist and for OS detection                                            |
| Filtered        | NMAP can't determine if the port is open because the probe is being blocked by a firewall or router rules<br>Usually no response or "Destination unreachable"                                       |
| Unfiltered      | Port is accessible but NMAP doesn't know if its open or closed<br>Only used in ACK scan which is used to map firewall rulesets<br>Other scan types can be used to identify whether the port is open |
| Open/Filtered   | NMAP is unable to determine between open and filtered<br>The port is open but gives no response<br>No response could mean that the probe was dropped by a packet filter of any response is blocked  |
| Closed/Filtered | Nmap is unable to determine whether port is closed or filtered Only Used in the IP ID idle scan.                                                                                                    |

#### CUSTOMIZED TCP PACKETS


| Technique    | Purpose                                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| ACK Scan     | --- MAP out firewall rulesets<br>--- Determine if firewall is stateful or stateless                           |
| SYN/FIN Scan | --- Sets both the SYN and FIN bits<br>--- A good way to bypass a rule that drops packets with ONLY SYN raised |
```
nmap -sS --scanflags SYNFIN -T4 www.scanme.org
```

Adding service versioning to a UDP scan helps disambiguate the responses
```
nmap -sUV -T4 scanme.nmap.org
```


Network Administrators can use NMAP for inventory a network managing services upgrade schedules, and monitoring host or service uptime.
It is used to extract information such as live hosts on the network, open ports, services (Application name and version), types of packet filters/firewalls, as well as operating systems and versions used.
By Creating map of network, It sends specially crafted packets to the target host and then analyzes the responses to accomplish its goal.
Nmap includes many mechanisms for port scanning TCP and UDP, OS detection, version detection, ping sweeps and so on.

installation on UBUNTU
```
sudo apt install ettercap-graphical nmap -y
```



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

### Enumerating SNMP using NMAP
NMAP: using snmp-info NSE script against SNMP remote server to retrieve information related to the hosted SNMP services.

Using snmp-processes script to retrieve information related to the hosted SNMP services. 
```
nmap -sU -p 161 --script=snmp-processes <Target IP Address>
```
This command will list of all running SNMP processes along with the associated ports on the target host.

To retrieve information regarding SNMP server type and operating system details  
```
nmap -sU -P 161 --script=snmp-sysdescr <TargetIPAdress>

```

To Retrieves a list of all the applications running on the target machine.
```
nmap -sU -p 161 --script=snmp32-software <TargetIpAddress>
```

