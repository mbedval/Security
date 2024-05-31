#Enumeration in cybersecurity is the process of systematically gathering information about a target system or network to identify potential vulnerabilities that can be exploited. It involves extracting details such as valid usernames, machine names, open ports, services, operating system details, and other information that can be used to gain unauthorized access

Enumeration is a crucial step in the reconnaissance phase of a cyber attack, as it provides attackers with a roadmap to entering a system. It can also be used by security professionals to assess the security posture of their own systems and identify areas that need improvement

In summary, while enumeration is a crucial step in both ethical hacking and malicious attacks, the purpose, methods, scope, tools, and legal and ethical considerations differ significantly between the two. Ethical hackers use enumeration to improve security, while malicious attackers use it to exploit vulnerabilities and gain unauthorized access.

#cehv12

What is enumeration??
Is process of collecting information of target.

- Enumeration involves an attacker creating active connections with a target systems and performing directed queries to gain more information about the target
- Attacker use the extracted information to identify points for a system attack and performed password attacks to gain unauthorized access to information system resources.
- Enumeration techniques are conducted in an intranet environment

example: Attacker may stumble upon a remote inter-process communication (IPC) share such as IPC$ in windows and probe further to connect to an administrative share by brute-forcing admin credentials and obtain complete information about the file-system listing that the share represents.


Information enumerated (collected) by Intruders

1. Network resources
2. Network shares
3. routing tables
4. Audit and service settings
5. SNMP and FQDN details
6. Machine names
7. Users and groups
8. Applications and banners

Technique for Enumeration: 
- Extract username from email id
- Extract information using default password of system, devices
- Brute Force Active Directory: If logon hours feature is enabled , MS Active Directory results different error messages. Attacker can take advantage of this to enumerate valid usernames.
- Extract Information using DNS Zone Transfer: Network administrator can use DNS zone transfer to replicate DNS data across several DNS servers or backup DNS files. for this purpose the administrator needs to execute a specific zone-transfer request to the name server. If the name server permits zone transfer, it will convert all the DNS names and IP addresses hosted by that server to ASCII text. In this if DNS server is not configured properly, the DNS zone transfer can be an effective method to obtain information about the organization's network. This information may include lists of all named hosts, sub-zones and related IP addresses. A user can perform DNS zone transfer using 'nslookup' and 'dig' commands.
- Extract user groups from windows: Attacker once is registered user in the active directory. The attacker can then extract information from groups in which the user is a member by using the windows interface or command-line method.
- Extract username using SNMP: Attackers can easily guess read-only or read-write community string by using the SNMP application programming interface API to extract usernames.

TCP: is a connection oriented protocol capable of carrying messages over internet. if provide a reliable multi-process communication service in a multi-network environment. The feature and function of TCP includes
- Supports acknowledgement for receiving data through a sliding window acknowledgment system.
- Offers automatic retransmission of lost or acknowledged data
- Allows addressing and multiplexing of data.
- A connection can be established, managed or terminated
- Offer Quality-of-Service transmission.
- Offers congestion management and flow control

UDP is connectionless protocol that carries short messages over a computer network. It provides unreliable service. The applications of UDP include the following:
- Audio Streaming
- Video Conferencing and Tele Conferencing

Services and Ports to Enumerate:
- TCP 20/21 FTP
	FTP is a connection-oriented protocol used for transferring files over the Internet and private networks. FTP is controlled on TCP port 21, and for data transmission, FTP uses TCP port 20 or some dynamic port numbers depending on the server configuration. If attackers identify that FTP server ports are open, then they perform enumeration on FTP to find information such as the software version and state of existing vulnerabilities to perform further exploitations such as the sniffing of FTP traffic and FTP brute-force attacks

- TCP 22: Secure Shell (SSH)
	SSH is command level protocol mainly used for managing various networked devices securely. It is generally used as an alternative protocol to the unsecure Telnet protocol. SSH uses client/server communication model, and the SSH server, by default listen to its client on TCP port 22. Attacker may exploit SSH protocol by brute-forcing SSH login credentials.
	
	
- TCP 23 Telnet :
	The Telnet protocol is used for managing various networked devices remotely. It is an unsecure protocol because it transmits login credentials in the cleartext format. Therefore, it is mostly used in private networks. The Telnet server listens to its clients on port 23. Attackers can take advantage of the Telnet protocol to perform banner grabbing on other protocols such as SSH and SMTP, brute-forcing attacks on login credentials, port-forwarding attacks, etc.
	
- TCP 25: Simple Mail Transfer Protocol (SNMP)
	SMTP is TCP/IP mail delivery protocol. It transfer email across the internet and across local networks. It runs on the connection-oriented services by TCP and uses the well-known port number 25. Below table lists some commands used by SMTP and their respective syntaxes.
	
- TCP 139: NetBIOS Session Service (SMB over NetBIOS): 
	TCP is well known windows port. It is used to transfer files over an network. Systems uses this port for both #null-session establishment as well as file and printer sharing. To Restrict administrator should make it a top Priority, because improper configured TCP port 139 can allow a intruder to gain unauthorized access to critical system files or the complete file system, resulting in data theft or other malicious activities. 

	
- TCP 179 : Border Gateway Protocol (BGP)
	BGP is widely used by Internet service providers (ISPs) to maintain huge routing tables and for efficiently processing Internet traffic. BGP routers establish sessions on TCP port 179. The misconfiguration of BGP may lead to various attacks such as dictionary attacks, resource-exhaustion attacks, flooding attacks, and hijacking attacks.
	
- TCP 2049: Network File System (NFS)
	NFS protocol is used to mount file systems on a remote host over a network, and users can interact with the files systems as if they are mounted locally. NFS servers listen to its client systems on TCP port 2049. If NFS services are not properly configured, then attackers may exploit the NFS protocol to gain control over a remote system, perform privilege escalation, inject backdoors or malware on a remote host, etc.
	
- TCP/UDP 53: Domain Name System (DNS) Zone Transfer 
	DNS Servers listening on UDP (Default protocol) on Port 53, in response if message size exceed more the default size (512 Octets) server sends a flag to indicate response message is truncated. So DNS client resend request via TCP over port 53. In case of lengthy queries for which UDP fails, TCP is used as failover solution.
	
- TCP/UDP 135: Microsoft RPC Endpoint mapper
	RPC is protocol used by client system to request a service from server, An Endpoint is the protocol port on which server listens for the client's RPC. RPC mapper enables RPC clients to determine the port number currently assigned to a specific RPC Services.  There is flaw in the part of RPC that exchanges messages over TCP/IP. The incorrect handling of malformed messages causes failures.  This vulnerability allows the attacker to send RPC messages to RPC Endpoint mapper process on a server to launch a denial-of-service (DoS) attack.
	
- TCP/UPD 389: LDAP (Light weight Directory protocol)
	LDAP is a protocol for accessing and maintaining distributed directory information services over an IP network. By Default LDAP uses TCP or UDP as its transport protocol over port 389
	
- TCP/UDP 162: SNMP Trap
	as SNMP trap uses TCP/UDP port 162 to send notification such as optional variables binding and the sysUpTime value from an agent to a manager.
	
- TCP/UDP 445: SMB over TCP (Direct Host)
	Windows Supports file and printer-sharing traffic using the SMB protocol directly hosted on TCP. in earlier OSs, SMB traffic required the NetBIOS over TCP (NBT) protocol to work on TCP/IP transport. Directly hosted SMB traffic uses port 445 (TCP and UDP ) instead of NetBIOS
	
- TCP/UDP 3268 : Global Catalog Service
	Microsoft Global Catalog server, a domain controller that stores extra information, uses port 3268. Its databases contain rows for every objects in the entire organization, instead of rows for only the objects in one domain. Global Catalog allows one to locate objects from any domain without having to know the domain name. LDAP in the Global Catalog server uses port 3268. This service listens to port 3268 through a TCP connection. Administrators use port 3268 for troubleshooting issues in the Global Catalog by connecting to it using LDP.
- TCP/UDP 5060, 5061 Session Initiation protocol (SIP)
	The Session Initiation Protocol (SIP) is protocol used in internet telephony for voice and video calls. Its typically uses TCP/UDP port 5060 (Non-encrypted signaling traffic) or 5061 (encrypted traffic with TLS) for SIP to servers and other endpoints.
	
- udp 69:
	TFTP is a connectionless protocol used for transferring files over the Internet. TFTP depends on connectionless UDP; therefore, it does not guarantee the proper transmission of the file to the destination. TFTP is mainly used to update or upgrade software and firmware on remote networked devices. It uses UDP port 69 for transferring files to a remote host. Attackers may exploit TFTP to install malicious software or firmware on remote devices
	
- UDP 137: NetBIOS Name Service (NBNS): 
	NBNS is known as windows internet name service (WINS), it provides a name resolution service for computers running NetBIOS. NetBIOS name servers maintain a database of the NetBIOS names and queries. Attackers usually attack the name service first. TCP 137 could be used as its transport protocol for few operations, but might never occur in practice.
	
- UDP 161: Simple Network Management Protocol (SNMP)
	SNMP is widely used in network management systems to monitor network-attached devices such as routers, switches, firewalls, printers, and servers. It Consists of a manager and agents. The agents receives requests on port 161 from the managers and responds to the managers on port 162.
	
- USP 500 : ISAKMP / Internet Key Exchange (IKE)
	Internet Security Association and Key Management Protocol (ISAKMP)/ Internet Key Exchange (IKE) is a protocol used to set up a security association (SA) in the IPsec protocol suite. It uses UDP 500 to establish, negotiate, modify and delete SAs and cryptographic keys in a virtual private network (VPN) environment.



