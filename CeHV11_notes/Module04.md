## Enumeration Overview

#### What is enumeration?
- The Systematic process of querying a target' servers and services for information
- The attacker utilizes information gathered during footprinting / reconnaissance to know which devices and services to query
- We exploit normal server functionality and protocols to gain more information about out target
- information Enumerated
	- OS & Services details
	- User and groups 
	- Emails addresses and contact information
	- Network shares
	- Routing tables
	- Audit and Services settings
	- SNMP and DNS information
	- Machine names
	- Application and banners

#### Enumeration Approach
- Enumeration should appear to the server as a normal client making legitimate information requests
- Your enumeration test should focus on the information you need
	- You want to avoid returning too much information that will clutter your results
- A combination of manual and automated testing will give the best results.

#### BANNER GRABBING EXAMPLE

``` 
netcat www.somehackableserver.com 80
```

RPCClient Enumeration Example
```
rpcclient <target IP> -U <username>
srvinfo
lookupnames administrator
lookupsids

rpctclient -U "" 192.168.1.20
```

#### METASPLOIT ENUMERATION EXAMPLE
```
user /auxiliary/scanner/smb/smb_lookupsid
set SMBUser moo
set SMBPass Pass22w0rd
set MinRID 1000
set MaxRID 1100
set RHOSTS 192.168.74.50

run
```

#### Services Enumeration TOOLS

| Port         | Services | Tools, Example and Comments                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP 21       | FTP      | Tools: Telnet and FTP client , nmap ftp-anon.nse, ftp-brute.nse, <br>Metasploit module : ftp/anonymous, ftp_login and ftp_version<br><br>Comments: identify FTP servers, versions, and authentication requirements including anonymous logins                                                                                                                                                                                                              |
| TCP 22       | SSH      | Tools: nmap, putty/ssh clients, nmap ssh-run.nse, <br>metasploit modules: ssh_login, ssh_login_pubkey<br><br>Comments: Linux servers, routers, switches and other network devices, jailbroken iphones                                                                                                                                                                                                                                                      |
| TCP 23       | telnet   | Tools : putty/telnet clients, nmap telnet-brute.nse, telnet-ntlm-info.nse, <br>metasploit moduels: telnet_login, telnet_version<br><br>comments: linux server, router, switches and other network devices                                                                                                                                                                                                                                                  |
| TCP 25       | SMTP     | Tools: putty/telnet clients, nmap smtp-enum-user.nse, smtp-command.nse, smtp-open-relay.nse, smtp-brute.nse, metasploit module smtp_enum, smtp_Version modules<br><br>Comments: Extract email addresses, Enumeration smtp server information search for open relays<br>                                                                                                                                                                                    |
| TCP 53       | DNS      | Tools: dig, nslookup, nmap dns-brute.nse, metasploit module enum_dns<br><br>Comments: Elicit DNS transfer. Disocver DNS subdomains<br>                                                                                                                                                                                                                                                                                                                     |
| TCP 80       | HTTP     | Tools: putty/telnet clients dirbuster, nmap http-enum.nse, http-title.nse, http-sitemap, dir_webdav_unocode_bypass, enum_wayback, files_dir, http_login, http/ssl, http_version, webdav_scanner, webdav_website_content<br><br>Comments: Manually request web pages, enumerate directories, files webDAV features, version and more<br>                                                                                                                    |
| TCP 135, 111 | RPC      | Tools: nmap rpcinfo.nse, rpc-grind.nse, msrpc-enum.nse, metasploit dcerpc<br><br>Comments: Query and manipulate Remote Procedure call (RPC) based services such as windows DCOM and \*nix NFS, nlockmgr, quotad and mounted  <br>                                                                                                                                                                                                                          |
| TCP 137      | NETBIOS  | Tools: nbtscan, nmap smb-enum-shares.nse, smb-enumdomains.nse, smb-os-discovery.nse<br><br>Comments: List NetBios computer, user, group, workgroup and domain names, domain controller roles, file and print sharing services, Microsoft Exchange services <br>                                                                                                                                                                                            |
| TCP 139      | SMB      | Tools: enum.exe, enum4linux.pl, smbclient, nmap smb-enum-shares.nse smb-os-discocvery.nse. Metasploit modules smb_enumshares, smb/smb2, smb_version<br><br>Comments: Retrieve directory information, list and transfer files NSE scripts might not work on newer versions OS <br>                                                                                                                                                                          |
| UDP 161      | SNMP     | Tools: getif, Solarwinds, NPM, PRTG, whatsup gold, Nagios, Spiceworks, Observium, nmap snmp-info.nse, smtp-brute.nse, snmp-interface.nse snmp-processes.nse, Metasploit modules snmp_enum, snmp_enumusers, snmp_enumshares, snmp_login<br><br>Comments: obtain information on dozens of data objects depending on device, Targets must have SNMP agent enabled, you must know the community string devices are using<br>                                   |
| TCP/UDP 389  | LDAP     | Tools: Active Directory users and computer, ntdutil.exe, OpenLDAP, LDAPAdmin, LDP.exe, nmap ldap-search.nse, Metasploit module enum_ad_computers<br><br>Comments: Retrieve a wide range of information from Active Directory. Non Priviledge user can query Active directory nearly all information. To capture password hashes, copy database files using ntds.dit using ntdsutil.exe, then use windows password Recovery tools to extract the hases.<br> |
| TCP 445      | RPC      | Tools: RPC client, metasploit smb_login, smb_enumusres, and smb/psexec modules, nmap NSE smb-enum-* Scripts, enum.exe, user2sid.exe sid2user.exe, Powershell, pstools.<br><br>Comments: Retrieve wide range of microsoft computer and domain information.<br>                                                                                                                                                                                              |
| TCP 1433     | SQL      | Tools: nmap mysqlinfo-exe Metasploit modules mssql_ping, mssql_enum, enum_domain_accounts, enum_sql_logins<br><br>Comments:  Locate and enumeration information including logins from microsoft and mysql SQL servers<br>                                                                                                                                                                                                                                  |
| TCP 3268     | LDAP     | Tools: same as LDAP only with different port<br><br>Comments: The active directory global catalog mains listing of all objects in an entire Active Directory Forest.<br>                                                                                                                                                                                                                                                                                   |
|              |          |                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

#### SMB and NETBIOS ENUMERATION

##### NETBIOS
- Network Basic Input/Output System
- An API and Layer 5 protocol
- Allows applications to communicate over a local area network (LAN) with device specific NetBIOS names
	- 1-15 alphanumeric characterist (a hidden 16th character describes the name type)
	- Special characters can only include (  - . __ $) dash, period, underscore, dollar sign
	- $ has special meaning (name or share exists but is hidden on the network)
	- Only the dash is compatible with DNS naming conventions
- Used by Microsoft for simple LAN communications, name resolutions and file sharing
- Originally used by broadcast-based NetBEUI networking protocol
- Microsoft later made it a payload of TCP/IP (NetBIOS over TCP)
- TCP 137, 139 UDO 137 , 138

##### NETBIOS NAMES
#NetBIOSNameList 

##### SERVER MESSAGE BLOCK (SMB)
- Microsoft file and print sharing protocol
- Microsoft workstation service (client) connects to a remote machine's server services 
- Also provides authenticated inter-process communications (IPC) among processes running on remote computers
- A hidden network share, known as IPC share (ipc$) is used on windows computers 
	- Facilitates communication between processes and remote computers

##### NETBIOS and SMB
- Originally NetBIOS and SMB worked together
	- An SMB Client uses the NetBIOS API to send an SMB command to an SMB server
		- Listens for replies from the SMB server
	- An SMB servers uses the NetBIOS API to listen for SMB commands from SMB clients
		- Send replies to the SMB client
- Since windows 2000, SMB runs directly on TCP 445
- NetBIOS still exists for backward compatibility
- Linux/ Unix Samba server is a reverse-engineered SMBv1 File server service
	- It has the same vulnerabilties as the Windows original
> NetBIOS and SMB have a long history of vulnerabilities

NetBIOS / SMB Enumerations
- You can use SMB to make NetBIOS calls to a Microsoft server service
- You can Enumerate:
	- Computer names
	- Share names
	- User names
	- Logon information
	- Password policy and hashes
	- NetBIOS computer and domain names
	- Active Directory domain and forest names
	- FQDNs
	- System time
##### NULL USER
- A null user is pseudo account that has no username and password
- was initially used by windows systems to "Log in" to each to trade network browse lists
- For decades the null session was an exploit that took advantage of the null user 
- Mapping a drive to the IPC$ process then allows you to enumerate a lot of information via NetBIOS and SMB

#### NBTSTAT 
- Windows utility
- Displays NetBIOS over TCP/IP protocol statistics, NetBIOS name tables for local and remote computer and the NetBIOS cache
```
nbtstat [-a remotename] [-A IPAddress] [-c] [-n] [-r] [-R] [-RR] [-s] [-S] [Interval]
```
#### NETCOMMAND 

- has 19 sub command for enumerating information VIA NetBIOS
```
NET [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |
      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |
      STATISTICS | STOP | TIME | USE | USER | VIEW ]
```
#### ENUM4LINUX EXAMPLE
[pending]
#### SHAREENUM EXAMPLE
[pending]

#### SUPERSCAN
- A connection-based TCP port scanner, pinger and hostname resolver
	- Support for unlimited IP ranges
	- Host detection by multiple ICMP methods
	- TCP SYN and UDP scanning
	- Simple HTML report generation
	- Source Port Scanning
	- Hostname resolving
	- Banner grabbing
	- Window Host enumeration

#### ADDITIONAL NETBIOS ENUMERATION TOOLS

- NetBIOS Enumerator
- NSAuditor Network Security Auditor
	- Includes more than 45 network tools and utilities for network security auditing, network scanning, network monitoring etc.
- Hyena
	- A GUI application for managing and security Microsoft operating systems
	- Shows Shares
	- User logon name for windows servers and domain controller
	- Displays graphical representation of Microsoft Terminal Services, Microsoft Windows Network, web client network, etc.
- WinFingerprint
	- Shows operating systems, enumerates users, groups, SIDs transports sessions, services, service pack and hostfix level, date and time, disks and open TCP/UDP ports


### FILE TRANSFER ENUMERATION
#### FILE TRANSFER PROTOCOL
- A common clear text file sharing protocol
	- Interactive
	- Has commands to list files and directories, upload and download files
	- TCP 21 (commands)
	- TCP 20 or random port (data transfer)
- An FTP server can be configured to:
	- Authenticate a user
	- Allow anonymous connections
- You can use the FTP protocol to enumerate
- ##### FTP ACTIVE MODE
	- random port 1 request to FTP server at PORT 21 but FTP Server response via port 20 to client on new/other port
	- ==Problem Statement== : The server tries to initiate the data connection, which the client's firewall blocks
	- Solution: FTP PASSIVE MODE is the solution. The client inititates the data connection, which the client's firewall allows.
- ##### FTP ENUMERATION
	- You can use FTP commands to enumerate information from an FTP Server
		- Accounts
		- Passwords
		- Anonymous login capabilities
		- Port Scanning other targets
- ##### FTP Enumeration tools
	- Netcat
		- Banner grab from an FTP Server
	- NMAP Scripts
		- ftp-anon:   Checks if an FTP server allows anonymous logins
		- ftp-brute:   Perform brute-force password auditing against FTP servers
		- ftp-bounce: Checks to see if an FTP server allows ports scanning using the FTP bounce method
	- ftp-user-enum
		- Tools for enumerating OS-Level user accounts via the FTP service
		- Works against the default solaris in.ftpd and GNU inetutils ftpd
- #### TRIVIAL FTP (TFTP)
	- FTP's Little Brother
		- No authentication
		- Clear text
		- UDP 69
		- non-interactive
		- no browsing the server directory
		- you must know the name of the file you want to download/upload
	- Typically used to upload/download OS and config files for networking devices
		- You can try downloading a configuration file by its default name
- ##### USING TFTP to Enumerate Information
- you can try to download configuration files stored on a TFTP server
	- The service has no way to authenticate connection or enforce authorization
- NMAP has a script that will try to download files by supplying a list of file names
```
	- nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=customlist.ext <host>
```

#### NETWORK FILE SYSTEM (NFS)
- The File sharing system for linux/unix
- Clients can mount (connect to) a share
- Tools to enumerate NFS include:
	- rpcinfo (part of linux rpcbind)
	- rpcscan (written in python, available on #GitHUB)
	- SuperEnum (Written in python, available on #github)
- You can use the NFS client to enumerate shares on the network

NFS EXAMPLE
- OnServer : - 
	- Add line in the /etc/exports to allow anyone on the subnet to read/write to the share  "/home/srvshare 192.168.1.0/24 (rw / sync)"
	- Run a command to export all shared listed in /etc/exports
	- Start the NFS server process
- OnClient
	- mkdir /home/fromserver
	- sudo mount -t nfs \<server IP\>:/home/srvshare /home/fromserver

### 4.4 WMI ENUMERATION
#### WINDOWS MANAGEMENT INSTRUMENTATION (WMI)
- The Microsoft implementation of Web-Based enterprise management (WBEM)
- A standard technology for accessing management information in an enterprise environment
- Uses the common Information Model (CIM) industry standard to represent systems, application, networks, devices and other managed components
- Capable of obtaining management data from remote systems
	- Uses DCOM (TCP 135) to make these connections

##### WMI NAMESPACE
- WMI Organizes its classes in a hierarchical namespace
	- Conceptually similar to a folder structure
- root/cimV2 similar to a folder structure
	- It contain 277 classes for computer hardware and configuration. Commonly queried classes are as follows

| Win32_BIOS                | Win32_BootConfiguration           | Win32_ComputerSystem |
| ------------------------- | --------------------------------- | -------------------- |
| Win32_ComputerSystemEvent | Win32_ComuputerSystemPrecessor    | Win32_CurrentTime    |
| Win32_DeviceSettings      | Win32_DiskPartition               | Win32_Group          |
| Win32_GroupUsers          | Win32_IP4RouteTable               | Win32__LogicalDisk   |
| Win32_LogonSession        | Win32_NetworkAdapterConfiguration | Win32_NetworkClient  |
| Win32_NetworkConnection   | Win32_NTDomain                    | Win32_NTLogEvent     |
| Win32_OperatingSystem     | Win32_Process                     | Win32_Processor      |
| Win32_Registery           | Win32_ScheduledJob                | Win32_Service        |
| Win32_Share               | Win32_StartupCommand              | Win32_SystemAccount  |
| Win32_SystemBIOS          | Win32_SystemUsers                 | Win32_UserAccount    |
| Win32_UserInDomain        |                                   |                      |


#### COMMON POWERSHELL CMDLETS FOR WMI
Get-CimClass : Returns all WMI classes
Get-CimInstance -ClassName \<name\> : Return information about a particular class
```
get-CimInstance -ClassName Win32_Processor
Get-CimInstance "*processor*"   (Mux) need to validate
Get-CimInstance Win32_process | ft
Get-CimInstance ClassNAme | ft-autosize //output results in table format, automatically resizing columns as needed
Get-CimInstance ClassName | gl // Output results in list format
```

#### QUERY WMI WITH WQL
- WMI Query Language
- A subset of ANSI SQL
- Basic Syntax :- 
	- Select \<property\> from \<WMI-class\>
- Examples: 
```
Select * from Win32_BIOS
Select Name from Win32_Bios
Select name, version from Win32_Bios
```
- Can be used in powerShell, other scripts and custom apps.
- Sometimes has better performance than equivalent PowerShell cmdlets
	- Queries might also be more complex than the equivalent cmdlet

#### WMI ENUMERATION AND EXPLOIT TOOLS
Enumeration
#SolarWindsFreeWMIMonitor #WMIExplorer (CodePlex) #WMIExplorerMarchVanOrsouw #Hyena #Powershell 
Exploit
#GitHub #WMIsploit #SharpStrike #WMEye #Powershell 
#MetaSploit Exploit/windows/local/wmi , auxiliary/scanner/smb/impacket/wmiexec, exploits/windows/local/wmi_persistence

#### 4.5 SNMP Enumeration

#### SIMPLE NETWORK MANAGEMENT PROTOCOL (snmp)
- Used to centrally monitor devices on a network
- An SNMP manager polls agents for informtion
	- Polling is done round style, on a regular interval (every few minutes)
	- Manager is software on a server or workstation
	- Agent is small software installed or build into a device OS
- The manager uses a management Information Base (MIB) to know what types of information an agent can provide
	- A MIB is a set of counters (Object IDs ) relevant to the device
#### SNMP Security
- SNMP has several versions that are still in use
	- v1, v2, v2c all communicate in clear text
	- v3 is encrypted
	- Not all device support for v3
- Both the manager and agent are configured with a simple authentication mechanism called the "community string"
	- Simple text string
	- An agent will only respond to  a manager that has the same community string
	- There are two default community strings
		- Public - for read-only queries
		- Private - for read/write communications
		- Many administrators do not change the default community strings
	- SNMP Ports
		- UDP 161 : Manager queries and agent replies
		- UDP 162 : Agents "raise traps" (send pre-configured alerts) to the manager

#### SNMP Components
- Managed Device
	- Router, switch, hub, firewall, computer, server service (DHCP, DNS, etc) printer, IoT device
- Agent
	- Software installed on managed devices
	- Responds o the NMS
- Network Management Systems (NMS)
	- Typically software installed on a dedicated computer

#### OBJECT IDENTIFIER (OID)
- Represents a single "question" and SMNP manager can ask an agent
- Identifies a very specific, unique counter on a device
- Has a corresponding name and data type
- When queried by manager agent will return a value

#### Management Information Base (MIB)
- A collection of OIDs stored in a text file
- A set of questions that an SNMP manager can ask a device regarding its status
- Standardized vendor-neutral MIBs define functionality common to all devices of the same type
- The manufacturer creates additional MIBs specific to their products
- An agent might use multiple MIBs to monitor one device
- Most SNMP managers have MIBs already installed
	- Vendor-neutral MIBs
	- Vendor-specific MIBs for popular products

#### MIB HIERARCHY
- All OIDs, regardless of manufacturer, are part of a global hierarchy
- Each OID is unique
- The SNMP manager must know what MIBs the agent is using
	- At least know a starting OID to query
	- The manager can then repeatedly issue a “get-next” command
	- The agent will provide information about successive OIDs
	- The manager does not need to OIDs for every single counter on the device

#### SNMP ENUMERATION
- SNMP is a good target for enumeration
- Often the defaults are not changed:
	- Community strings
	- Encryption levels
- Most versions use clear-text communications
	- Microsoft devices don’t even support the encrypted version
	- You might be able to sniff community strings and manager-agent communications
- Many SNMP management tools include a feature to discover all the MIBs installed on
- the agents
- You can also “walk” the MIB
	- Start at a single common OID
	- Repeatedly ask the device to “get-next” until it runs out of OIDs to report on

#### INFORMATION SNMP CAN ENUMERATE
network devices, Hosts, user and groups, Services, Installed software, Network shares, Device configurations, IP and Mac addresses, ARP Tables, Routing tables, Vlans, Port and interface status, Network traffic, etc

#### SNMP ENUMERATION TOOLS
#SolarWindsFreeWMIMonitor  #NMAPScripts #MetasploitSNMPauxiliaryModules #snmpwalk #snmpget #SNMPScanner #getIF #Observium #OpUtils #OIDViewSNMPMIBBrowser #iReasoningMIBbrowser #SNScan #SoftPerfectNetworkScanner #SNMPInformant #NetSNMP #NSauditorNeworkSecuritySpiceworks  
```
Syntax : snmpget [options] [community string] [hostname / address ] [OID]

snmpget -v2c 127.0.0.1 -c public .1.3.6.1.2.1.1.5.0

```

### 4.6 LDAP ENUMERATION
#### LIGHTWEIGHT DIRECTORY ACCESS PROTOCOL (LDAP)
- The search and edit protocol for X.500-style directory service databases
- TCP 389
- Secure LDAP TCP 636
- Clear text by default
- Can be used to obtain a list of every object in the directory service database including:
	- User, Group, and Computer accounts
	- User department and contact information
	- Group membership
	- Network resource information
- Directory Service Examples:
	- Microsoft Active Directory Domain Services
	- Novell eDirectory
	- Open Software Foundation DCE Directory

#### X.500 NAMING HIERARCHY
LDAP Directory Tree
	dc=net , dc.com, dc=org
	 Organization dc=example
		Organization Unit  OU= people, OU=servers
			Person  udid   = mbedval

#### LDAP ENUMERATION TOOLS
- Active Directory Users and Computers
- #SofterraLDAPAdministrator #LDPexe #Metasploit module ldap_hashdump
- - LDP.exe #nmapNSEforLdap #jXplorer (www.jxplorer.org)
- Responder (available on github)
	- ` .Responder.py -I eth0 -rPv -I <server IP>`

### 4.7 DNS ENUMERATION
- Query a DNS server for its records:
	- A, AAAA
	- NS
	- MX
	- CNAME
	- PTR
	- SOA 
- Obtain individual records or “zone transfer” the entire database file
	- Exploit DNS AXFR (all transfer) vulnerability
	- Some DNS servers will transfer their entire zone to any requestor without requiring authentication
	- This saves the attacker time
	- You can also just manually request all the various record types and end up with the same content

#### DNS ENUMERATION TOOLS
#Dig #FIERCE #NSLOOKUP #Host #dnsrecon  #dnsenum 
- Metasploit auxiliary module dns_enum 
- Nmap NSE script dns-brute
- SecurityTrails advanced DNS enumeration

```
dnsrecon# ./dnsrecon.py -d cisco.com
```

##### NSLOOKUP EXAMPLES 
```
#Windows
nslookup example.com
nslookup -type=ns example.com
nslookup -type=soa example.com
nslookup -query=mx example.com
nslookup -type=any example.com
nslookup example.com ns1.nsexample.com
nslookup 10.20.30.40
nslookup -type=ptr 96.96.136.185.in-addr.arpa
```
##### DIG
Unix/Linux tool for querying DNS
```
dig Hostname
dig DomaiNameHere
dig @DNS-server-name Hostname
dig @DNS-server-name IPAddress
dig @DNS-server-name Hostname|IPAddress type
dig www.example.com A
dig 74.125.236.167
dig +short example.com MX
dig +short example.com TXT
dig +short example.com NS
dig example.com ANY
```

##### DIG and FIERCE ZONE TRANSFER EXAMPLES
- Try a zone transfer by guessing the domain that the server is authoritative for:
`dig axfr @<DNS_IP> \<DOMAIN\>`
-  Try to perform a zone transfer against every authoritative name server
	- If it doesn’t work, launch a dictionary attack
`fierce --domain <DOMAIN> --dns-servers <DNS_IP>`

### 4.8 SMTP ENUMERATION

#### How EMAIL WORKS
 - ACME client uses SMTP to send email message to email server for acme.com
- Local email server performs DNS lookup to find MX record and IP address (A/AAAA record) of email server for example.com
- Acme.com email server uses SMTP to deliver message to example.com email server
- Example.com email server puts message into example.com client mailbox
- Example.com client later retrieves message using POP3, IMAP4, HTTP, or even RPC

#### SMTP ENUMERATION
- Simple Mail Transfer Protocol (SMTP) has three built-in commands
	- VRFY – validates that an email address actually exists for a user
	- EXPN – request or expand a mailing list into individual recipients
	- RCPT TO – Specifies the actual recipient(s)
- As an attacker, you can use the SMTP commands manually to enumerate valid email addresses

##### SMTP ENUMERATION TOOLS
#telnet #netcat #netScanToolsPro #smtp-user-enum #smtp-user-enum-py #kali-ismtp 
- Metasploit auxiliary module smtp_enum
- Nmap NSE script smtp-enum-users

#### TELNET SMTP ENUMERATION EXAMPLE

```
telnet <email server> 25
very test@example.com
// if return code is 250, 251, 252 than The server has accepted the request and the user account is valid
// if the received message code is 550: than the user account is invalid
```

#### SEND An EMAIL USING TELENT
```
telnet mail.example.com 25
ehlo example.com
mail from: username@example.com
rcpt to: friend@hotmail.com, friend2@yahoo.com
data
Subject: My Telnet Test Email
Hello,
This is an email sent by using the telnet command.
Your friend,
Me
.
q 
```

#### METASPOIT SMTP ENUMERATION EXAMPLE
- Create user.txt containing email address to be tested
- Open Metasploit framework
- In the Metasploit console enter commands
```
use auxiliary/scanner/smtp/smtp_enum
set rhosts <email server IP>
set rport 25
set USER_FILE /root/Desktop/user.txt
exploit
```

##### SMTP-USER-ENUM Example
```
smtp-user-enum -M VRFY -D example.com -u moo -t <email server IP>
smtp-user-enum -M VERY -U /home/mbedval/Desktop/email.txt -t 192.168.1.100
// suply list of usernames and verify if they exist
```

##### ISMTP Example
Verify the email addresses supplied in the email.txt list actually exist
```
ismtp -h <email-server-IP>:255 -e /root/Desktop/email.txt
```

### 4.9 REMOTE CONNECTION ENUMERATION
#### TELENT ENUMERATION
- TCP 23
- Used to obtain a command prompt of the remote host
- Can also be used to banner grab 
```
	telnet <target> <port>
```
- Nmap has several telnet enumeration scripts
	- Run all Nmap telnet scripts against a target:
	```
		nmap -n -sV -Pn --script "*telnet* and safe" -p 23 <target>
	```
	- Brute force password via telnet
	```
		Nmap –script telnet-brute <target>
	```

#### SSH ENUMERATION

- TCP 22
- Secure replacement for telnet
- Client and server exchange public keys to create a session key
- Includes Secure FTP (SFTP) and Secure Copy (SCP)
- Login syntax = ssh \<username\>@\<hostname\>
- Some SSH implementations have default usernames and passwords
	- Example: jailbroken iPhone SSH service uses root / alpine
- Nmap, Metasploit and Searchsploit have various tools for SSH enumeration and exploitation

#### SSH ENUMERATION EXAMPLE

- Use Nmap to determine if a host is running an SSH service
- Use Nmap to query the version of SSH
- Use a Metasploit module to enumerate SSH users
- Check the Kali Searchsploit module to see if an enumeration (or other) exploit
- exists for the SSH service
- Search for nmap scripts related to SSH enumeration
```
NMAP <TargetIPAddress>
Nmap -sC -sV <TargetIPAddress>
// Using script from various scripts with nmap 
ls /usr/share/nmap/scripts | grep ssh
```

- Use Metasploiit modules to enumerates SSH or login information
```
	search ssh_enumusers
	search ssh_login
```


- Use the kali searchsploit module to search for version-specific exploits
```
kali:-# searchsploit openssh

```
##### RPCCLIENT COMMANDS

| Command             | Interface | Description                                    |
| ------------------- | --------- | ---------------------------------------------- |
| Queryuser           | SAMR      | Retreive user information                      |
| Querygroup          | SAMR      | Retrieve group information                     |
| querydominfo        | SAMR      | Retrieve domain information                    |
| enumdomusers        | SAMR      | Enumerate domain users                         |
| enumdomgroups       | SAMR      | Enumerate domain users                         |
| createdomuser       | SAMR      | create a domain user                           |
| deletedomuser       | SAMR      | Delete a domain user                           |
| lookupnames         | LSARPC    | Look up usernames to SID values                |
| lookupsids          | LSARPC    | Look up SIDs to username (RID Cycling)         |
| lsaaddacctraghts    | LSARPC    | Add right to a user account                    |
| lsaremoveacctrights | LSARPC    | Remove rights from a user account              |
| dsroledominfo       | LSARPC-DS | Get Primary domain information                 |
| dsenumdomtrust      | LSARPC-DS | Enumerate trusted domains within and AD forest |


> SAMR = Security Account Manager (SAM) Remote Protocl
> LSARPC =Local Security Authority (Domain Policy) Remote Protocol

##### RPCClient Examples
```
rpcclient -U Administrator%Password@123. 192.168.1.172
//provides shell rpcclient $> 

rpcclient $> srvinfo
rpcclient $> enumdomusers


```


### 4.10 Website Enumeration
### WHAT CAN A WEBSITE REVEAL

- Usernames and passwords
- Email addresses and contact information
- Domain names, host names and IP addresses
- Links and URLs
- Technologies used by the organizations
- Employee, customer and other confidential information
- Internal resources
- Potential vectors for attack
- The simplest way to start website enumeration
- View the HTML source of a web page
- Attempt to open a browser to popular directory names
- Note the HTTP response code:
	- 404 = "Not Found“
	- 403 = "Forbidden“
	- 402 = "Payment Required“
	- 401 = "Unauthorized" (Must authenticate first)
	- 200 = "OK“

#### NON-STANDARD PORTS
- Some websites are deliverately configured to use non-standard ports
- nmap -sV can detect this

```
nmap -PN -sT -sV -p0-65535 <target>
```

#### NMAP WEBSITE ENUMERATION SCRIPTS
```
nmap --script=http-enum <target>
nmap --script=http-drupal-enum <target>
nmap -–script=http-php-version <target>
nmap --script=http-webdav-scan <target>
nmap --script=http-wordpress-enum <target>
```
#### METASPLOIT WEBSITE SCANNING MODULES
```
Metasploit has 281 web scanning modules including:
auxiliary/scanner/http/apache_userdir_enum
auxiliary/scanner/http/tomcat_enum
auxiliary/scanner/http/chromecast_webserver
auxiliary/scanner/http/brute_dirs.
auxiliary/scanner/http/dir_listing
auxiliary/scanner/http/dir_scanner
auxiliary/scanner/http/http_version
auxiliary/scanner/http/wordpress_login_enum
```

#### WEBSITE ENUMERATION TOOLS
##### ENUMERATION TECHNIQUE
- Google Dorks
- Word lists
- Brute Forcing
- Third party services
- SSL Certificates
- SSL Certificates
- DNS Zone Transfer

##### WEBTECHNOLGIEUSED
- WhatWeb
- Wappalyzer
- NetCraft
- IDServe



##### SUBDOMAIN ENUMERATIONS
- Wfuzz
- WPSCan
- Amass
- Assetfinder
- SubBrute
- SubExractor
- SubFinder
- Sublist3r
- PureDns

##### HIDDENT OBJECTS ENUMERATION
- DirBuster
- DirB
- dirsearch.py
- GoBuster
- Ffuf
- Feroxbuster


#### NTP ENUMERATON
- Network Time Protocol (NTP) is used to synchronize clocks of network devices
- UDP 123
- Can maintain time to within 10 milliseconds over the public Internet
- Attackers query NTP for
	- List of hosts connected to NTP server
	- Clients IP addresses, system names, and operating systems
	- Internal IP addresses can be acquired if the NTP server is on the DMZ


>Active Directory clients use Windows Time (not NTP) to synchronize their clocks to the domain
The Active Directory PDC Emulator domain controller is the time source for the domain.
It can synchronize to other sources via NTP

```
// Query a time server
ntpupdate -q pool.ntp.org

// Trace a chain of NTP servers back to the primary source
ntptrac

//moniter operation of the NTP server, request last 600 clients that connected to NTP time server
ntpdc -n -c monlist <IP or Hostname of time server> 
```

##### NTP ENUMERATION TOOLS



### 4.11 Other Enumeration Types

- NTP Time Server Monitor
- NTP Server Scanner
- Nmap
- Wireshark
- AtomSync
- NTPQuery
- PresenTense NTP Auditor
- PresenTense Time Server
- PersenTense Time Client
- NTP Time Server Monitor
- LAN Time Analyser

#### VOIP ENUMERATION

- VoIP uses SIP (Session Initiation Protocol) to manage voice and video calls over IP
	- TCP 5060 - Clear Text
	- TCP 5061 - SIP-TLS (encrypted)
- Data is carried by:
	- Real-time Transport Protocol (RTP) UDP 5004
	- and Real-time Transport Control Protocol (RTCP UDP 5005)
- VoIP enumeration provides sensitive information such as:
	- VoIP gateway (connects SIP system to PSTN)
	- IP-PBX systems (routes calls inside the VoIP network)
	- client software
	- user phone extensions
- This information can be used to launch various VoIP attacks such as:
	- DoS, Session Hijacking, Caller ID spoofing, Eavesdropping, Spamming over Internet Telephony, VoIP phishing, etc.


- Discover target VoIP information through:
	- Google search and Shodan for public information
	- Nmap and Sipvicious to map the internal VoIP network
	- Wireshark to identify SIP users
	- Job sites that list knowledge of a specific VoIP system as a skills requirement
- Search for the following information:
	- The public IP of the server
	- The VoIP network / infrastructure
	- Devices connected to the VoIP network, their open ports, and running services
	- Users information (extension, the device information, and logs)
	- Information about the VoIP server (model, vendor, OS, ports, etc.)

##### GOOGLE DORCS to FIND VOID TARGETS

| Google Dork                                              | Description                                      |
| -------------------------------------------------------- | ------------------------------------------------ |
| inurl:/voice/advanced/ intitle:Linksys SPA configuration | Finds the Linksys VoIP router configuration page |
| inurl:”NetworkConfiguration” cisco                       | Find the Cisco phone details                     |
| inurl:”ccmuser/logon.asp”                                | Find Cisco call manager                          |
| intitle:asterisk.management.portal web-access            | Finds the Asterisk web mgmt portal               |
| inurl:8080 intitle:”login” intext:”UserLogin” “English”  | VoIP login portals                               |
| intitle:” SPA Configuration”                             | Search Linksys phones                            |
#### SiPVICIOUS
- A SIP auditing tool used to scan for and enumerate SIP devices and accounts
- Sends SIP INVITE or OPTION packets looking for responses from live hosts
	- Logs the results to a file
- Attacks include:
	- SIP flood, RTP flood, SIP enumeration, Digest leak, RTP Bleed and RTP inject, fuzzing

```
root@kali # svmp 192.168.1.0/24 -v
```

#### IPSEC ENUMERATION
- IPSEC VPNs are digitally signed and optionally encrypted using DES, 3DES or AES
- You can use nmap or other scanners to identify IPSEC VPN servers
- Internet Key Exchange (IKE) is the handshake protocol used at the start of an IPSEC
- session
- You can also use 'ike-scan' and 'psk-crack' to try to capture and crack an IKE pre-shared key hash

- #### IKE-SCAN
- A command-line tool that uses the IKE protocol to discover, fingerprint and test IPsec VPN servers
- Can do two things:
	- Determine which hosts are running IKE
		- This is done by displaying those hosts which respond to the IKE requests sent by ike-scan.
	- Determine which IKE implementation the hosts are using
		- Done by recording the times of the IKE response packets from the target hosts and comparing the observed retransmission backoff pattern against known patterns.
	- Can identify VPNs from manufacturers including Checkpoint, Cisco, Microsoft, Nortel, and Watchguard


#### PSK-CRACK
- Attempts to crack IKE Aggressive Mode pre-shared keys
	- Keys must have been previously gathered using ike-scan with the --pskcrack option
- Can work in dictionary or brute-force mode


#### DNS IPV6 GRINDING
- You can identify IPv6 servers through DNS grinding
- DNS grinding is a dictionary attack using a list of possible host names
	- Uses AAAA requests
- Grinding tools include:
	- dnsdict6
	- dnsrevenum6
	- These are part of the thc-ipv6 tool suite
```
		sudo apt install thc-ipv6
```


IPV6 ENUMERATION EXAMPLE
```
dnsdict6 -4 -t 16 example.com 
//start 16 thread for 798 words to enumerate website example.com
```

##### BGP
- Border Gateway Protocol (BGP) is the routing protocol used on the Internet
- ISPs use BGP to choose Internet routes
	- BGP has slow convergence
	- An entire Autonomous Systems is treated as a “hop”
- Traffic between Internet-based networks is controlled by using BGP and autonomous system (AS) numbers
- Organizations use BGP
- IANA assigns AS numbers to RIRs
- RIRs allocate numbers to ISPs and large organizations so that they can manage their IP router networks and upstream connections.
- You can use whois and HE BGP Toolkit to enumerate:
	- An organization’s AS numbers and IP addresses (referred to as “prefixes”)
- Knowing IP addresses gives you targets to scan


```
whois -a "nintendo*"
// whois query reveals netblocks and AS numbers for the company Nintendo
```
\

- ### 4.12 Enumeration Countermeasures and Review


 - When possible, use protocols that are encrypted, rather than clear text
 - Disable NetBIOS and SMBv1
- Change the SNMP community string
- Disallow DNS zone transfers to unknown servers
- Maintain separate DNS servers for internal and public records (split DNS)
- Consider disabling VRFY and EXPN commands on your email server
- Use file system and share permissions to restrict access to sensitive content
- Perform your own enumeration to see what types of information an attacker can obtain
	- Remediate when **possible**
- Enumeration is systematic process of querying a target’s servers and services for information
- Enumeration should appear to the server as a normal client making legitimate information  requests
 - You can enumerate information about the OS, its services, users and groups, network information, machines names, configuration settings, installed apps and service banners.
 - Many network protocols can be used for enumeration including:
	- NetBIOS/SMB, FTP/TFTP, NFS
	- SNMP
	- Telnet, SSH, RPC
	- SMTP
	- HTTP, DNS,
	- LDAP, SQL, NTP
	- IPSEC, IPv6, SIP, BGP and others

