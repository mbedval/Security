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
#SolarWindsFreeWMIMonitor