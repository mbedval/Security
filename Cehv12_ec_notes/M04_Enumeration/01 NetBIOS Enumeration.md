
Windows uses NetBIOS for file and printer sharing. NetBIOS uses UDP port 137 (name services) and UDP138 (datagram services) and TCP 139 (Session Services)

A NetBIOS name is unique 16 ASCII string used to identify the network devices over TCP/IP; fifteen characters are used for the device name, and the sixteenth character is reserved for the service or name record type.


> [!NOTE]
> note: NetwBIOS name resolution is not supported by Microsoft for IPv6 (Internet protocol version 6)

#### NetBIOS name list
#NetBIOSNameList

| Name     | NetBIOS Code | Type   | Information obtained                                                                       |
| -------- | ------------ | ------ | ------------------------------------------------------------------------------------------ |
| Hostname | 00           | Unique | Hostname                                                                                   |
| Domain   | 00           | Group  | Domain Name                                                                                |
| hostname | 03           | Unique | Messenger service running for the computer                                                 |
| username | 03           | Unique | Messenger service running for the logged-in user                                           |
| hostname | 20           | Unique | Server Service running                                                                     |
| domain   | 1D           | Group  | Master browser name for the subnet                                                         |
| domain   | 1B           | Unique | Domain Master browser name, identifies the primary domain controller (PDC) for the domain. |
#### Attacker use the NetBIOS enumeration to obtain
- The list of computers that belong to a domain
- The list of shares on the individual hosts in the network
- Policies and passwords.

Attackers usually target the netBIOS service because it is easy to exploit and run on windows systems even when not in use.
So when Attacker find port 139 is open, gives a try to find which resources can be accessed or viewed on a remote system. By doing NetBIOS enumeration attacker may (1) attempt to read or write to a remote computer system, depending of the availability of shares. or (2) can launch a DoS attack.

#### Tools
##### NBTSTAT
**nbstat** utility in windows displays NetBIOS over TCP/IP NetBT (Protocol statistics), NetBIOS name tables for both the local and remote computers and the NetBIOS name cache.

**reference URL**: [microsoft docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat)

```
nbtstat -a $IPaddressRemoteMAchine 
//// to obtain the NetBIOS name table of a remote computer

nbtstat -c
//// to obtain the contents of the netBIOS name cache, table of NetBIOS names, and their resolved IP addresses.
```

##### NetBIOS enumerator 
[NetBIOS enumerator](http://nbtenum.sourceforge.net ) helps to enumerate details such as NetBIOS names, Usernames, Domain names, and MAC addresses, for a given range of IP addreses.

##### others 
Tools explore and scan a network within a given range of IP addresses and Lists of computers to identify security loopholes or flaws in networked systems. These tools also enumerate operating system, Users, Groups, Security Identifiers (SIDs), Password policies, services packs and hotfixes, NetBIOS shares, transport, sessions, disks and security event logs, etc.
1. [[Nmap]] 
```
	nmap -sV -v --script nbstat.nse <target IP address>
```
2. [Global Network Inventory](http://www.magnetosoft.com)  
3. [Advanced IP Scanner](https://www.advanced-ip-scanner.com/)
4. [Hyena](https://www.systemtools.com)
5. [Nsauditor Network Security Auditor](https://www.nsauditor.com)
6. 
