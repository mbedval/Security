 #application-layer 

Simple Network Management Protocol (SNMP) is an application-;ayer protocol that runs on UDP and maintains and manages routers, hub, and switches on a an IP network. SNMP allows Network administrator to manage network devices from a remote location. 

SNMP has many security vulnerabilities, such as a lack of auditing. this vulnerability is exploited by attackers for enumeration

- SNMP enumeration is process of enumerating user accounts and devices on a target system using SNMP
- SNMP consists of a manager and an agent, agents are embedded on every network device and the manager is installed on a separate computer. Almost all the network infrastructure devices contain SNMP agent for managing it. 
- SNMP holds two passwords to access and configure the SNMP agent from management station.
	- Reading community string: it is public by default , it allows for the viewing of the device/system configuration
	- Read/Write community string: it is private by default, it allows remote editing of configuration.
- Attackers use these default community strings (password )to extract information about a device
- Attackers by enumerating SNMP collects information about network resources such as hosts, routers, devices and shares and network information such as ARP tables, routing table, devices-specific information and traffic statistics
- 

Components associated with SNMP
- GetRequest: Used by the SNMP manager to request information from an SNMP agent
- GetNextRequest: Used by the SNMP manager continuously to retrieve all the data stored in an array or table.
- GetResponse:Used by SNMP agent to satisfy a request made by the SNMP manager 
- SetRequest: Used by the SNMP Manager to modify the value of a parameter withing an SNMP agent's management information base (MIB)
- Trap: Used by an SNMP agent to inform the  pre-configured SNMP manager of a certain event.

Communication:
	1. SNMP Manager (==Host-X==) uses GetRequest command to query number of active sessions to the SNMP agent (==Host-Y==) . SNMP manager uses Service Libraries such as  MS SNMP Management API Library 'Mgmtapi.dll' .
	2. Agent after receiving message first verify the community string 'Compinfo' is present on it MIB Database, checks the request against its  list of access permissions for that community and verify the source IP Address. 
	3. If community string or access permission is passed the SNMP is set to send an authentication trap, its sends an authentication failure trap to the specified trap destination, ==Host Z==.
	4. The Master agent component calls the appropriate extension agent to retrieve the request session information from the MIB
	5. Using Session information retrieved from the extension agent, the SNMP service forms a return SNMP message that contains the number off active sessions and the destination IP Address (10.10.2.1) of the SNMP manager
	6. Host Y sends the response to ==Host X==
	

Management Information Base)
MIB is the virtual database containing a formal description of all the network objects that SNMP manages. It is a collection of Hierarchically organized information. It provides a standard representation of the SNMP agents information and Storage .. MIB Elements are recognized using object Identifiers (OIDs) . OID is the numeric name given to an object and begins with the root of the MIB tree. The OID can uniquely identify the object in the MIB hierarchy.

MIB-Managed objects includes scalar objects. which defines single object instance and tabular objects, which define a group of related object instances. OIDs includes the object's type (Such as counter, string or address), access level (r or rw), Size restrictions and range information. The SNMP manager converts the OIDs into a human-readable display using the MIB as a codebook.

from http://IpAddress/Lseries.mib or http://library_name/Lseries.mib user can find the list of MIBs installed with SNMP services in the windows resource kit. The major MIBs are as follows
- DHCP.MIB : Monitors network traffic between DHCP servers and remote hosts.
- HOSTMIB.MIB : Monitors and manages host resources
- LNMIB2.MIB : Contains objects types for workstation and server services.
- MIB_II.MIB : Manages TCP/IP-based internet using as simple architecture and system 
- WINS.MIB : for the windows internet name Service (WINS)


Tools
1. [OpUtils](https://www.manageengine.com):
2. [Network Performance Monitor](https://www.manageengine.com): 
3. [PRTG Network Monitor](https://www.paessler.com)
4. [[SNMPWalk]]
5. [[Nmap#Enumerating SNMP using NMAP|NMAP]]
7. [SNMP-check]( https://www.nothink.org) : 
1. SoftPerfect Network Scanner: Software Network scanner discovers shared folders and retrieves practically any information about network devices via WMI, SNMP, HTTP, SSH and PowerShell.