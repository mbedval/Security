
Usage: #Enumeration 

[SNMPWalk](https://ezfive.com ) : 
SNMPWalk is a command-line tool that allows attackers to scan numerous SNMP nodes instantly and identify a set of variables that are available for accessing the target network. 

This command allows attacker to view all the OIDs, variables and other associated information. retrieve all the data in transist to the SNMP servr from the SNMP agent, including the server being used, user credentials, and other parameters.
```
snmpwalk -v1 -c public <Target IP Address>
```

Command to enumerate SNMPv2 with a community string of public
```
snmpwalk -v2c -c public <Target IP Address>
```

Command to search for installed software
```
snmapwalk -v2c -c public <Target IP Address> hrSWInstalledName
```

Command to determine the amount of RAM on the host
```
snmpwalk -v2c -c public <TargetIPAddress> hrMemorySize
```

Command to change an OID to a different value
```
snmpwalk -v2c -c public <TargetIpAddress> <OID> <NewValue>
```

Command to change the sysContact OID:
```
snmpwalk -v2c -c public <TargetIPAddress> sysContact <NewValue>
```

