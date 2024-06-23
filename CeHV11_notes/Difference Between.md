
#### Footprinting vs Enumeration
- Footprinting focuses on collecting publicly available information about the target system or network
- Enumeration focuses on extracting technical information from systems, including usernames , machine names, network resource , shares and services

#### Scanning and enumerations

|                      | Scanning                                                                                                                            | Enumeration                                                                                                                                 |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Purpose              | The purpose of network is to identify live hosts, open ports and running services on a target network                               | The purpose is to extract detailed information about the identified systems, such as user accounts, network shares and other sensitive data |
| Technique            | Common scannning technique includes ping , sweeps, port scans, and vulnerability scan using Nmap, Unicornscan, Angry IP Scanner     | Technique include querying services like SNMP, NetBIOS, LDAP and DNS to gather more detailed information about the target systems           |
| Information gathered | High-Level overview of the target network including hosts are active. Which ports are open and which services are running           | Deep dives into identified systems to extract more granular information, such as user accounts, shared resources and application details.   |
| Order of Execution   | Scanning is typically the first step in the Reconnaisance phase, as it helps indentify potential targets for further investigations | is performed after the scanning phase, using the information gathered to delve deeper into the target systems.                              |
|                      |                                                                                                                                     |                                                                                                                                             |

#### ABCD