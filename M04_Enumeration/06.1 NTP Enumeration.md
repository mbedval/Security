
#### Network Time Protocol
- Network Time Protocol (NTP) is designed to synchronize the clock of networked computers
- It uses UDP port 123 as its primary means of communication
- NTP can maintain time to within 10 Milliseconds (1/100 second) over the public internet
- It can achieve accuracies of 200 microseconds or better in local area network under ideal conditions.

Attacker query NTP server to gather valuable information. such as 
- List of connected hosts
- Clients IP Address in a network their system names, and OSs.
- Internal IPs can be obtained if the NTP server is in the demilitarized zone (DMZ)

##### Tools

ntpupdate collects the number of time stamps from several time sources. I
```
ntpupdate [-46bBdqsuv] [-a key] [-e authdelay] [-k keyfile] [-o version] [-p samples] [-t timeout] [-U user_name] serverr [...]
```

| option       | description                                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| -4           | Force DNS resollution of given host names to the IPv4 namespace                                               |
| -6           | Force DNS resolution of given host names to the IPv6 namespace                                                |
| -a key       | Enable the authentication function/specify the key identifier to be used for authentication                   |
| -B           | Force the time to always be slewed                                                                            |
| -b           | Force the time to be stepped                                                                                  |
| -d           | Enable debugging mode                                                                                         |
| -e authdelay | Specify the processing delay to perform an authentication function                                            |
| -k keyfile   | Specify the path of the authentication key file as the string "keyfile" ; the default is /etc/ntp/keys        |
| -o version   | Specify the NTP version for outgoing packets as an integer version, which cane be 1 or 2, the default is 4    |
| -p samples   | Specify the number of samples to be acquired from each server, with values ranging from 1-8; the default is 4 |
| -q           | Query only; do not set the clock                                                                              |
| -s           | Divert logging output from the standard output (default) to the system syslog facility                        |
| -t timeout   | Specify the maximum wait time for a server response; the default is 1 s                                       |
| -u           | use an unpriviledged port for outgoing packets                                                                |
| -v           | Be verbose; logs ntpupdate's version identification string.                                                   |


ntptrace traces a chain of NTP servers back to the primary source.
```
ntptrace [-n] [-m maxhosts] [servername/IP_address]
```

| Option      | Description                                                                              |
| ----------- | ---------------------------------------------------------------------------------------- |
| -n          | Do not print hostname and show only IP Addresses, may be useful if a name server is down |
| -m maxhosts | set the maximum number of levels up the chain to be followed                             |


ntpdc monitors operations of the NTP daemon,
```
ntpdc [-ilnps] [-c command] [host] [...]
```
![[Pasted image 20240531185508.png]]

| Options | Description                                                                                                                                                       |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -d      | Set the debugging mode to on                                                                                                                                      |
| -c      | Following argument is interpreted as an interactive format command; multiple -c options may be given                                                              |
| -i      | Force ntpdc to operate in the interactive mode                                                                                                                    |
| -l      | obtain a list of peers known to the servers; this switch is equivalent to -c listpeers                                                                            |
| -n      | Output all host addresses in the dotted-quad numeric format, rather than host names                                                                               |
| -p      | Print a list of the peers as well as a summary of their states; this is equivalent to -c peers                                                                    |
| -s      | Print a list of the peers as well as a summary of their states, but in as slightly different format from that for the -p switch; this is equivalent to -c dmpeers |



ntpq monitors NTP daemon (ntpd) operations and determines performance
```
ntpq [-inp] [-c command] [host] [...]
```

![[Pasted image 20240531185710.png]]


#### NTP enumeration Tools

PRTG Network monitor includes SNTP Sensor monitor, as simple network time protocol SNTP server that shows the response of the server and time difference in comparison to the local system time.

source: https://www.paessler.com
PRTG monitor all systems, devices, traffic, and applications of IT infrastructure by using various technology such as SNMP, WMI and SSH. Attackers use PRTG network monitor to retrieve SNTP server details such as the response time from the server, active sensors with the server, and synchronization time.

