#Fav 

Metasploit is a open source version
- Written mostly in Ruby
- Modules are organized into categories

| Module Category | Description                                     |
| --------------- | ----------------------------------------------- |
| Auxiliary       | Scan Targets                                    |
| Exploits        | Attack (Kick the door in)                       |
| Payloads        | Pwn (toss in the grenade)                       |
| Encoders        | Evade detection, change bad exploit charracters |
| Evasion         | Generate your own evasive payloads              |
| NOPS            | Advanced buffer overflows                       |
| Post            | Escalate privilege , additional task            |
#### BASIC metaspliot use case

- Use an exploit and payload together to attack a target
	- The exploit gets you into the victim
	- the payload performs the actual task you want to accomplish
- Updating Metasploit: Metasploit is installed in kali.
- `sudo apt update && sudo apt upgrade`
- `msfupdate`
- Metasploit search
- `search [<options>`] [<keyword>:<value>]
- prepending a value with '-' will exclude any matching results
- If no options or keywords are provided, cached results are displayed.




Metasploit is open-source project that provides the infrastructure, content, and tool to perform penetration tests and extensive security auditing

it Provide information about security vulnerability and aids in penetration testing and IDS signature development.

The best feature of this tool is modal approach, in which it allow combination of any exploit with any payload.

It enables you to automate the process of discovery and exploitation and provides you with the necessary tools to perform the manual testing phase of a penetration test.

Metasploit Pro supports scan for open ports and services, exploit vulnerabilities, pivot further into network, collect evidence, and create a report of the test results.