SMTP provides 3 built-in-commands
1.  VRFY validates users
2. EXPN Shows the actual delivery addresses of aliases and mailing lists
3. RCPT TO - Defines the recipients of a message

SMTP servers respond differently to VRFY, EXPN and RCPT TO command for valid and invalid users, based on which we determine valid users on the SMTP server. Attackers can directly interact with SMTP via the Telnet prompt and collect a list of valid users on the SMTP server.

SMTP uses mail exchange (MX) servers to direct mail vaa DNS. It runs on TCP port 25, 2525, or 587.

SMTP enumeration can be done using command-line utilities like Telnet and netcast or by using Metasploit, NMAP, NetScanTools Pro, and SMTP-user-enum to collect a list of valid users, delivery addresses, messages recipients, etc

Attacker perform enumeration on the target SMTP server using various SMTP commands available with NSE scripts.

##### Example with NMAP

1. The following command will list all the SMTP commands available in the NMAP directory:
	`nmap -p 25, 365, 587 --script=smtp-enum-user <TargeIPAddress> `
2. Run the following command to identify SMTP open relays
	``nmap -p 25 -script=smtp-open-relay <TargetIPAddress>``
3. Run the following commands to enumerate all the email users on the SMTP servers:
	`nmap -p 25 -script=SMTP-enum-users <TargetIPAddress>`

##### Example with Metasploit

```
msconsole
msf > use auxiliary/scanner/smtp/smtp_enum`
msf auxiliary(smtp_enum) > show options  //alternatively we can use show evasion command
```
`
note: Metasploit framework uses default wordlists for various application at location  "/usr/share/metasploit-framework/data/worlists"

```
msf auxiliary(smtp_enum) > set RHOST
msf auxiliary(smtp_enum) > set USER_FILE 

```



The Metasploit framework contains an SMTP enumeration module that allows attackers to connect to the target SMTP server and enumerate usernames using the predefined wordlists.
`msf6 auxiliary(smtp_enum) > run

Tools
**NetScan Tool Pro** : source: http://www.netscantools.com
Netscantool is email Generator tool tests the process of sending an email message through an SMTP server. #windows #paid Attackers use this to enumeration and extract all the mail header parameters, including confirm/urgent flags. Attackers can also record the email session in a log file and then view the communications between netscantool and smtp server. 

SMTP-user-enum: source: // http://pentestmonkey.net
smtp-user-enum is a tool for enumerating OS-Level user account on solaris via the SMTP service (sendmail). Enumeration is performed by inspecting the responses to VRFY, EXPN, and RCPT To commands.  pass list of users to atleast one target running an SMTP service.
```
smtp-user-enum.pl [options] [-u username] | -U file-of-usernames) (-t host | -T file-of-targets)
```


