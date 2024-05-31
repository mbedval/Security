Enumerating user accounts using the PsTools suite helps to control and manage remote systems from the command line.

[PSTools](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools) 
1. PsExec is a lightweight Telnet replacement that can execute processes on other systems
2. PsFile is a command-line utility that shows a list of files on a system that opened remotely. and it can close opened files either by name or by a file identifier. The default behavior of PsFile is to list the files on the local system opened by remote systems. 
```
psfile [\\RemoteComputer -u Username [-p Password]] [[Id | path] [-c]]
```
3. PsGetSid: translates SIDs to their display name and vice versa. It works on built-accouns, domain accounts and local accounts. It also displays the SIDs of user accounts and translates an SID into the name that represents it. IT works across the network to query SIDs remotely. 
```
psfile [\\RemoteComputer [-u Username [-p Password]]] [[Id | path] [-c]]

```
4. PsGetSid: translates SIDs to their display name and vice versa. It works on built-in accounts, domain accounts and local accounts. It also displays the SIDs of user accounts and translates an SID into the name that represents it.
```
psgetsid [\\computer[,computer[,...] | @file] [-u username [-p password]]] [account|SID]
```
5. PsKill : to kill processes on remote systems 
6. PsInfo: To gather key information about legacy windows systems
7. PsList: to Displays central processing unit (CPU) and memory information or thread statistics. pstat and pmon show different types of data only for the processes on the system on which the tools are run.
8. PsLoggedOn" is an applet that display both the locally logged-in users and users logged in via resources from either the local computer or remote one.
```
	psloggedon [-] [-l] [-x] [\\computername | username]
```
9. PsLogList The elogdump utility dumps the contents of an event log on a local or remote computer. Note: it is clone of elogdump except that psLogList can log in to remote systems in situations where the user's security credentials would not permit access to the event log and PSLogList retrieves messages string from the computer on which the event log is stored.
10. PsPassword can change an account password on local or remote systems.. Batch can be created to change multiple administrator passwords
11. PsShutDown to shutdown or reboot local or remote computer.



