### MODULE 04_Enumeration

#### LAB01_Task 01 :  Netbios Enumeration
Perform #NetBios Enumeration Using Windows Command-Line Utilizes

objective : attack 2019 Machine to target window 11 machine
Open command prompt (administrator)
```
ntstat -a 10.10.1.11 
```
output :// netbios remote machine name Table is displayed
```
netstat -c
```
// netbios remote cache name table

#### LAB02_Task03: Perform SNMP Enumeration using snmpwalk
Connect to parrot
connect to terminal and do SU
```
snmpwalk -v1 -c public 10.10.1.22
// list object identifier and other variable

snmpwalk -v2c -c public 10.10.1.22
// perform v2 enumeration, data transisted from agent to smtp server

```

#### LAB03_Task 01: Perform LDAP Enumeration using System internal tool #ActiveDirectoryExplorer

Windows 2019 Machine, 
- Open ==`Active Directory Explorer`== from CEH-Tool shared drive on machine
- Connect to : 10.10.1.22 
- Click OK
Displays Active directory structure
- Click CN=Users
- Select user in list and 
- Right click and Modify Attribute: 
- and Select the Value of attribute (example : jason to mukesh)


#### LAB04_TASK 01 : NFS Enumeration using #RPCScan and #SuperEnume
Setup -Prerequsite
Window 2019 Machine
- Open Server manager
- Add roles and features
- In Server roles : 
	- Select `Server for NFS`
- Next , Next and Install
Test Workstation: Parrot machine
Open Terminal
```
sudo su
cd /home attacker
nmap -p 2049 10.10.1.19
// confirm that nfs is running on server 10.10.1.19


locate superEnum
cd /home/attacker/SuperEnum
echo "10.10.1.19" >> Target.txt
// 

./supernum
`Enter the file name with IP`

cd /home/attacker/RPCScan
python3 rpc-scan.py 10.10.1.19 --rpc
// 

```


#### LAB 05_TASK 01 : Perform DNs Enumeration using Zone Transfer with #dig on linux and #nslookup on windows
Workstation : Parrot
Open Terminal
cd /home/attacker
```
cd /home/attacker
dig ns www.certifiedhacker.com


dig @ns1.bluehost.com www.certifiedhacker.com axfr
// if it is configured correction to not allow transfer , it will fail. else attack can pass



```

Workstation : Windows 11
Open Terminal
```
nslookup 
> set querytype=SOA
> ls -dns1.bluehost.com
```


#### LAB  06_Task 01: Perform SMTP Enumeration using #NMAP
Workstation : Parrot
Open Terminal
```
cd /home/attacker
nmap -p 25 --script=smtp-enum-users 10.10.1.19
// list user available with SMTP 

nmap -p 25 --script=smtp-open-relay 10.10.1.19
// display list of open relay , if no output means no relay available

nmap -p 25 --script=smtp-command 10.10.1.19
// display port/status and available command with the smtp target

```

#### LAB 08 _ TASK 01 Enumerate Information using Global network Inventory
Workstation : Windows 11
Utility : Global Network Inventory

- New Audit Wizard
- Select `Single Address scan`
- Enter `10.10.1.22`
- Next
- Connect as : Domain \Username : Administator , password : `Pa$$w0rd`
- Next
- Finish

It will start SCAN and status displayed in `Scan Progress`
Select computer from scan result tree and see summary  and other inventory

### MODULE 05 Vulnerability
#### LAB 01 TASK 01 : Perform vulnerability Research In Common Weakness Enumeration (CWE)
- Login windows 11
- cwe.mitre.org
- Search tab: Search "SMB"
- From search results Select " CWE 552 - Files or Directories Accessible to External Parties"
- and also open CWE List :
- View CWE List : Weakness in the 2022 CWE ....
- with similar steps search vulnerabilities and do needful research



#### LAB 03 TASK 01: Perform vulnerability analysis using OpenVAS
Workstation: Parrot OS
- Open `Pentesting` --> `Vulnerability Analysis` --> `Openvas Greenbone`
- Tool will initializae and portal will be served at http://127.0.0.1:9392
- Login with Admin/password
- Add `Target Machines` and scan with and without the firewall state
- Scan the machines , if the reports are similar means that the systems are vulnerable 

#### LAB 04
















> Note: Use CeHv12 Resource for 