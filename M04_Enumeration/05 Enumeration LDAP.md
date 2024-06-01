
- LDAP is an internet protocol for accessing distributed directory services.
- LDAP is one of many protocol that access the directory listing. 
- LDAP access directory listing within Active Directory or from other directory services. 
- LDAP is a hierarchical or logical form of a directory similar to companies organizational chart. 
- It Uses DNS for quick lookups and the fast resolutions of queries. A client starts an LDAP session by connecting to Directory System Agent (DSA), typically on TCP port 389, and sends an operation request to the DSA. The Basic Encoding Rules (BER) format is used to transmit information between the client and server.
- 


Attacker can anonymously query the LDAP service for sensitive information such as username, addresses, departmental details, and server names, which an attacker can use to launch attacks.


#### Manual LDAP Enumeration
- Using #nmap check whether LDAP server is listerning on port 389 for LDAP and port 636 for Secure LDAP
- If the target server is listening on the specified ports, initiate the enumeration process by installing LDAP using the following command, 
```
$pip3 install ldap3
$python3

>> import ldap3
>> server = ldap.server ('TargetIpAddress', use_ssl, get_info = ldap3.All, port=389)
>> connection = ldap3.connection(server)
>> connection.bind()
```

- on executging bind() if result is True, We can query like 
```
>>> server.info
```
	Above command will return the DSA information
```
>>> connection.search (search_base='DC=DOMAIN, DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
```
- on executing above command return is TRUE than run command to dump the entire LDAP
```
>> connection.entries
```
```
>>> connection.search (search_base='DC=DOMAIN, DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='userPassword')
```


#### Automated LDAP Enumeration
attacker use ldap-brute NSE script to brute-force LDAP authentication. By Default, it uses the built-in username and password lists. The 'userdb' and 'passdb' script arguments can be employed to use custom lists.

```
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users, dc=CEH, dc=com "' <TargetIpAddress>
```

#### LDAP Enumerator Tools

1. Softerra Enumeration Tools: is LDAP administrator tool that works with LDAP servers such as Active Directory (AD) Novell Directory Services, and Netscape/iPlanet. It browses and manages LDAP directories. Attacker collects details such as the username, email address and department
2.  [[ldapsearch]]
3. [AD Explorer ](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
4. [LDAP Admin Tools](https://www.ldapsoft.com/)
5. [LDAP Account Manager](https://www.ldap-account-manager.org))
6. [Ldapsearch](https://securityxploded.com/)
