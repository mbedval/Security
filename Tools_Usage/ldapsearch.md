#ldapenumeration #Enumeration 

ldapsearch is a shell-accessible interface for the ldap_search_ext(3) library call. 
ldapsearch opens a connection to an ldap server, binds it, and performs search using the specified parameters. The filter should conform to the string representation of the search filters, as defined in RFC 4515. If not provided, the default filter, (objectClass=* ), is used


The following command can be used to perform an LDAP search using simple authentication
```
ldapsearch -h <TargetIpAddress> -x
```
if the above command is successfully executed, following command can be executed to obtain additional details related to the naming contexts:
```
ldapsearch -h <TargetIpAddress> -x -s base namingcontexts
```
output domain component can be identified as (example : dc=htb, DC=local) the following command can be used to obtain more information about the primary domain:
```
ldapsearch -h <TagetIpAddress> -x -b "DC=htb, DC=local"
```
Now another command can be executed to retrieve information about specific object or all the objects in this directory.
```
\\specific for employee
ldapsearch -h <TargetIpSearch> -x -b "DC=htb, DC=local" '(objectClass=Employee)'

\\ for all objects
ldapsearch -h <TargetIpSearch> -x -b "DC=htb, DC=local" '(objectClass=*)'
```

The following command retrieves a list of users belonging to a particular object class:
```
ldapsearch -h <TargetIpAddress> -x -b "DC=htb,DC=local" '(objectClass=Employee)' sAMAccountName sAMAccountType
```

