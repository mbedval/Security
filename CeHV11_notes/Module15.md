### 15.1 SQL INJECTION OVERVIEW

#### WHAT IS SQL
- SQL is structured query language
- Used to interact with a relationship database
	- Query (read) data from a database
	- Add new data
	- Update existing data
	- Delete data
	- Create new database and tables
#### What is SQL Injection?
	Aks SQLi
- The most common vulnerabilities in websites
- An attack in which a normal SQL query has been modified
	- if the web app does not validate the input, it will send the modified SQL command to be executed by a back-end database
- Nearly all SQL servers are vulnerable to SQLi. SQL server has no built-in mechanism to validate input.
- SQLi can happen in any programming language
	- SQLi is usually successful when an Internet-facing web app does not validate and clean input it receives from the users.
	- Instead it automatically passes malicious request to the SQL server
	- 


#### SQL INJECTION THREATS
- SQLi allows an attacker to retrieve data from the backend database directly
- This can cause:
	- unauthorized data exfilteration / loss of data confidentiality 
	- unauthorized data modification/ loss of data integrity
	- Possible unauthorized remote execution of system commands
- The attacker could also alter the data and put it back. Nobody would notice the change.
- SQLi that exfiltrates data will usually have a larger HTML response size than normal 
	- Example:
		- An attacker extracts the full credit card database
		- That single response might be 20 to 50 MB
		- A normal response might only be 200 KB

### 15.2 BASIC SQL INJECTION

#### SQL Special Characters
These special characters are common targets for abuse in SQL Injection

| Input character | Meaning in Transact-SQL                                                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ;               | Query Delimiter<br>Place between two queries to run both in single command                                                                                         |
| ''              | Character data string delimiter<br>Cause a syntax error                                                                                                            |
| --              | Single Line comment delimiter<br>Text following -- until the end of that line is not evaluated by the server<br>use to ignore a fields                             |
| --              | Single-line comment delimiter<br>Text following -- until the end of that line is not evaluated by the server<br>use to ignore a field you don't know the value for |
| `/*  ...  */`   | Comment delimiters<br> Text between is not evaluated by the server                                                                                                 |
| XP_             | In MSQL, used at the start of the name of extended stored procedures such as XP_cmdshell                                                                           |
|                 |                                                                                                                                                                    |
#### SIMPLEST SQL INJECTION EXAMPLE
- Add a single quote (' ) to a normal query
- This makes the query syntax incorrect
- A vulnerable database will throw an error
- The attacker can then use this information to continue with the attack

#### Always TRUE SQL query
A command SQLi technique is to inject a query that always evaluate to true `' or 1=1`
This is used to 
	bypass authentication
	identify injectable parameters
	extract data
	`select accoun, balance from account where account_own_id = 0 or 1=1`

#### SQL IN WEB PAGES
- SQL injection usually occurs when you ask a user for input on a web form.
- A web app takes the input and dynamically creates a SQL query.
	- The SQL query already exists.
	- It has placeholders for the user's input
	- The web app inserts the input to complete the query
	- The query is then sent to the database for execution.

#### 15.3 FINDING VULNERABLE WEBSITES

- Search for websites that are rely on php scripts to generates dynamics SQL queries
- PHP-based website are usually you best targets because:
	- They can be set by just about anyone (ie. wordpress)
	- They often contain lots of valuable information about customers within the database you are attempting to hack.
- Use Google Dorks to identify possible targets.
	- inurl:index.php?id=
	- inurl:pages.php?id=
	- inrul:view.php?id=

> comprehensive list of google dorks [Pastebin](https://pastebin.com/C2awJsLB) and [Brokenkeysite](https://brokenkeyssite.wordpress.com)


#### TESTING POSSIBLE TARGETS
- Take the results of your Google Dork
- Paste it into the browser.
- Add a single quote to the end 
- Press enter
- If you receive an error. the site is likely vulnerable to SQLi

### 15.4 ERROR BASED SQL INJECTION
#### ERROR-BASED SQL INJECTION
- Relies on error messages thrown by the database server to 
	- Indicates the website is vulnerable to SQLi
	- Obtain information about the structure of the database
- The attacker uses information contained in the error to escalate the attack
- Sometimes the names or structure of databases elements are included in the error.
- Example: `http://www.example.com/listproduct.php?cat=1` when single quote is added , if there is error. strongly suggesting the site is vulnerable to SQLi

### 15.5 UNION SQL INJECTION
- The union keyword lets you execute one or more additional SELECT queries and append the results to the original query
- For a UNION query to work, two key requirement must be met:
	- The individual queries must return the same number of columns
	- The data types in each column must be compatible between the individual queries
	- `Select a, b from table 1 UNION SELECT c, d from Table2`

#### UNION SQL INJECTION
- Leverage the UNION SQL Operator
	- The attacker uses a UNION clause in the payload
	- combines the results of two or more SELECT statements into a single result
- You need to ensure that your attack meets SQL UNION requirements
	- The individual queries must return the same number of columns
	- The data types in each column must be compatible between the individual 
- Malicious Union SQL Injection
	- `http://testphp/vulweb.com/artists/php?artis=1 UNION select 1, version(), current_user()`
	- Result : The web application displays the system version and the name of the current user example: `5.1.73=0ubuntu0.10.04.1 moo@localhost`

#### 15.6 BLIND SQL INJECTION
- Some vulnerable web apps do not return expected results and are  UNION attacks aren't effective
- If you do not see the expected results, you can still use Blind SQL injection.
- Blind SQL tries to trigger conditional responses
	- The attacker cannot directly see the result of the attack
	- But you get some kind of response depending on if the query is TRUE or FALSE
	- Take a long time because data must be enumerated character by character

#### BLIND SQL INJECTION TYPES
- Boolean-based
	- Attacker sends a SQL query to the database
	- Forces the application to return a different result depending on whether the query returns a TRUE or FALSE result
- Time-based
	- Attacker sends a SQL query to the database
	- Force the database to wait for a specified amount of time.
	- Response time indicate if the result is TRUE or FALSE
> `Blind SQL injection` vulnerability is harder to detect than XSS or CSRF


##### USING BOOLEAN-BASED BLIND SQL
- The app uses the tracking ID to determine if this is known user
	- `Select TrackingID from TrackedUSers where TrackingID = 'usdfa2343dadf9da`
- if the tracking id is recognized the users sees a message "welcome back"
- You will try a series of TRUE/FALSE injection to determine a password
- Determine if the first character of the password is greater than the letter m. 
	- `realquery blah' AND SUBSCRING ((Select Password From Users where username = 'Administrator'), 1, 1) > 'm`
- Continue using the same query but with different letters (or different operators) until you find the first letter
- SO that You now know that the first letter of the administrator password

#### BLIND SQL INJECTION TIME-BASED EXAMPLE
- Sometimes a vulnerable web app will return the same response for either Boolean based payload
- In that case you can send a payload that includes a time delay command.
- If the attack is TRUE then the response  will come after the delay.
- The actual command syntax will depend on the type of database
- `realquery blah '; IF(1=2 WAITFOR DELAY '0:0:10' --`
- `realquery blah'; IF (Select count (username) from users where username = 'Administrator' AND SUBSTRING (PASSWORD, 1, 1) > 'm') =1 WAITFOR DELAY '0:0:10' -- `

### 15.7 SQL INJECTION TOOLS
#Metasploit : Has many modules to attack mssql, mysql, postgrestsql, Oracle SQL and other
#BSSLHacker : Automated Blind SQL Injection
#sqlmap  : Poplular open source tool that works against a wide of database servers #linux
#SQLninja : Exploits web apps that uses a SQL back end. 
#Safe3SqlInjection Easy to use, supports HTTP, HTTPS and wide range of SQL servers
#SQLSus A MySQL injection and takeover tools
#Mole :You just need to discover a vulnerable URL and then pass it in the tool

#### Mobile Device SQL INJECTION TOOLs
#DroidSQLi : Automated SQLi
#sqlmapchik : Android port of the popular sqlmap, Automates discovering and exploiting SQL vulnerabilities

### 15.8 EVADING DETECTION
- All of these examples translates to "SELECT"
	- URL ASCII Encoding
	- URL Double encoding (Replace % with %25) 
	- Escaped unicode (hex, code point , U+)
	- hex : `\x73\x63\x6c\x65\x74`
	- Code point:  `\u0053\u0045\u004c\u0045\u0043\u0054`
	- U+ : u+0053u+0045u+004cu+0045u+0043u+0054
- HTML Encoding : &#83;&#69;&#76;&#69;&#67;&#84;
- Hex Encoding : 0x53484c484354
- SQL Char() function: Pass ASCII inter value into the function for conversion to the equivalent character. "`CHAR(83)+CHAR(69)+CHAR(76)CHAR(69)+CHAR(67)+CHAR(84)`"

#### CONCATANATION EVASION
Uses the SQL engine's native ability to build a single string from multiple pieces
	The attacker breaks the forbidden keyword into pieces
	The SQL engine reconstructs the pieces into the original statement
Syntax varies depending on the database
Generally uses either + or ||
`EXCE ('SEL' + 'ECT US' + 'ER')` 
`EXEC ('SEC' || 'ECT US' || 'ER')`

#### VARIABLE EVASION
- Many engines allow the declaration of variables
	- These can be used to evade WAF detection as well as code-based input validation
	- In this example nvarchar = unicode
	- `; declare @myvar nvarchar(80); set @myvar =N'UNI' + N' ON SEL' + N' ECT U' + N' SER'); EXEC(@myvar)`



### 15.9 ANALYZING SQL INJECTION
- `String query = "Select * FROM customers Where custID'" + request.getParameter("id") + "'";` This code is vulnerable to SQL injection.
- This code does not conduct any input validation
- It needs to be modified to use parameterized queries
- `'test' +oR+7>1%20` is same as saying `test' or 7>1`. This is variation of `blah' or 1=1`


### 15.10 SQL INJECTION COUNTER MEASURES
#### For Developers
- Learn safe coding
- Develop the web app to always validate input
- Use prepared statement with parameterized queries in your web app 
- Whitelist input validation
- Escape all user-supplied input to filter out wildcards and special characters.
- Specially the acceptable characters in form input
- Limit the acceptable number of characters in form input
- Create stored procedures in the database to enforce correct input types and disallow ad-hoc queries
#### For Database Administrators (DBA)
- Disable operating system-level commands such as `xp_cmdshell`.
- Suppress error messages
- Use only customized error messages
- Ensure all database traffic is monitored with IDS / WAF
- Enforce least privilege
- Ensure the database service account has minimal rights.

#### SQL INJECTION VULNERABILITY CHECKERS
#netsparker : Web vulnerability scanner with SQLi module and cheat sheet
#SQLmap: Automated SQLi
#jSQLInjection ; Java based remote tester and SQLi deterrent tool
#Haviji :  Web page vulnerability tester with automated SQLi
#Burp MITM web proxy for watching client- server interactions
#BBQSQL Python based injection exploitation tool. Good for Identifying sophisticated SQLi
#Blisqy: Tests using Time-based blind SQLi

#### SAFE CODING EXAMPLE
- Stored Procedures:
	- A stored procedure is a query that you pre-define in the SQL server itself. It limits what is sent to the database for execution. An attacker cannot make up an ad-hoc to be executed.
	- The application calls the stored procedure and passes variables to it.
	- Store procedures are independent of any web app coding.
```
//Create the procedure
CREATE PROCEDURE dbo.myproc #id nvarchar(8)
AS
	Select name from users WHERE id = @id;
GO

//Call the procedure
EXEC database.dbo.myproc 1;

//This SQL Injection will not work
Exec database.dbo.myproc 0; Delete * FROM users 

output : Too many characters.

```
- Parameterized queries
	- Aka prepared statement
	- part of the web app
	- Created using the web app programming language (PHP, Java, Python, C#, etc)
	- Used to pre-compiled a statement before sending it to the database
	- All you need to supply are the "parameters" (variables). 
		- Typically supplied by the user in a form on a webpage
		- Now the query is complete
		- Can be sent to the database to be executed.
		- 
- PHP Examples
	- Using traditional SQL question mark placeholder
		- `$sql 'SELECT name, cust_type from customers where userid =?';`
		- 
	- Using PHP named placeholder
		- `$sql = 'SELECT name, email , cust_type from customers where userID = :user';`
- Python Example
	- `cusor.execute("SELECT * FROM users where username = %s", params)`
- Java Example
	- `string customer = reques.getParameter("customerName"); String query = "SELECT account_balance FROM user-data WHERE user_name =? ";`
- Whitelist examples
	- //Java sample Validation code to whitelist 
	- `String tableName;`
	- `Switch(PARAM):`
	- `case "Value1" : tablename = "Customers`
	- `case "Value2: tableName = "Products`
- SQL Wildcards Example
	- `SELECT * FROM products WHERE name LIKE '%cal%'`
	- SQL Like means you only know part of the value
	- It matches California , Calligraphy, Total Recall
	- Attacker can use wildcard in SQLi `SELECT * from customers where name='admin' and Password ='%'`
- Escaping Special Characters
	- You need to escape any maliciously inputted wildcards
	- You want the special characters (such as a wildcard) to lose their special meaning
	- Escaped wildcards are no longer treated as a special character
		- They lose their ability to represent any result
		- They are treated as literals.
		- Only results that actually contain the characters % or _ will be returned
	- The default escape character is backslash (\). Some database allow you to choose (declare) what the escape character will be.
	- Example
		- Normal Query: `SELECT * from employees where ssn like '444333222`
		- attacker query: `Select * from employees Where seen like * '\'\;\%`
##

###15.11 SQL INJECTION REVIEW
- SQL injection is most common vulnerability in websites
- SQL injection uses non-validated input to send SQL commands through a web app.
- Common SQLi methods include error-based. UNION and blind SQL injection
- A methodological approach must be taken to detect SQL injection vulnerabilities
- User parameterized queries and stored procedures to disallow users from entering ad-hoc queries.

