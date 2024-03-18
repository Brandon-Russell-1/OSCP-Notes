
## How to Install SQL Server & Client

See [https://therootcompany.com/blog/mssql-server-on-ubuntu/](https://therootcompany.com/blog/mssql-server-on-ubuntu/) and [https://docs.microsoft.com/en-us/sql/linux/quickstart-install-connect-ubuntu?view=sql-server-ver15](https://docs.microsoft.com/en-us/sql/linux/quickstart-install-connect-ubuntu?view=sql-server-ver15).

`sqlcmd` (covered above) is the client.

In short:

```bash
# add gnupg2, just in case
sudo apt install -y gnupg2

# add Microsoft keys
curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list | sudo tee /etc/apt/sources.list.d/msprod.list

# install sqlcmd
sudo apt-get update -y
sudo apt-get install -y mssql-tools unixodbc-dev

# add sqlcmd to PATH
curl -sS https://webinstall.dev/pathman | bash
export PATH="$HOME/.local/bin:$PATH"

pathman add /opt/mssql-tools/bin
export PATH="/opt/mssql-tools/bin:$PATH"
```

For Windows see [https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15).

Alternatively, check out [https://github.com/dbcli/mssql-cli](https://github.com/dbcli/mssql-cli).

## How to Open the SQL Prompt

As a one-off:

```bash
sqlcmd -S localhost -U SA
```

Or, using ENVs:

```bash
source .env
sqlcmd -S "${MSSQL_HOST},${MSSQL_PORT}" -U "${MSSQL_USER}" -P "${MSSQL_PASS}"
```

What the `.env` might look like:

`.env`:

```bash
MSSQL_HOST=localhost
MSSQL_PORT=1433
MSSQL_USERNAME=SA
MSSQL_PASSWORD=Password!2#
MSSQL_CATALOG="TestDB"
MSSQL_INSTANCE=""
```

## How to Run a Single Statement

It’s not sufficient to end a line with a `;`, you have to use `GO` (without a semicolon).

```sql
SELECT 'Hello, World!';
GO
```

## How to Run Multi-Line Statements

The `sqlcmd` cli can be cumbersome to use.

Specifically: **multi-line copy/paste** does not work.

You may be better off to put statements into a script, and then run the script, like this:

```bash
sqlcmd -S localhost,1433 -U SA -i foo.sql
```

```bash
source .env
sqlcmd -S "${MSSQL_HOST},${MSSQL_PORT}" -U "${MSSQL_USER}" -P "${MSSQL_PASS}" -i ${1}
```

### Cheat: Script the Script

To make this a bit easier for myself, I do this:

`mssqldo.sh`:

```bash
#!/bin/bash
set -e
set -u

source .env

my_sql_file="${1}"
sqlcmd \
  -S "${MSSQL_HOST},${MSSQL_PORT}" \
  -U "${MSSQL_USER}" \
  -P "${MSSQL_PASS}" \
  -i "${my_sql_file}"
```

Make executable:

```bash
chmod a+x mssqldo.sh
```

Usage:

```bash
./mssqldo.sh foo.sql
```

## How to Show all Databases

```sql
SELECT name, database_id, create_date FROM sys.databases;

GO
```

Note: Microsoft calls a database a “catalog”, half of the time anyway.

## How to Show all Tables

All tables in a database:

```sql
SELECT table_name, table_schema, table_type
    FROM information_schema.tables
    WHERE table_catalog = 'TestDB'
    ORDER BY table_name ASC;

GO
```

All tables across all databases:

```sql
SELECT *
    FROM information_schema.tables
    ORDER BY table_name ASC;

GO
```

See [https://www.databasestar.com/sql-list-tables/](https://www.databasestar.com/sql-list-tables/).

## How to Describe Columns of a Table

```sql
USE TestDB
EXEC sp_columns @table_name = N'MyTable';
```

```sql
EXEC TestDB.dbo.sp_columns MyTable;
```

However, you can’t treat the result as a table from which to query. So if you want to narrow down the result and select specific columns, it gets a little complicated - you have to turn on some special options run a linked server query to itself. It’s not _that_ complicated, but it’s just not obvious.

See also:

- [https://database.guide/how-to-select-a-subset-of-columns-from-a-stored-procedures-result-set-t-sql/](https://database.guide/how-to-select-a-subset-of-columns-from-a-stored-procedures-result-set-t-sql/)

## How to create a Read-Only User

```sql
USE master;
CREATE LOGIN mynewuser_ro WITH PASSWORD='xxxxx', DEFAULT_DATABASE=TestDB, CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF;

USE TestDB;
CREATE USER mynewuser_ro FOR LOGIN mynewuser_ro;
ALTER USER mynewuser_ro WITH DEFAULT_SCHEMA=db_datareader;
EXEC sp_addrolemember N'db_datareader', N'mynewuser_ro';
GRANT SELECT ON sys.database_files TO mynewuser_ro;

GO
```

See [https://docs.informatica.com/complex-event-processing/informatica-proactive-monitoring/3-0-hotfix-1/installation-guide/pre-installation/before-you-install/prepare-the-databases/powercenter-repository-database-requirements/create-a-read-only-user-in-microsoft-sql-server.html](https://docs.informatica.com/complex-event-processing/informatica-proactive-monitoring/3-0-hotfix-1/installation-guide/pre-installation/before-you-install/prepare-the-databases/powercenter-repository-database-requirements/create-a-read-only-user-in-microsoft-sql-server.html) - but ***note**: those instructions _actually_ create a user with **Read-Write** access!

Also, that user will have access to certain other tables than the database to which it is granted access. See the comments at [https://stackoverflow.com/questions/16211717/best-way-to-create-sql-user-with-read-only-permissions](https://stackoverflow.com/questions/16211717/best-way-to-create-sql-user-with-read-only-permissions).

### How to Generate a Random Password

This is more of a general Linux tip, but whatever… :)

```bash
xxd -l16 -ps /dev/urandom
```

```txt
0fc105b21019610009afa03eb55c8203
```

See [https://therootcompany.com/blog/how-to-generate-secure-random-strings/](https://therootcompany.com/blog/how-to-generate-secure-random-strings/).

## How to Grant Write Access

You must be logged in as `SA`, of course.

```sql
USE TestDB;

GRANT CREATE TABLE TO mynewuser_rw;
GRANT DELETE,INSERT TO mynewuser_rw;
```

## How to Enable Linked Server Data Access

This is for running certain special functions and commands, such as `OPENQUERY`, `OPENROWSET` etc.

```sql
EXEC sp_serveroption
  @server = 'SQLSRVR',
  @optname = 'DATA ACCESS',
  @optvalue = 'TRUE';
```

Your server name is probably `SQLSRVR`, but you can maybe find out for sure with `SELECT @@SERVERNAME`;

See also:

- [https://database.guide/how-to-enable-disable-data-access-in-sql-server-t-sql-examples/](https://database.guide/how-to-enable-disable-data-access-in-sql-server-t-sql-examples/)
- [https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-serveroption-transact-sql?view=sql-server-ver15](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-serveroption-transact-sql?view=sql-server-ver15)
- [https://dba.stackexchange.com/questions/115201/get-servername-from-linked-server](https://dba.stackexchange.com/questions/115201/get-servername-from-linked-server)

## SSH Port Forward / Proxy / Relay

For this scenario:

1. You have a Windows Server _inside_ the private network
    - `10.0.0.10`
2. You have a Linux Server on the same network, but with ssh already port-forwarded publicly
    - `jumpbox.example.com`
3. You want to access SQL server from you Apple laptop

You could make the Windows’ server port 1433 appear through the linux box to your laptop as port 1443 locally - or any port really. For illustrative purposes I’ll actually use port 14330:

```bash
ssh -L 14330:10.0.0.10:1433 jumpbox.example.com
```

You could also put this in your ssh config so you don’t havet to go looking that up all the time:

`.ssh/config`:

```ssh
Host jumpbox
    Port 22
    Hostname jumpbox.example.com
    LocalForward 14330 10.0.0.10:1433
```

```bash
ssh -N jumpbox
# See also https://unix.stackexchange.com/a/100863/45554
```

Then update the port used by sqlcmd:

```bash
sqlcmd -S localhost,14330 -U SA
```

## How to export to SQL

You can’t. You have to use the GUI tools for that.

See [https://dba.stackexchange.com/a/291907/230109](https://dba.stackexchange.com/a/291907/230109).

## How to export to CSV

**You can’t.** At least not with `sqlcmd`.

Use [mssql-to-csv](https://github.com/therootcompany/mssql-to-csv/releases) instead.

But there is a hack that mostly works if you don’t need to escape.

```bash
#!/bin/bash

set -e
set -u

source .env

# To remove header: -h-1
sqlcmd -S "${MSSQL_HOST}" -U "${MSSQL_USER}" -P "${MSSQL_PASS}" -i "${1}" -s"," -W -w 999 \
	|
		grep '[a-zA-Z0-9_-]' |
		grep -v 'rows affected'
```

See

## How to do a Backup

**You can’t!**

Running a backup with `sqlcmd` will produce a backup **on the server**, not the client.

```sql
USE TestDB;

BACKUP DATABASE [TestDB]
    TO DISK = N'C:\Backups\MS-SQL-Server-Test-DB.bak'
    WITH NOFORMAT, NOINIT,
    NAME = N'MS-SQL-Server-Test-DB Full Database Backup',
    SKIP, NOREWIND, NOUNLOAD,  STATS = 10;

GO
```

**However**, it may be possible to create a CIFS/SMB share (Windows share) on Linux, use [`xp_cmdshell`](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) to [mount it](https://www.getfilecloud.com/supportdocs/display/cloud/How+to+Mount+CIFS+Shares+from+Windows+Command+Line), and then run the backup from the server to client over the network share.

See also:

- [https://dba.stackexchange.com/questions/291790/how-to-create-sql-server-backup-from-windows-server-to-linux-client-with-sqlcmd/291907#291907](https://dba.stackexchange.com/questions/291790/how-to-create-sql-server-backup-from-windows-server-to-linux-client-with-sqlcmd/291907#291907) (read the comments)
- [https://www.davidklee.net/2017/08/08/sql-server-on-linux-series-backing-up-over-the-network/](https://www.davidklee.net/2017/08/08/sql-server-on-linux-series-backing-up-over-the-network/)
- [http://joshburnstech.com/2018/09/map-network-drive-sqlserver/](http://joshburnstech.com/2018/09/map-network-drive-sqlserver/)

## How to Give a User Backup Privileges

```sql
USE TestDB;

EXEC sp_addrolemember N'db_backupoperator', 'mynewuser_ro';

GO
```
