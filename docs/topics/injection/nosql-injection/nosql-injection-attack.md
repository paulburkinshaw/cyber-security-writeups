# NoSql Injection Attacks

The root cause of an injection attack is that improper concatenation of untrusted user input into a command can allow an attacker to alter the command itself. With SQL injection, the most common approach is to inject a single or double quote, that terminates the current data concatenation and allows the attacker to modify the query. The same approach applies to NoSQL Injection. If untrusted user input is directly added to the query, we have the opportunity to modify the query itself. However, with NoSQL Injection, even if we can't escape the current query, we still have the opportunity to manipulate the query itself. Therefore, there are two main types of NoSQL Injection:

- Syntax Injection - This is similar to SQL injection, where we have the ability to break out of the query and inject our own payload. The key difference to SQL injection is the syntax used to perform the injection attack.
- Operator Injection—Even if we can't break out of the query, we could potentially inject a NoSQL query operator that manipulates the query's behaviour, allowing us to stage attacks such as authentication bypasses.

## Operator Injection Attack 1
Go to:
https://tryhackme.com/room/nosqlinjectiontutorial 
Task 4

Capture the POST request in BURP and change:  
`user=xxxx&pass=yyyy&remember=on`  

To:  
`user[$ne]=xxxx&pass[$ne]=yyyy&remember=on`  

The resulting filter would end up looking like this:  
`['username'=>['$ne'=>'xxxx'], 'password'=>['$ne'=>'yyyy']]`  

This would trick the database into returning any document where the username isn't equal to 'xxxx,' and the password isn't equal to 'yyyy'. 

## Operator Injection Attack 2
Go to:
https://tryhackme.com/room/nosqlinjectiontutorial 
Task 5

The `$nin` operator allows us to create a filter by specifying criteria where the desired documents have some field, not in a list of values:  

`user[$nin][]=admin&user[$nin][]=pedro&pass[$ne]=yyy&remember=on`  

This would translate to a filter that has the following structure:  

`['username'=>['$nin'=>['admin', 'pedro'] ], 'password'=>['$ne'=>'yyy']]`

Which tells the database to return any user for whom the username isn't admin, and the username isnt pedro, and the password isn't aweasdf. 
Notice that the `$nin` operator receives a list of values to ignore.

## Operator Injection Attack 3

## Syntax Injection 
Test for Syntax Injection by providing both a false and true condition and seeing if the output differs  

`admin' && 0 && 'x`

`admin' && 1 && 'x`

## Links 
### Mongdb query reference
https://www.mongodb.com/docs/manual/reference/operator/query/

