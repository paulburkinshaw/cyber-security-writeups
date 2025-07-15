# Second-Order SQL Injection Attacks

Second-order SQL injection, also known as stored SQL injection, exploits vulnerabilities where user-supplied input is saved and subsequently used in a different part of the application, possibly after some initial processing. The injection occurs upon the second use of the data when it is retrieved and used in a SQL command, hence the name "Second Order".

This type of attack is more insidious because the malicious SQL code does not need to immediately result in a SQL syntax error or other obvious issues, making it harder to detect with standard input validation techniques.

