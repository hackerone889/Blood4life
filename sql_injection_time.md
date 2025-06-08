**Title: [sql-injection] in [Blood4life] <= [v1.0]**
---
## BUG Author: [Sujal Patel]
---
### Product Information:
---
- Software Link: https://github.com/hackerone889/Blood4life.git
- BUG Author: Sujal Patel

### Vulnerability Details
---
- Type: Time Based SQL Injection
- Affected URL: http://192.168.29.124/blood/bbdms/login.php
- Vulnerable Parameter: Emailid

#### Vulnerable Files:
- File Name: Login.php
- Path: /blood/bbdms/login.php

#### Vulnerability Type
- SQL Injection Vulnerability (CWE-89: SQL Injection)
- Severity Level: CRITICAL (CVSS: 9.1)

#### Root Cause
The code directly concatenates user input into SQL query strings without any parameterization or input validation, allowing attackers to inject malicious SQL code.

![image](https://github.com/user-attachments/assets/bec8b0f9-6744-41df-ba06-c0227af52bc8)


### Impact:
- Unauthorized access to database information  
- Potential exposure of sensitive information (such as user passwords)  
- Possible database corruption or data manipulation

### Description:
---
#### 1. Vulnerability Details:
- In this php code, username parameter is directly concatenated into SQL Statement
- No input validation or escaping mechanisms implemented

#### 2. Attack Vectors:
- Attackers can manipulate SQL query structure using special characters
- Additional information can be extracted using Time Based Payloads
- Database information can be obtained through Time Based injection
- Time based injection might reveal more information

#### 3. Attack Payload Examples: 
```
    Payload: email=' AND (SELECT 5803 FROM (SELECT(SLEEP(5)))LOuf) AND 'Hdtb'='Hdtb&password=Test@123&login=
```

![image](https://github.com/user-attachments/assets/bd207556-a5fb-4ea8-9fae-81914ceab25d)



### Proof of Concept:
---
#### Information extraction
```
email=' AND (SELECT 5803 FROM (SELECT(SLEEP(5)))LOuf) AND 'Hdtb'='Hdtb&password=Test@123&login=
```
##### email is injectable!

![image](https://github.com/user-attachments/assets/ad898ce2-96b9-4341-ba92-2f61104e75df)


##### Databases information extracted

![image](https://github.com/user-attachments/assets/6d4ed215-52cf-41c7-90ce-75145ffe9565)


##### Tables information extracted

![image](https://github.com/user-attachments/assets/1bae8f47-0bb8-413f-8058-315f1552c6fd)

##### Table=tbladmin data dumped!

![image](https://github.com/user-attachments/assets/42f39a63-5f52-4b90-b250-53117c576828)

### Suggested Remediation:
---
- Implement Prepared Statements
- Input Validation
- Security Recommendations
  - Implement principle of least privilege
  - Encrypt sensitive data storage
  - Implement WAF protection
  - Conduct regular security audits
  - Use ORM frameworks for database operations

### Additional Information:
---
- Refer to OWASP SQL Injection Prevention Guide
- Consider using modern frameworks like MyBatis or Hibernate
- Implement logging and monitoring mechanisms
- References:
 - OWASP SQL Injection Prevention Cheat Sheet
 - CWE-89: SQL Injection
 - CERT Oracle Secure Coding Standard for Java

The severity of this vulnerability is ***HIGH***, and immediate remediation is recommended as it poses a serious threat to the system's data security.

Mitigation Timeline:

- Immediate: Implement prepared statements
- Short-term: Add input validation
- Long-term: Consider migrating to an ORM framework

This vulnerability requires immediate attention due to its potential for significant data breach and system compromise.




