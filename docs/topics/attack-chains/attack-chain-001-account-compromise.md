---

title: Attack Chain: Account Compromise via Enumeration and Predictable Reset Token
tags: [enumeration, brute-force, authentication, web]
difficulty: intermediate
platform: tryhackme

---

# Attack Chain: Account Compromise via Enumeration and Predictable Reset Token

This attack chain simulates a real-world situation where **verbose login errors** and a **weak password reset mechanism** are chained together to compromise a user's account.  
It combines:
- [enumeration-via-verbose-errors](..\authentication\authentication-enumeration-and-brute-force\enumeration-via-verbose-errors.md)
- [brute-forcing-predictable-password-reset-tokens](..\authentication\authentication-enumeration-and-brute-force\brute-forcing-predictable-password-reset-tokens.md)

---

## Overview

> Discover a valid user email via login error messages and exploit a predictable password reset implementation to gain access to their account.

---

## Chain Structure

### 1. Enumeration via Verbose Error Messages  
The login form leaks whether an email address exists based on the error message returned.  
[Read full write-up →](..\authentication\authentication-enumeration-and-brute-force\enumeration-via-verbose-errors.md)

**Outcome:** Valid user email address is discovered.

---

### 2. Brute-Forcing a Predictable Password Reset Token  
The password reset feature uses a numeric token in the URL. By brute-forcing these tokens, an attacker can trigger the password reset flow and obtain a new password for the targeted account.  
[Read full write-up →](..\authentication\authentication-enumeration-and-brute-force\brute-forcing-predictable-password-reset-tokens.md)

**Outcome:** Gained access to the account via forced password reset.

---

## Real-World Relevance

This kind of chained attack has been seen in actual breaches where:
- Login forms are too verbose (“User not found” vs “Incorrect password”)
- Password reset tokens are numeric or guessable
- Account takeover happens without needing the original password

---

## Defenses & Mitigations

- Use **generic login error messages** like “Invalid credentials”
- Implement **rate limiting** and **CAPTCHAs** on login and reset forms
- Use **long, random, single-use tokens** for password resets
- **Log and alert** on excessive reset attempts per IP or email

---

## Tools Used

- Burp Suite Intruder  
- Crunch wordlist generator  
- Custom Python scripting  

---

## Future Enhancements

- Simulate alert generation in a SIEM (e.g., failed reset attempts)  
- Implement detection logic for brute-force token attempts  
- Expand to include MFA bypass if relevant  

