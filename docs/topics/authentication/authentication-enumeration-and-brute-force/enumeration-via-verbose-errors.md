---

title: Enumeration via verbose error messages
tags: [enumeration, brute-force, web]
difficulty: intermediate
platform: tryhackme

---

# Enumeration via verbose error messages

**Platform**: TryHackMe  
**Category**: Enumeration + Brute Force  
**Technique**: Verbose Login Enumeration

---

## Background / Theory

This attack simulates a real-world situation where poor feedback in the login process can lead to the disclosure of a valid email account.

---

## Steps

In this attack we will exploit a verbose error in a login form that reveals whether an email address has been registered yet. We'll be applying a **brute-force wordlist** to identify a registered email address via login form responses. We’ll be using a **Python script** and a **common email wordlist** to automate this process.  

1. Go to Task 3 on https://tryhackme.com/room/enumerationbruteforce
2. Go to http://enum.thm/labs/verbose_login/ and enter any email address in the Email field, this gives the error "Email does not exist" indicating the email has not been registered yet.
3. Download the common emails payload list and execute the Python script to brute force the login form with the emails in the list until a valid email is found in the responses.

---

### Outcome

- Discovered a valid user email through login error message analysis  

### Next Steps in Attack Chain
- [brute-forcing-predictable-password-reset-tokens](brute-forcing-predictable-password-reset-tokens.md)

---

### Mitigation

- Use generic error messages (e.g., “Invalid credentials”) to prevent account enumeration
- Implement CAPTCHA and rate limiting for login attempts