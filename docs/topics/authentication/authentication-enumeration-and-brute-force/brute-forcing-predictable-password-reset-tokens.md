---

title: Brute-Forcing Predictable Password Reset Tokens
tags: [authentication, brute-force, web]
difficulty: intermediate
platform: tryhackme

---

# Brute forcing predictable password reset tokens

**Platform**: TryHackMe  
**Category**: Enumeration + Brute Force  
**Technique**: Brute Force Reset Token

---

## Background / Theory

The reset functionality uses a numeric token in the URL, which can be brute forced to trigger a password reset for a known user.

This attack simulates a real-world situation where a predictable password reset mechanism can be exploited to gain access to an existing user account.

---

## Steps

In this attack we will exploit a password reset feature that uses **predictable numeric tokens**.  
By brute forcing token values using **Crunch** and **Burp Suite Intruder**, we can trigger the application to return a new password.  

Although the THM example uses the `admin` account, a real-world attacker might use the valid email discovered in [enumeration-via-verbose-errors](enumeration-via-verbose-errors.md)  to reset the password for that specific user.

1. Go to Task 4 on https://tryhackme.com/room/enumerationbruteforce
2. Open a terminal in AttackBox and use Crunch to generate a list of numbers from 100 to 200
3. Open Burp Suite and capture the request to http://enum.thm/labs/predictable_tokens/reset_password.php?token=123
4. Send the request to the Intruder
5. Highlight the value of the token parameter, click Add payload button
6. Set the Payload Type to Simple list and click the Load button and select the list you generated in step 3.
7. Start the attack and sort the requests by the Length field - select the request that has a bigger length value than all the other requests. This is the one that contains a new password
8. Log into the application using the new password.

---

### Outcome

- Gained access to the user’s account by brute forcing a weak reset token

### Next Steps in Attack Chain
- 

---

### Mitigation

- Use long, randomized, single-use tokens for password resets
- Invalidate password reset tokens quickly after issuance
- Monitor for repeated failed token attempts and block accordingly