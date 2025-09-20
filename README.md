# SecureShift

[![Docker Image](https://img.shields.io/badge/Docker-SecureShift-blue?logo=docker)](https://hub.docker.com/r/ozcanpng/secureshift)

SecureShift is a **security training and demonstration project** written in **Go** with a simple **SQLite** backend and a static web frontend.  
It is designed to showcase **common web vulnerabilities** in a controlled environment, allowing security researchers, students, and developers to practice exploitation and mitigation.

---

## 🚀 Implemented Vulnerabilities

- SQL Injection (SQLi)  
- Cross-Site Scripting (XSS)  
- Cross Site Request Forgery (CSRF)  
- DOM-based Vulnerabilities (DOM XSS)  
- OS Command Injection  
- Path Traversal  
- Insecure Deserialization  
- Information Disclosure  
- File Upload Vulnerabilities  
- JWT (JSON Web Token) Bypass  
- Insecure Direct Object Reference (IDOR)  
- Server-Side Request Forgery (SSRF)  
- Server-Side Template Injection (SSTI)  
- XML External Entity (XXE)  

---

## 🛠 Lightweight Stack

- **Backend:** Go (Chi Router, SQLite3)  
- **Frontend:** Static HTML/CSS/JS  
- **Database:** SQLite (preloaded sample data)  

---

## 🔑 Default Credentials

```
Username: darlene
Password: darlene321
```

---

## 📦 Usage with Docker

1) **Pull the image** (latest tag by default)  
```bash
docker pull ozcanpng/secureshift
```

2) **Run the container** (detached, port 3000 exposed, named `secureshift`)  
```bash
docker run -d -p 3000:3000 --name secureshift ozcanpng/secureshift
```

3) **Stop the container**  
```bash
docker stop secureshift
```

4) **Start the container again**  
```bash
docker start secureshift
```

Now open: 👉 [http://localhost:3000](http://localhost:3000)

---

## 📖 Repository Overview

SecureShift is built for:  
- **Cybersecurity Students** – to practice attacks/defenses  
- **Developers** – to understand common pitfalls  
- **Researchers** – to simulate vulnerable apps safely  

---

## ⚠️ Disclaimer

This project is **for educational and training purposes only**.  
Do **NOT** deploy it on production systems.  

---

## 🗂 Repo Structure & Notes

- `/cmd` → main application entry point  
- `/internal` → backend logic, handlers, routes, modes  
- `/web` → static frontend (HTML/JS/CSS)  
- `/data` → ⚠️ *excluded from repo* (database auto-generated, keep empty)  
- `/web/uploads` → ⚠️ *intentionally left empty* for testing file upload vulnerabilities  

> 📝 Note: `data/` and `web/uploads/` directories should remain empty in the repository.  
> The database is created automatically when the container runs.  
> `uploads/` is left open for practicing file upload attacks.

---

## 📌 Links

- 🐳 **Docker Hub:** [ozcanpng/secureshift](https://hub.docker.com/r/ozcanpng/secureshift)  
- 📂 **GitHub Repository:** *(this repo)*  

---

## 📜 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.
