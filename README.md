# SecureShift
<p align="center">
  <img src="https://raw.githubusercontent.com/ozcanpng/SecureShift/refs/heads/main/web/uploads/SecureShift.png" alt="SecureShift Logo" width="300">
</p>
<p align="center">
  <a href="https://hub.docker.com/r/ozcanpng/secureshift">
    <img src="https://img.shields.io/badge/Docker-SecureShift-blue?logo=docker" alt="Docker">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  </a>
  <a href="https://golang.org/">
    <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go" alt="Go">
  </a>
</p>

SecureShift is a web application security training platform designed for educational purposes. It demonstrates common web vulnerabilities in a controlled environment for security learning and practice.

## Features

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Cross Site Request Forgery (CSRF)
* DOM-based Vulnerabilities (DOM XSS)
* OS Command Injection
* Path Traversal
* Insecure Deserialization
* Information Disclosure
* File Upload Vulnerabilities
* JWT (JSON Web Token) Bypass
* Insecure Direct Object Reference (IDOR)
* Server-Side Request Forgery (SSRF)
* Server-Side Template Injection (SSTI)
* XML External Entity (XXE)

## Quick Start

### Using Docker
```bash
# Pull and run the container
docker pull ozcanpng/secureshift
docker run -d -p 3000:3000 --name secureshift ozcanpng/secureshift

# Access the application
open http://localhost:3000
```

### From Source
```bash
# Clone the repository
git clone https://github.com/ozcanpng/SecureShift.git
cd SecureShift

# Install dependencies
go mod tidy

# Run the application (secure mode by default)
go run cmd/server/main.go

# Or run in insecure mode for vulnerability discovery
MODE=insecure go run cmd/server/main.go

# Or run in secure mode explicitly
MODE=secure go run cmd/server/main.go

# Access the application
open http://localhost:3000
```

## Operating Modes

SecureShift operates in two modes:

- **Secure Mode** (default): Vulnerabilities are patched for learning purposes
- **Insecure Mode**: Contains intentional vulnerabilities for security testing

You can switch between modes using the `MODE` environment variable. If you discover vulnerabilities in secure mode, please report them - this helps improve the platform's security.

## Default Login
```
Username: darlene
Password: darlene321
```

## Docker Commands
```bash
# Pull image
docker pull ozcanpng/secureshift

# Run container
docker run -d -p 3000:3000 --name secureshift ozcanpng/secureshift

# Stop container
docker stop secureshift

# Start container
docker start secureshift

# Remove container
docker rm secureshift

# View logs
docker logs secureshift
```

## Build from Source
```bash
# Clone repository
git clone https://github.com/ozcanpng/SecureShift.git
cd SecureShift

# Download dependencies
go mod download

# Build application
go build -o secureshift cmd/server/main.go

# Run binary (secure mode)
./secureshift

# Run binary (insecure mode)
MODE=insecure ./secureshift
```

## Project Structure
```
SecureShift/
├── cmd/server/main.go     # Application entry point
├── internal/              # Application logic
├── web/                   # Frontend files
├── data/                  # Database (auto-generated)
├── LICENSE                # MIT License
└── README.md
```

## Documentation

For detailed vulnerability explanations and exploitation examples, see:
[SecureShift PoC Report](./SecureShift-PoC-EN/SecureShift-PoC-EN.md)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

**GitHub**: [SecureShift Repository](https://github.com/ozcanpng/SecureShift)  
**Docker Hub**: [ozcanpng/secureshift](https://hub.docker.com/r/ozcanpng/secureshift)
