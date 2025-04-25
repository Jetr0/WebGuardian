# WebGuardian: Advanced Web Protection System

## 🛡️ Overview

WebGuardian is an advanced web security Flask application designed to protect web services from various types of cyber attacks. It provides comprehensive protection against multiple attack vectors through intelligent request filtering, logging, and IP management.

## ✨ Key Features

- **Multi-Vector Attack Detection**
  - SQL Injection (SQLi) prevention
  - Cross-Site Scripting (XSS) protection
  - Path Traversal mitigation
  - Command Injection blocking
  - Server-Side Request Forgery (SSRF) prevention
  - HTTP Header Injection detection
  - NoSQL Injection protection

- **Dynamic IP Management**
  - Permanent IP blocking using iptables
  - Configurable whitelist
  - Automatic IP blocking for detected attacks
  - Manual IP unblocking and whitelisting

- **Comprehensive Logging**
  - Detailed attack logs
  - Request statistics tracking
  - Attack type categorization

- **Web Dashboard**
  - Real-time attack statistics
  - Log viewer
  - Whitelist management interface

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Flask
- sudo access (for iptables management)
- Kali Linux or similar Linux distribution recommended

### Setup
1. Clone the repository:
```bash
git clone https://github.com/Jetr0/WebGuardian.git
cd webguardian
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up iptables permissions:
```bash
sudo visudo
# Add the following line to allow iptables management without password
yourusername ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/iptables-save
```

## 🔧 Configuration

### Attack Payload Customization
Modify `ATTACK_PAYLOADS` dictionary in the main script to add or adjust attack detection patterns.

### Whitelist Management
- Default whitelist includes: `127.0.0.1`, `0.0.0.0`, `localhost`
- Manage whitelist via web interface at `/whitelist`

## 🌐 Running the Application

```bash
python app.py
```

The application will start on `http://0.0.0.0:5000/`

### Web Interfaces
- Main Dashboard: `http://0.0.0.0:5000/`
- Logs: `http://0.0.0.0:5000/logs`
- Whitelist Management: `http://0.0.0.0:5000/whitelist`

## 📊 Monitoring

WebGuardian tracks:
- Total requests
- Blocked requests
- Blocked IPs
- Attacks by type
- Timestamps of last request

## 🛡️ Security Best Practices

- Regularly review and update attack payloads
- Monitor logs frequently
- Be cautious when whitelisting IPs
- Keep the system updated

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

WebGuardian is a security tool and should be used responsibly. Always ensure you have proper authorization before deploying on any system.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📧 Contact

Your Name - paurg06@gmail.com

Project Link: [https://github.com/Jetr0/WebGuardian](https://github.com/Jetr0/WebGuardian)