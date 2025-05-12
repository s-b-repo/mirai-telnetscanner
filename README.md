---


# Telnet Proxy Scanner and Brute-Forcer

This is a high-performance, proxy-enabled **Telnet brute-forcing and proxy scanning tool** built in Python. It is designed for security researchers and penetration testers who need to:

- 🕵️ Discover **public proxy servers**
- 🔐 Brute-force **Telnet logins** using proxy rotation
- 💾 Save working credentials to disk
- 🌐 Route traffic through **HTTP proxies** or a local **WireGuard-based proxy API**

---

## Features

✅ Proxy-aware scanning (HTTP proxy tunnel support)  
✅ Credential list support (`creds.txt`)  
✅ IP randomization with reserved IP filtering  
✅ Parallel proxy testing and login attempts  
✅ Working hits saved to `hits.txt`  
✅ Minimal CPU usage for 1-core systems  
✅ Modular design (easily extended)

---

## 📦 Installation

1. Clone the repo:

```
git clone https://github.com/yourusername/telnet-proxy-scanner.git
cd telnet-proxy-scanner
````

2. Install dependencies:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ First-Time Setup

Run the setup script to create the admin user and initialize the SQLite database:

```
python3 setup.py
```

You'll be prompted to enter:

* A username
* A valid email address
* A strong password

The script will:

* Initialize the database
* Create the user
* Print the success message

---

## 🚀 Running the Scanner

Once setup is complete, launch the main tool:

```
python3 main.py
```

The tool will:

* Load proxies from `proxies.txt`
* Load credentials from `creds.txt`
* Generate random IPs (avoiding reserved/private ranges)
* Attempt brute-force logins using active proxies
* Save valid logins to `hits.txt`

---

## 📁 File Overview

| File          | Description                                    |
| ------------- | ---------------------------------------------- |
| `setup.py`    | Setup script for database and admin user       |
| `main.py`     | Main scanner logic                             |
| `creds.txt`   | Credential list in `user:pass` format          |
| `proxies.txt` | Proxy list in `ip:port` format (HTTP only)     |
| `hits.txt`    | Valid login hits saved during brute-force runs |
| `models.py`   | Flask-SQLAlchemy models for users and proxies  |

---

## 🧪 Proxy Format

Supports only **HTTP proxies** in the format:

```
96.126.118.190:801
97.83.40.67:5678
98.175.31.195:4145
```

Avoids:

* Authenticated proxies
* SOCKS proxies

---

## 📌 Notes

* Optimized for **low-resource VPS** (1 core, 512MB RAM)
* Built for **educational and lawful** penetration testing only

---

## 🛑 Legal Disclaimer

This tool is intended for **educational use** only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning or brute-forcing devices you do not own.

---

## 🧠 Credits

me suicidak teddy

---

## 📬 Questions?

Open an issue or contact via GitHub.


