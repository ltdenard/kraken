# 🐙 Kraken

Kraken is an automation tool designed to streamline the process of extracting and cracking password hashes from Active Directory (AD) environments. Built on top of [Impacket](https://github.com/SecureAuthCorp/impacket), Kraken adds multiprocessing and automation to handle large `ntds.dit` files efficiently.

---

## 🎯 Features

- 🔐 Automated hash extraction from `ntds.dit`
- ⚡ Multiprocessing for faster processing of large datasets
- 🧩 Seamless integration with Hashcat
- 🛠️ Designed for red teamers, CTF players, and AD researchers

---

## 🛠️ Setup

### ✅ Requirements

- **Samba Client** (for interacting with SMB shares):

```bash
sudo yum install samba-client
```

- **Python 3.9.2** (Kraken is tested with this version)

### 🔧 Virtual Environment Setup

```bash
python3.9 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ Optional: Run as a Systemd Service

To run Kraken in the background as a service:

1. **Edit `krakenworker.service`**:  
   Update these two fields:
   - `WorkingDirectory=` → path to your Kraken repo
   - `ExecStart=` → path to your Python binary and `kraken_worker.py`

2. **Install the service**:

```bash
sudo cp krakenworker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable krakenworker.service
sudo systemctl start krakenworker.service
```

3. **Check the service**:

```bash
sudo systemctl status krakenworker.service
```

---

## 🚀 Usage

1. Activate your virtual environment:

```bash
source ./venv/bin/activate
```

2. Run the worker:

```bash
python kraken_worker.py
```

Make sure any required input files (e.g., `ntds.dit`, SYSTEM hive) are present or configured correctly for your pipeline.

---

## 🧠 Credits

Kraken is powered by modified version of [Impacket](https://github.com/SecureAuthCorp/impacket) — a phenomenal library by the folks at SecureAuth. Big thanks to them!

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized** use only. You must have **explicit permission** to perform hash extraction or password cracking on any systems you target with Kraken. Unauthorized use may be illegal and is strictly discouraged.

---

> “With great power comes great responsibility.” – Uncle Ben
