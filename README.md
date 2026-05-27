# 🛡️ Secure File Transfer Monitoring System (SFTMS)

The **Secure File Transfer Monitoring System (SFTMS)** is a lightweight, background daemon that monitors file system events in real-time, enforcing security policies such as unauthorized access prevention, data integrity checking, and alert generation.

This project now also includes an interactive **Web Dashboard** to visualize security metrics and logs.

---

## 🌟 Key Features

1. **Real-time File Monitoring**: Uses `watchdog` to monitor creations, modifications, moves, and deletions without polling latency.
2. **Data Integrity Hashing**: Automatically calculates and tracks SHA-256 hashes of tracked files to detect silent tampering or corruption.
3. **Authorization & Rate Limiting**: Whitelists specific users and limits the number of file operations allowed within a specific time window.
4. **Email Alert Engine**: Configurable SMTP integration that sends real-time email notifications for `HIGH` or `CRITICAL` severity events (runs in a background thread to prevent blocking).
5. **Interactive Dashboard**: A frontend built with Streamlit providing real-time data visualization of transfer events and security violations.
6. **Excel Audit Reporting**: Automatically generates comprehensive multi-sheet Excel reports detailing user activity and system alerts.

---

## 🛠️ Project Architecture (6 Phases)
- **Phase 1**: Setup & file system listener.
- **Phase 2**: Event classification & transfer logging.
- **Phase 3**: File integrity hashing (SHA-256).
- **Phase 4**: Authorization check & violation flagging.
- **Phase 5**: Alert engine & email notifications.
- **Phase 6**: Audit report generation (Excel).

---

## 🚀 Getting Started Locally

### 1. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/your-username/Secure-File-Transfer-Monitoring-System.git
cd Secure-File-Transfer-Monitoring-System
pip install -r requirements.txt
```

### 2. Setup Test Environment
To test the system safely without pointing it at real sensitive directories, initialize the dummy environment:
```bash
python main.py --setup
```
*This creates a `test_watch/` folder containing sample dummy files.*

### 3. Run the Live Monitor
Start the monitoring daemon:
```bash
python main.py
```
*Once running, navigate to the `test_watch/` folder and modify, rename, or copy files to see real-time alerts in your terminal!*

### 4. Generate the Audit Report
To generate a comprehensive Excel spreadsheet of all tracked events:
```bash
python main.py --report
```

---

## 📊 Viewing the Web Dashboard

To launch the local Web Dashboard and view your logs:
```bash
streamlit run app.py
```
*This will open an interactive interface in your browser.*

---

## ⚙️ Configuration
All configurations can be found in `config/settings.py`.
- **`WATCH_PATH`**: Change this to the actual directory you want to monitor in production.
- **`WHITELIST_USERS`**: Define which Windows/Linux usernames are authorized.
- **`SMTP Settings`**: Configure environment variables (`SFTMS_SMTP_USER`, `SFTMS_SMTP_PASSWORD`, etc.) to enable real email alerting.

---

## ☁️ Deployment

**To Deploy the Web Dashboard (Streamlit Community Cloud):**
1. Push this repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io/).
3. Click **"New App"** -> **"Deploy a public app from GitHub"**.
4. Select this repository and set the main file path to `app.py`.
5. Click **Deploy**.

**To Deploy the Background Monitor (Windows):**
Use **NSSM (Non-Sucking Service Manager)** to wrap `main.py` as a permanent background Windows Service, ensuring the monitor auto-starts with the server and remains invisible.
