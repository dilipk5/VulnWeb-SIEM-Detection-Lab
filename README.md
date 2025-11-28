# Complete SIEM Detection Lab Using Splunk and Python Web App.



***A full end-to-end detection engineering project using real attacker behavior, custom POST-body logging, and Splunk dashboards***


Security analysts often work with production systems where logs are huge, incomplete, inconsistent, or unstructured.

I wanted to build something from scratch that would simulate this real-world workflow:

**attacks → logs → ingestion → field extraction → detection → dashboards → investigation**.

This project is the result — a full SIEM detection lab built using:

- A **vulnerable Flask web app** (blog + shop + login + comments)
- **Apache reverse proxy** on Ubuntu
- **Custom POST-body logging**
- **Splunk Universal Forwarder**
- **Kali Linux attacker VM**
- **Detection dashboards for XSS, SQLi, brute-force, and enumeration**

The goal was not only to simulate attacks, but to detect them in a way that mirrors what SOC teams do in real enterprise environments.

# Setting Up the Vulnerable Python Web App and Splunk SIEM

## 1. Python web Application

It intentionally includes several vulnerabilities: SQL injection, XSS, weak authentication, file handling issues, and more. Perfect material for Splunk detections.

```powershell
git clone https://github.com/<your-repo>/Vuln-Web
cd Vuln-Web
pip install -r requirements.txt
```

### Initialize the database

The project ships with an initialization script inside `app/__init__.py`, which automatically builds tables and inserts test users, posts, and comments:

```bash
python3 run.py
```

On first boot, it prints:

```
✓ Default admin created
✓ Fake blog posts created
✓ Fake comments created
```

Now the web app is ready and running on port `8080`:

```bash
python3 run.py
```

Open it in a browser:

```
http://localhost:8080
```

## 2. Adding POST-Body Logging to Capture Attacks

You probably dont have to wrooy about this step cause i updated the github code to log post requests. 

By default, Apache logs only cover GET requests.

But most attacks (SQLi, XSS, brute-force) happen in **POST data**.

To detect these attacks, the app was modified to log every POST request body into a dedicated log file.

Inside `app/__init__.py`, the following middleware was added:

```python
import logging
from logging.handlers import RotatingFileHandler
from flask import request

post_log_handler = RotatingFileHandler(
    '/var/log/vulnweb/post.log',
    maxBytes=500000,
    backupCount=5
)

post_log_handler.setFormatter(
    logging.Formatter('%(asctime)s - IP: %(ip)s - PATH: %(path)s - BODY: %(body)s')
)

post_logger = logging.getLogger('post_logger')
post_logger.setLevel(logging.INFO)
post_logger.addHandler(post_log_handler)

@app.before_request
def log_post_body():
    if request.method == 'POST':
        post_logger.info(
            "",
            extra={
                "ip": request.remote_addr,
                "path": request.path,
                "body": request.get_data(as_text=True)
            }
        )

```

POST bodies now appear in:

```
/var/log/vulnweb/post.log

```

Example:

```
IP: 127.0.0.1 - PATH: /login - BODY: {'username':'admin','password':'admin1'}
IP: 127.0.0.1 - PATH: /blog/22/comment - BODY: {'content': "<script>alert('XSS')</script>"}
```

## 3. Installing Apache and Setting Up a Reverse Proxy

To simulate a real-world production environment, Apache was placed in front of the Python app.

Apache listens on port **80** and proxies traffic to the Flask app on **8080**.

### Install Apache

```bash
sudo apt install apache2
```

### Enable necessary modules

```bash
sudo a2enmod proxy proxy_http
```

### Create a reverse-proxy configuration

`/etc/apache2/sites-available/vulnweb.conf`:

```
<VirtualHost *:80>
    ServerName vulnweb.local

    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog ${APACHE_LOG_DIR}/vulnweb-error.log
    CustomLog ${APACHE_LOG_DIR}/vulnweb-access.log combined
</VirtualHost>
```

Enable the site:

```bash
sudo a2ensite vulnweb.conf
sudo systemctl restart apache2
```

Now the web app is reachable from:

```
http://localhost
```

And logs appear in:

```
/var/log/apache2/vulnweb-access.log
/var/log/apache2/vulnweb-error.log
```

## 4.**Installing Splunk on Ubuntu**

Splunk was installed directly on the Ubuntu VM.

This allows everything (logs + dashboards + detections) to stay centralized.

### Install Splunk Enterprise

Download the `.deb` package:

```bash
sudo dpkg -i splunk*.deb
```

Start Splunk:

```bash
sudo /opt/splunk/bin/splunk start --accept-license
```

Splunk’s UI is now available at:

```
http://localhost:8000
```

## 5. Adding Data Sources to Splunk

Splunk needs to ingest:

- Apache access logs
- Apache error logs
- Flask POST-body logs

### Add Apache logs

```bash
sudo /opt/splunk/bin/splunk add monitor /var/log/apache2/vulnweb-access.log -sourcetype access_combined
sudo /opt/splunk/bin/splunk add monitor /var/log/apache2/vulnweb-error.log
```

### Add the POST-body log file

```bash
sudo /opt/splunk/bin/splunk add monitor /var/log/vulnweb/post.log -sourcetype vulnweb_post
```

Restart Splunk:

```bash
sudo /opt/splunk/bin/splunk restart
```

## 6. Field Extraction for POST Payloads

Splunk receives the full raw line, but we want:

- `IP`
- `PATH`
- `BODY`

So a field extraction was added using Regex:

```
IP:\s(?<IP>[^ ]+)\s-\sPATH:\s(?<PATH>[^ ]+)\s-\sBODY:\s(?<BODY>.*)
```

Now Splunk recognizes POST content as separate fields, enabling:

- XSS detection
- SQLi detection
- brute-force patterns
- endpoint analytics

This is the crucial step for security monitoring.

# **Lab Architecture Overview**

The lab contains three machines:

### **1. Ubuntu VM (Victim + Splunk SIEM)**

- Hosts the vulnerable Flask web application
- Runs Apache as a reverse proxy
- Captures access logs
- Captures POST request bodies
- Splunk Universal Forwarder sends all logs to Splunk on the same VM

### **2. Kali Linux VM (Attacker)**

Used to simulate real attacker behavior:

- XSS payloads
- SQL injection
- Login brute force
- Directory enumeration
- POST-body manipulation
- Basic DoS

## 3. Arch (HOST + 2nd Attacker)

# **Web Application Overview**

This was my project to learn web security fundamentals i coded this and then uploaded on github , here you can see this https://github.com/dilipk5/Vuln-Web.

The custom Flask web application includes:

- User registration & login
- Blog posts
- Comments (XSS-prone)
- Product pages
- SQL-backed data storage
- Multiple known vulnerabilities:
    - No input sanitization
    - Plain-text passwords
    - Unsafe string interpolation
    - Missing auth checks
    - XSS-injection spots
    - SQL injection in login & search
    - POST body not validated

Perfect for a detection lab.

Apart form this since apache only logged get and post request but the data inside post request is not stored by the apache log so using flask logging feature i was able to log post request also witht the data inside it which was usefull in xss or sqli detection in splunk.

So I built a custom Flask logging middleware:

```python
@app.before_request
def log_post_body():
    if request.method == 'POST':
        post_logger.info(
            "",
            extra={
                "ip": request.remote_addr,
                "path": request.path,
                "body": request.get_data(as_text=True)
            }
        )
```

POST logs are written to:

```
/var/log/vulnweb/post.log
```

Splunk ingests this along with Apache logs, giving full visibility into attackers’ payloads.

This step elevates the project into true detection engineering territory — not just traffic monitoring.

# **Attack Simulation**

From the Kali attacker VM, I executed multiple realistic attacks.

### **1. Directory Brute Force**

```
gobuster dir -u http://victim/ -w /usr/share/wordlists/dirb/common.txt
```

→ Thousands of 404s

→ Perfect for “Enumeration Detection”

---

### **2. Login Brute Force**

```
hydra -l admin -P rockyou.txt victim http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

→ Repeated POSTs

→ Easily detected in POST logs

---

### **3. SQL Injection Attempts**

```
POST /login
username=admin&password=' OR 1=1--
```

or

```
/search?q=' UNION SELECT password FROM users--
```

These show up clearly in `BODY` fields.

---

### **4. XSS Payloads**

```
<script>alert(1)</script>
<img src=x onerror=alert(1337)>
```

Submitted inside blog comments, detected in POST logs.

---

### **5. DoS-style Request Flood**

```
ab -n 2000 -c 200 http://victim/
```

→ Visible as sharp spikes in request-per-second timeline.

# **Detection Logic in Splunk**

## **Field Extraction**

POST logs look like:

```
IP: 192.168.31.204 - PATH: /login - BODY: {'username':'admin','password':'admin1'}
```

I created a regex field extractor:

```
IP:\s(?<IP>[^ ]+)\s-\sPATH:\s(?<PATH>[^ ]+)\s-\sBODY:\s(?<BODY>.*)
```

Splunk now has:

- `IP`
- `PATH`
- `BODY`

This is the foundation of all detections.

---

# **Detection Panels in Splunk Dashboard**

The dashboard contains multiple panels that mimic real SIEM alerting.

---

## **1. XSS Detection (POST Payloads)**

Search:

```
index=* sourcetype=vulnweb_post
| where like(BODY,"%<script>%") OR like(BODY,"%onerror%")
| table _time IP PATH BODY
```

Shows:

- attacker IP
- endpoint attacked
- raw XSS payload

---

## **2. SQL Injection Detection**

```
index=* sourcetype=vulnweb_post
| where like(BODY,"% OR 1=1%")
   OR like(BODY,"%UNION SELECT%")
   OR like(BODY,"%--%")
| table _time IP PATH BODY
```

---

## **3. Login Brute Force Detection**

```
index=* sourcetype=vulnweb_post PATH="/login"
| stats count as attempts by IP
| where attempts > 5
```

---

## **4. Directory Enumeration Detection**

```
index=* sourcetype=access_combined status=404
| stats count by clientip
| where count > 50
```

---

## **5. Top Attacking IPs**

```
index=* sourcetype=vulnweb_post
| stats count by IP
| sort - count
```

---

## **6. Live Event Timeline**

```
index=* (sourcetype=vulnweb_post OR sourcetype=access_combined)
| timechart span=30s count
```

This creates a dynamic timeline of all malicious activity.

# Final Splunk Dashboard

![image.png](attachment:7d3fdc6f-f882-4a31-a645-ac8d6796878e:image.png)

![image.png](attachment:54dfa4cd-921c-492b-a77d-4b15d4c43c31:image.png)

# **Result: A Fully Functional Detection Engineering Lab**

This project simulates the real workflow of a SOC analyst:

1. Attacker launches multi-stage attacks from Kali
2. Web server logs each event
3. Custom POST-body logging captures hidden payloads
4. Splunk ingests all logs in real time
5. Field extraction breaks them into IP, PATH, BODY
6. Detection rules reveal XSS, SQLi, brute-force, and enumeration
7. Dashboards visualize attacks with timelines and summaries
8. A correlated kill-chain view shows full attacker behavior

It’s a complete lifecycle — from exploit → log → detection → analysis.
