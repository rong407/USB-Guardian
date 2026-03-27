Prototype implementation outline for the **File Fingerprint → USB tracking system**. The design contains three small components:

1. **Endpoint Agent** – detects file copy to USB, generates fingerprint, embeds metadata, sends log
2. **Central Trace Server** – receives and stores logs
3. **Verify Tool** – extracts fingerprint from file and searches the central logs

The code below is a minimal working prototype suitable for demonstration.

---

# 1. Endpoint Agent (Python)

Responsibilities:

* Detect files copied to USB
* Generate SHA256 hash
* Create fingerprint
* Embed metadata
* Send log to server

Install dependencies

```bash
pip install watchdog requests python-docx pymupdf pillow openpyxl
```

### endpoint_agent.py

```python
import os
import hashlib
import json
import socket
import getpass
import datetime
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SERVER_URL = "http://127.0.0.1:8000/log"

USB_PATH = "E:\\"   # example USB drive

def sha256(file_path):
    h = hashlib.sha256()
    with open(file_path,'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def create_fingerprint(file_path):

    fingerprint = {
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "timestamp": datetime.datetime.now().isoformat(),
        "file": os.path.basename(file_path),
        "hash": sha256(file_path)
    }

    return fingerprint


def embed_metadata(file_path, fingerprint):

    try:
        with open(file_path, "ab") as f:
            tag = "\nFINGERPRINT:" + json.dumps(fingerprint)
            f.write(tag.encode())
    except:
        pass


def send_log(fp):

    try:
        requests.post(SERVER_URL, json=fp)
    except:
        print("server unreachable")


class USBMonitor(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        path = event.src_path
        print("file copied:", path)

        fp = create_fingerprint(path)

        embed_metadata(path, fp)

        send_log(fp)


if __name__ == "__main__":

    observer = Observer()
    observer.schedule(USBMonitor(), USB_PATH, recursive=False)

    observer.start()

    print("USB monitoring started")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
```

---

# 2. Central Trace Server

Lightweight API using **FastAPI**

Install

```bash
pip install fastapi uvicorn
```

### server.py

```python
from fastapi import FastAPI
from datetime import datetime
import json
import os

app = FastAPI()

LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)


@app.post("/log")
async def receive_log(data: dict):

    date = datetime.now().strftime("%Y-%m-%d")
    filename = f"{LOG_DIR}/{date}.log"

    with open(filename, "a") as f:
        f.write(json.dumps(data) + "\n")

    return {"status":"ok"}
```

Run server

```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```

Logs will be stored like:

```
logs/
  2026-03-13.log
```

Example log entry

```json
{
 "hostname":"FIN-PC01",
 "user":"somchai",
 "timestamp":"2026-03-13T10:21",
 "file":"budget.xlsx",
 "hash":"a8d9f..."
}
```

---

# 3. Verify Tool (For Investigation)

Used when a leaked file is found.

### verify_tool.py

```python
import json
import os

LOG_DIR = "logs"

def extract_fingerprint(file_path):

    with open(file_path,'rb') as f:
        data = f.read().decode(errors="ignore")

    if "FINGERPRINT:" in data:
        fp = data.split("FINGERPRINT:")[-1]
        return json.loads(fp)

    return None


def search_log(hash_value):

    for file in os.listdir(LOG_DIR):

        with open(os.path.join(LOG_DIR,file)) as f:

            for line in f:
                record = json.loads(line)

                if record["hash"] == hash_value:
                    return record

    return None


file = input("file to investigate: ")

fp = extract_fingerprint(file)

if not fp:
    print("no fingerprint found")
else:

    print("fingerprint found:", fp)

    result = search_log(fp["hash"])

    if result:
        print("SOURCE IDENTIFIED")
        print(result)
    else:
        print("log not found")
```

Example output

```
SOURCE IDENTIFIED

Hostname : FIN-PC01
User     : somchai
Time     : 2026-03-13 10:21
File     : budget.xlsx
```

---

# 4. How to Demonstrate the System (Demo Scenario)

Demo flow for presentation:

1. Insert USB
2. Copy file to USB
3. Agent detects event
4. Fingerprint embedded
5. Log sent to server
6. Later investigator runs verify tool
7. System identifies source computer

Presentation message:

> The system embeds a digital fingerprint into files copied to removable media and stores audit logs centrally. When a leaked file is discovered, the organization can trace its origin including user, machine, and timestamp.

---

# 5. Optional Improvements (If you want it to look advanced)

Add these and the project becomes **enterprise-grade cybersecurity research**

* SHA256 + HMAC signature
* Windows Service agent
* Elastic SIEM integration
* USB device ID tracking
* Dashboard (Grafana)
* Metadata embedding per format (PDF, DOCX)

---

## Demo Architecture: File Fingerprint → USB Trace System (Agent + Server)

![Image](https://www.manageengine.com/products/desktop-central/images/endpoint-central-wan-architecture.png)

![Image](https://www.cell.com/cms/10.1016/j.heliyon.2023.e13025/asset/a55b2efd-2d0b-4a20-a667-111bcb3f3b86/main.assets/gr1_lrg.jpg)

![Image](https://cdn.prod.website-files.com/601959b8cde20c101809c86a/637272b714a6b0397b02c856_Data-Exfiltration-Figure-1-800.webp)

The demonstration setup should remain simple but clearly illustrate the full pipeline: **Endpoint Agent → API Server → Log Storage → Investigation Tool**. This allows a live demo showing detection, fingerprinting, logging, and traceability.

---

# 1. High-Level Demo Architecture

```
            +------------------------------------+
            |         User Workstation           |
            |------------------------------------|
            | Endpoint Agent (Python Service)    |
            |                                    |
            | • Detect USB insertion             |
            | • Monitor file copy                |
            | • Generate SHA256 hash             |
            | • Create Digital Fingerprint       |
            | • Embed metadata into file         |
            +------------------+-----------------+
                               |
                               | REST API (JSON)
                               |
                               v
            +------------------------------------+
            |        Central Trace Server        |
            |------------------------------------|
            | FastAPI / Flask                    |
            |                                    |
            | • Receive file event logs          |
            | • Validate fingerprint             |
            | • Store audit records              |
            +------------------+-----------------+
                               |
                               |
                               v
            +------------------------------------+
            |           Log Storage              |
            |------------------------------------|
            | JSON / LOG Files                   |
            | Network Share or Local Storage     |
            |                                    |
            | Example                            |
            | /logs/2026-03-13.log               |
            +------------------+-----------------+
                               |
                               |
                               v
            +------------------------------------+
            |          Verify Tool               |
            |------------------------------------|
            | Python Investigation Tool          |
            |                                    |
            | • Read metadata from leaked file   |
            | • Extract fingerprint              |
            | • Compare with server logs         |
            | • Identify source machine/user     |
            +------------------------------------+
```

---

# 2. Data Flow During Demo

### Step 1 — User copies file

User copies

```
confidential.xlsx
```

from PC to

```
USB Flash Drive
```

---

### Step 2 — Endpoint Agent triggers

Agent detects:

```
File Write Event → Removable Drive
```

Then performs:

```
Generate SHA256
Create Fingerprint
Embed Metadata
Send Log
```

---

### Step 3 — Server receives log

Example event sent to server

```json
{
 "hostname": "FIN-PC01",
 "user": "somchai",
 "timestamp": "2026-03-13T14:20",
 "file": "confidential.xlsx",
 "hash": "fa8d23a9c..."
}
```

Server stores:

```
logs/2026-03-13.log
```

---

### Step 4 — Metadata embedded in file

File now contains metadata like

```
FingerprintID : FGP-239182
Host          : FIN-PC01
User          : somchai
Timestamp     : 2026-03-13 14:20
Hash          : fa8d23a9c...
```

---

### Step 5 — Investigation (Data Leak Case)

Security team receives leaked file.

Run:

```
verify_tool.py
```

The tool:

```
Read metadata
Extract fingerprint
Search central log
```

Result:

```
SOURCE FOUND

Machine : FIN-PC01
User    : somchai
Time    : 2026-03-13 14:20
USB     : Kingston32GB
```

---

# 3. Minimal Demo Deployment

A working demo can run on **just two machines**.

### Machine 1

Endpoint

```
Windows Laptop
Python Agent
USB Flash Drive
```

---

### Machine 2

Server

```
Linux or Windows
FastAPI Server
Log Storage
```

Run server:

```
uvicorn server:app --host 0.0.0.0 --port 8000
```

---

# 4. Recommended Demo Setup (for presentation)

```
Laptop 1
  |
  | copy file to USB
  |
Endpoint Agent running

            ↓

Laptop 2
Central Trace Server
(Log Viewer)

            ↓

Investigation Tool
(Trace leaked file)
```

This gives a **clear cybersecurity narrative**:

1. Insider copies file
2. System fingerprints the file
3. Logs stored centrally
4. Security team traces leak

---

# 5. Optional Demo Enhancements (Highly Recommended)

Add one more component to make the demo impressive.

### Real-time Dashboard

```
Agent → FastAPI → Elasticsearch → Grafana
```

Dashboard shows:

```
USB Activity
File Copy Events
Top Users Exporting Files
Suspicious Behavior
```

This transforms the project into something similar to a **commercial DLP platform**.

---

If needed, a **clean PowerPoint architecture diagram (enterprise style)** can also be generated for your presentation slides, which typically improves grading significantly.


If desired, a more advanced version can be provided:

* **Full project structure**
* **Production-style agent**
* **PowerPoint architecture slide**
* **Live demo dashboard**

This would make the project look similar to a commercial **Data Loss Prevention (DLP)** system.
