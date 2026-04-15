# Multi-threaded TCP Port Scanner with Service Detection and Banner Grabbing

## Overview

This project is a Python-based multi-threaded TCP port scanner developed for educational and authorized security testing purposes.

It performs fast port scanning, resolves domain names to IP addresses, detects commonly associated services, attempts basic banner grabbing, and exports results into a structured CSV file for further analysis.

---

## Features

* Multi-threaded TCP port scanning for improved performance
* Domain name to IP resolution
* Configurable port range scanning
* Common service detection (HTTP, SSH, FTP, etc.)
* Basic banner grabbing for open ports
* CSV export of scan results
* Command-line interface for flexible usage

---

## Technologies Used

* Python (Standard Library)

  * socket
  * threading
  * queue
  * argparse
  * csv
  * os

---

## Project Structure

```text
port-scanner-project/
│
├── src/
│   └── port_scanner.py
│
├── output/
│   └── scan_results.csv
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/multi-threaded-tcp-port-scanner.git
cd multi-threaded-tcp-port-scanner
```

---

### 2. (Optional) Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate
```

---

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

Note: This project uses only Python standard libraries, so no external packages are required.

---

## How to Run

### Basic Usage

```bash
python src/port_scanner.py --target localhost --start-port 7995 --end-port 8005
```

---

### Scan a Domain

```bash
python src/port_scanner.py --target google.com --start-port 80 --end-port 100
```

---

### Custom Thread Count

```bash
python src/port_scanner.py --target 127.0.0.1 --start-port 1 --end-port 1000 --threads 100
```

---

### Custom Output File

```bash
python src/port_scanner.py --target localhost --start-port 1 --end-port 100 --output output/my_scan.csv
```

---

## Command-Line Arguments

| Argument     | Description                      |
| ------------ | -------------------------------- |
| --target     | Target IP address or domain name |
| --start-port | Starting port number             |
| --end-port   | Ending port number               |
| --threads    | Number of threads (default: 50)  |
| --output     | CSV output file path             |

---

## Local Testing

### Step 1: Start a Local Server

```bash
python -m http.server 8000
```

---

### Step 2: Run Scanner

```bash
python src/port_scanner.py --target localhost --start-port 7995 --end-port 8005
```

---

### Expected Output

```
Port 8000 is OPEN (Unknown Service)
   ↳ Banner: HTTP/1.0 200 OK
```

---

## Output

Scan results are:

* Displayed in the terminal
* Saved in CSV format at:

```
output/scan_results.csv
```

---

### Example CSV Output

```
target_input,resolved_ip,port,service,banner
localhost,127.0.0.1,8000,Unknown Service,HTTP/1.0 200 OK
```

---

## Important Notice (Ethical Use)

This tool is created strictly for educational and authorized security testing purposes only.

* Use only on systems you own or have explicit permission to test
* Do not scan unauthorized networks or external systems
* Misuse of this tool may violate laws and regulations

The developer assumes no responsibility for misuse of this software.

---

## Learning Outcomes

This project demonstrates practical understanding of:

* TCP/IP networking fundamentals
* Socket programming in Python
* Multi-threading for performance optimization
* Port scanning techniques
* Service identification
* Banner grabbing for reconnaissance
* Ethical and responsible use of security tools

---

## Future Improvements

* Advanced service fingerprinting
* Improved banner detection for multiple protocols
* Integration with vulnerability databases
* GUI-based interface
* Logging and reporting enhancements

---

## Author

Cybersecurity Undergraduate
Networking and Security Enthusiast
