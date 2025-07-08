# ZoneShah - Zone Transfer Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ZoneShah** is a professional and powerful domain zone transfer vulnerability scanner developed by Shahwar Shah. It is designed to efficiently detect vulnerable domains allowing DNS zone transfers, a critical security misconfiguration. The tool provides colorful, clear, and user-friendly output, helping security researchers and pentesters identify and report zone transfer vulnerabilities quickly.

---

## Features

- Scan a single domain or a list of domains from a file.
- Supports verbose mode (`-v`) to track detailed scanning process.
- Always shows both successful and failed zone transfer attempts.
- High accuracy with no false positives or false negatives.
- Only displays vulnerable domains prominently.
- Graceful exit on Ctrl+C.
- Developed with ❤️ by Shahwar Shah.
- Colorful terminal output for better readability.

---

## Installation

### Prerequisites

- Python 3.6 or higher
- `pip` package manager

### Install dependencies

```bash
pip install dnspython termcolor
Usage
bash
Copy
Edit
usage: scanner.py [-h] [-u DOMAIN] [-f FILE] [-v]

ZoneShah - Zone Transfer Vulnerability Scanner by Shahwar Shah

optional arguments:
  -h, --help            show this help message and exit
  -u DOMAIN             Scan a single domain
  -f FILE               Scan a list of domains from file
  -v, --verbose         Enable verbose output to show scan progress
Examples
Scan a single domain quietly:

bash
Copy
Edit
python3 scanner.py -u example.com
Scan a single domain with verbose output:

bash
Copy
Edit
python3 scanner.py -u example.com -v
Scan multiple domains from a file quietly:

bash
Copy
Edit
python3 scanner.py -f domains.txt
Scan multiple domains with verbose output:

bash
Copy
Edit
python3 scanner.py -f domains.txt -v
How it Works
ZoneShah fetches the authoritative name servers (NS records) for each domain and attempts a DNS zone transfer (AXFR) from those NS servers. If the zone transfer is successful, it indicates a serious vulnerability that could expose the entire DNS zone data.

Contribution
Contributions, issues, and feature requests are welcome! Feel free to check issues and submit pull requests.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Appreciation
Thank you for using ZoneShah! Your support and feedback keep this project alive and growing.
Developed with ❤️ by Shahwar Shah.

Contact
GitHub: https://github.com/yourusername/ZoneShah

Email: sshahwar2007@gmail.com
