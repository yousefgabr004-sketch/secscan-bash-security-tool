# SecScan - Bash Security Assessment Tool

## Overview

SecScan is a Bash-based automated security assessment tool designed
for authorized and isolated lab environments.

The tool performs reconnaissance, port and service enumeration,
service-specific security checks, and generates structured reports.

---

## Features

- Target availability check using Ping
- TCP port and service scanning using Nmap
- Service and version detection
- FTP anonymous login check
- SSH banner/version check
- HTTP enumeration
- SMB share enumeration
- SMTP service detection
- DNS service detection
- Evidence-based security findings
- Risk descriptions and recommendations
- Structured security reports
- Error handling
- `--help` and `--version` options

---

## Requirements

The following tools should be installed:

- Bash
- Nmap
- Curl
- Ping

---

## Usage

Make the script executable:

```bash
chmod +x secscan.sh
