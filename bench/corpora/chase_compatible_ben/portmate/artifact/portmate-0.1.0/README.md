# PortMate 🔌

A powerful and intuitive CLI tool to check ports, find processes, and manage port usage. Your friendly port management companion!

[![PyPI version](https://badge.fury.io/py/portmate.svg)](https://badge.fury.io/py/portmate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why PortMate?

Every developer has faced this:
- 🚫 "Port 3000 is already in use"
- 🤔 "What process is using this port?"
- 😤 "How do I kill that process?"
- 🔍 "Which ports are currently listening?"

**PortMate solves all of this with simple, memorable commands.**

## Installation

```bash
pip install portmate
```

## Quick Start

```bash
# Check if a port is in use
portmate 3000

# Check multiple ports at once
portmate 3000 8080 5432

# Kill the process using a port
portmate --kill 3000

# List all listening ports
portmate --list

# Find an available port
portmate --find 3000

# Scan common ports
portmate --scan
```

## Features

### ✅ Check Ports
Instantly see if a port is in use and what's using it:

```bash
portmate 3000
```

Output:
```
● Port 3000 is IN USE
Status: LISTEN
PID: 12345
Process: node
User: nikhilesh
```

### 🔪 Kill Processes
Stop processes by port number:

```bash
portmate --kill 3000
```

With force kill:
```bash
portmate --kill 3000 --force
```

Skip confirmation:
```bash
portmate --kill 3000 --yes
```

### 📋 List All Ports
See everything that's listening:

```bash
portmate --list
```

Output:
```
Port    Service              Process    PID
------  -------------------  ---------  ------
3000    Node.js Dev Server   node       12345
5432    PostgreSQL           postgres   8901
8080    HTTP Alt             python     23456
```

### 🔍 Scan Ports
Scan a range of ports:

```bash
# Scan default range (1-10000)
portmate --scan

# Scan custom range
portmate --scan --start 3000 --end 4000
```

### 🎯 Find Available Ports
Find the next available port:

```bash
# Find available port starting from 3000
portmate --find 3000

# Check preferred port, find alternative if taken
portmate --find 3000 --preferred 3000
```

### 📊 Verbose Mode
Get detailed process information:

```bash
portmate 3000 --verbose
```

Output includes:
- Full executable path
- Process start time
- Complete command line
- Process status

## Command Reference

### Basic Commands

| Command | Description |
|---------|-------------|
| `portmate PORT` | Check if port is in use |
| `portmate PORT1 PORT2 ...` | Check multiple ports |
| `portmate --list` | List all listening ports |
| `portmate --scan` | Scan common ports (1-10000) |
| `portmate --kill PORT` | Kill process using port |
| `portmate --find START` | Find available port |

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Show detailed information |
| `--force` | `-f` | Force kill process (SIGKILL) |
| `--yes` | `-y` | Skip confirmation prompts |
| `--start N` | | Start port for scanning |
| `--end N` | | End port for scanning |
| `--preferred PORT` | | Preferred port (with --find) |
| `--version` | | Show version |

### Shortcut Alias

Use `pm` as a shortcut:

```bash
pm 3000
pm --list
pm --kill 8080
```

## Use Cases

### Web Development
```bash
# Check if your dev server port is free
portmate 3000 3001 8080

# Kill the old dev server
portmate --kill 3000

# Find next available port for new service
portmate --find 3000
```

### Database Management
```bash
# Check database ports
portmate 5432 3306 27017

# See all database processes
portmate --list --verbose
```

### System Administration
```bash
# Scan for open ports
portmate --scan --start 1 --end 1024

# List all services
portmate --list
```

### CI/CD & Testing
```bash
# Find available port for test server
PORT=$(portmate --find 8000)

# Clean up test processes
portmate --kill 8000 --yes
```

## Python API

Use PortMate in your Python scripts:

```python
from portmate import check_port, kill_process_by_port, scan_ports

# Check a port
result = check_port(3000)
if result['in_use']:
    print(f"Port is used by: {result['name']}")

# Kill a process
success, message = kill_process_by_port(3000)

# Scan ports
used_ports = scan_ports(start_port=3000, end_port=4000)
```

## Requirements

- Python 3.7+
- psutil >= 5.9.0
- colorama >= 0.4.6
- tabulate >= 0.9.0

## Platform Support

- ✅ macOS
- ✅ Linux
- ✅ Windows

## Common Ports Reference

PortMate recognizes common services:

| Port | Service |
|------|---------|
| 80 | HTTP |
| 443 | HTTPS |
| 22 | SSH |
| 3000 | Node.js/React Dev |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8080 | HTTP Proxy |
| 27017 | MongoDB |

## Troubleshooting

### Permission Denied
Some operations require elevated privileges:

```bash
sudo portmate --kill 80
```

### Port Still in Use After Kill
Try force kill:

```bash
portmate --kill 3000 --force
```

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details.

## Author

**Nikhilesh Bezawada**
- Email: siddunikhilesh517@gmail.com
- GitHub: [@siddu2402](https://github.com/siddu2402)

## Acknowledgments

Built with:
- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process utilities
- [colorama](https://github.com/tartley/colorama) - Colored terminal output
- [tabulate](https://github.com/astanin/python-tabulate) - Pretty tables

---

**Like this tool? Star it on GitHub! ⭐**
