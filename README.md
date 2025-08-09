# PoohsHoneyPot

A simple SSH honeypot written in Python using Twisted and Tkinter.  
It simulates a realistic filesystem, detects suspicious commands, and provides a live GUI monitor.

## Features

- SSH honeypot server (port 2222)
- Virtual filesystem with realistic directories
- Threat detection and logging
- Tkinter GUI for live monitoring
- Auto-installs required Python packages

## Usage

1. Install Python 3.11+
2. Run the script:
   `
   python PoohsHoneyPot.py
   `
3. Use an SSH client to connect to localhost:2222 (username: honeypot, password: password)

## Requirements

- Python 3.11+
- cryptography
- twisted
- psutil

## License

MIT
