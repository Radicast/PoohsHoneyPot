import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import random
import string
import json
import datetime
import os
import psutil  # Add at the top with other imports

# Cryptography imports for key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from twisted.cred import checkers, portal
from twisted.conch import avatar, recvline, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, connection, transport, keys, session
from twisted.conch.insults import insults
from twisted.internet import reactor, defer

# Threat level definitions
THREAT_LEVELS = {
    "High": ["rm", "shutdown", "reboot"],
    "Medium": ["nmap", "wget", "curl"],
    "Low": ["ping"]
}

# Virtual FileSystem Class
class VirtualFileSystem:
    # List of realistic directory names
    REAL_DIR_NAMES = [
        "Documents", "Downloads", "Pictures", "Music", "Videos", "Desktop",
        "Program Files", "Windows", "Users", "AppData", "System32", "Temp",
        "Public", "Work", "Projects", "Backup", "Logs", "Config", "Data", "Scripts"
    ]

    def __init__(self):
        self.root = {'type': 'dir', 'contents': {}}
        self.current_path = ['/']
        # Create 10 realistic directories at each level, depth 2
        self.generate_realistic_directories(self.root, depth=2, num_dirs=10)
        self.start_random_updates()

    def generate_realistic_directories(self, node, depth, num_dirs):
        if depth == 0:
            return
        # Randomly select directory names for this level
        dir_names = random.sample(self.REAL_DIR_NAMES, min(num_dirs, len(self.REAL_DIR_NAMES)))
        for dir_name in dir_names:
            node['contents'][dir_name] = {'type': 'dir', 'contents': {}}
            self.generate_realistic_directories(node['contents'][dir_name], depth - 1, num_dirs)

    def start_random_updates(self, interval=60):
        def update_fs():
            while True:
                time.sleep(interval)
                self.root = {'type': 'dir', 'contents': {}}
                self.generate_realistic_directories(self.root, depth=2, num_dirs=10)
                print("Filesystem updated.")
        threading.Thread(target=update_fs, daemon=True).start()

# HoneyPotProtocol
class HoneyPotProtocol(recvline.HistoricRecvLine):
    def __init__(self, user, ui):
        self.user = user
        self.vfs = VirtualFileSystem()
        self.client_ip = None
        self.ui = ui

    def connectionMade(self):
        self.client_ip = self.terminal.transport.getPeer().host
        self.ui.update_log(f"[CONNECT] Connection from {self.client_ip}")
        recvline.HistoricRecvLine.connectionMade(self)
        self.terminal.write(f"Welcome to the honeypot, {self.user.username}!\n")
        self.display_prompt()

    def connectionLost(self, reason):
        self.ui.update_log(f"[DISCONNECT] {self.client_ip} disconnected: {reason}")
        recvline.HistoricRecvLine.connectionLost(self, reason)

    def display_prompt(self):
        pwd = '/'.join(self.vfs.current_path) or '/'
        self.terminal.write(f"{self.user.username}@honeypot:{pwd}$ ")

    def lineReceived(self, line):
        command = line.strip()
        if command == '':
            self.display_prompt()
            return
        self.handle_command(command)
        self.display_prompt()

    def handle_command(self, command):
        log_message = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event": "command_received",
            "username": self.user.username,
            "command": command,
            "client_ip": self.client_ip,
        }
        self.log_event(log_message)
        self.ui.update_log(f"Command received: {command} from {self.client_ip}")

        threat_level, message = self.detect_threat(command, self.client_ip)
        if threat_level in ["Medium", "High"]:
            self.notify_threat(threat_level, f"Command from {self.client_ip}", message)
            if threat_level == "High":
                self.block_ip(self.client_ip)

        parts = command.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == 'ls':
            self.handle_ls(args)
        elif cmd == 'cd':
            self.handle_cd(args)
        elif cmd == 'pwd':
            self.handle_pwd()
        elif cmd == 'mkdir':
            self.handle_mkdir(args)
        elif cmd == 'help':
            self.handle_help()
        else:
            self.terminal.write(f"bash: {cmd}: command not found\n")

    def handle_ls(self, args):
        node = self.get_current_node()
        contents = node['contents'].keys()
        self.terminal.write('  '.join(contents) + '\n')

    def handle_cd(self, args):
        if len(args) != 1:
            self.terminal.write("Usage: cd <directory>\n")
            return
        dirname = args[0]
        if dirname == '..':
            if len(self.vfs.current_path) > 1:
                self.vfs.current_path.pop()
        else:
            node = self.get_current_node()
            if dirname in node['contents'] and node['contents'][dirname]['type'] == 'dir':
                self.vfs.current_path.append(dirname)
            else:
                self.terminal.write(f"bash: cd: {dirname}: No such file or directory\n")

    def handle_pwd(self):
        pwd = '/'.join(self.vfs.current_path) or '/'
        self.terminal.write(pwd + '\n')

    def handle_mkdir(self, args):
        if len(args) != 1:
            self.terminal.write("Usage: mkdir <directory>\n")
            return
        dirname = args[0]
        node = self.get_current_node()
        if dirname in node['contents']:
            self.terminal.write(f"mkdir: cannot create directory ‘{dirname}’: File exists\n")
        else:
            node['contents'][dirname] = {'type': 'dir', 'contents': {}}

    def handle_help(self):
        self.terminal.write("Available commands: ls, cd, pwd, mkdir, help\n")

    def get_current_node(self):
        node = self.vfs.root
        for part in self.vfs.current_path[1:]:
            node = node['contents'][part]
        return node

    def log_event(self, message):
        with open("honeypot.log", 'a') as log_file:
            log_file.write(json.dumps(message) + '\n')

    def detect_threat(self, command, client_ip):
        cmd = command.split()[0]
        for level, cmds in THREAT_LEVELS.items():
            if cmd in cmds:
                return level, f"Suspicious command '{cmd}' from {client_ip}"
        return "Low", "No threat detected"

    def notify_threat(self, level, title, message):
        print(f"[ALERT] {title}: {message}")

    def block_ip(self, ip):
        print(f"[BLOCK] Blocking IP: {ip}")

# Avatar and Realm
class HoneyPotAvatar(avatar.ConchUser):
    def __init__(self, username, ui):
        super().__init__()
        self.username = username
        self.channelLookup.update({b'session': session.SSHSession})
        self.ui = ui

class HoneyPotRealm:
    def __init__(self, ui):
        self.ui = ui

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            self.ui.update_log(f"[AUTH] User '{avatarId}' authenticated successfully")
            user = HoneyPotAvatar(avatarId, self.ui)
            return conchinterfaces.IConchUser, user, lambda: None
        self.ui.update_log(f"[AUTH FAIL] Unsupported interface for user '{avatarId}'")
        raise Exception("No supported interface")

# SSH Factory with key generation/loading
class HoneypotFactory(factory.SSHFactory):
    def __init__(self, ui):
        self.ui = ui
        self.portal = portal.Portal(HoneyPotRealm(ui))
        self.portal.registerChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse(
            honeypot='password'
        ))

        key_path = "server_rsa.key"
        if not os.path.exists(key_path):
            self.generate_host_key(key_path)

        with open(key_path, "rb") as f:
            key_data = f.read()
            self.privateKeys = {b'ssh-rsa': keys.Key.fromString(data=key_data)}
            self.publicKeys = {b'ssh-rsa': self.privateKeys[b'ssh-rsa'].public()}

    def generate_host_key(self, path):
        print("[INFO] Generating new RSA host key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(path, "wb") as f:
            f.write(private_bytes)

    def buildProtocol(self, addr):
        self.ui.update_log(f"[CONNECT ATTEMPT] Incoming connection from {addr.host}")
        return factory.SSHFactory.buildProtocol(self, addr)

# GUI Class
class HoneyPotUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeypot Monitor")

        self.status_label = tk.Label(root, text="Honeypot Status: Stopped", font=("Helvetica", 14))
        self.status_label.pack(pady=10)

        # Add a dedicated memory usage label
        self.memory_label = tk.Label(root, text="Memory Usage: -- MB", font=("Helvetica", 12), fg="blue")
        self.memory_label.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(root, width=60, height=15, wrap=tk.WORD)
        self.log_text.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Honeypot", command=self.start_honeypot)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Honeypot", command=self.stop_honeypot, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.monitor_memory_usage()

    def monitor_memory_usage(self):
        def update_memory():
            while True:
                process = psutil.Process(os.getpid())
                mem_mb = process.memory_info().rss / (1024 * 1024)
                # Update the memory label instead of logging
                self.memory_label.config(text=f"Memory Usage: {mem_mb:.2f} MB")
                time.sleep(10)
        threading.Thread(target=update_memory, daemon=True).start()

    def start_honeypot(self):
        self.status_label.config(text="Honeypot Status: Running")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.run_honeypot, daemon=True).start()

    def stop_honeypot(self):
        self.status_label.config(text="Honeypot Status: Stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        # reactor.stop() from another thread is complicated; skipping graceful shutdown here.

    def update_log(self, message):
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.yview(tk.END)

    def run_honeypot(self):
        try:
            factory = HoneypotFactory(self)
            reactor.listenTCP(2222, factory)
            self.update_log("[INFO] Honeypot SSH server listening on port 2222")
            reactor.run(installSignalHandlers=0)
        except Exception as e:
            self.update_log(f"[ERROR] Failed to start honeypot: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = HoneyPotUI(root)
    root.mainloop()

