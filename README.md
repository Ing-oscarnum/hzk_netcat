# HZK_NetCat 🔐

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Requirements](https://img.shields.io/badge/dependencies-see%2520requirements.txt-orange)

**Secure bidirectional file transfer and remote command execution tool** designed for ethical hacking and authorized penetration testing.

## 📌 Features
- **AES-256 Encryption**: Secure CBC mode with auto-generated keys
- **Cross-Platform**: Works on Linux, Windows, and macOS
- **Multi-Functional**:
  - Remote command execution
  - File upload/download
  - Encrypted bidirectional communication
- **Zero Config**: Server auto-generates cryptographic keys

## 🚀 Quick Start

### Prerequisites
```bash
pip install cryptography
```

## 📝 Use

### Server Mode
bash  
python3 hzk_netcat.py -l -p 53  
Output:

text  
[+] GENERATED KEY (SAVE THIS):  
    X8@kP+2^qY4%zL9=  
[!] This key will NOT be shown again  
[*] Listening on 0.0.0.0:53...  

### Client Mode
bash  
python3 hzk_netcat.py -t <SERVER_IP> -p 53 --key "X8@kP+2^qY4%zL9="

📖 Usage Examples
Command	                                                                Description
python3 hzk_netcat.py -t 192.168.1.100 -p 53 -u=file.txt --key "KEY"    Upload file
python3 hzk_netcat.py -t 192.168.1.100 -p 53 -d=remote.txt --key "KEY"  Download file
> ls    	                                                                Execute remote command

## ⚠️ Security Disclaimer
❗ Legal Use Only:
Authorized penetration testing  
Cybersecurity education  
Ethical hacking practice  

By using this tool, you agree to:
✔️ Obtain proper authorization  
✔️ Comply with all applicable laws  
✔️ Accept full responsibility for your actions  

## 🛠️ Technical Specifications
Component	    Details  
Encryption	    AES-256-CBC + PKCS7 padding  
Key Size	256-bit (SHA-256 derived)  
Default Port	53  (Customizable with -p)  
Buffer Size	    4096 bytes  

## 📂 Project Structure
📦 hzk_netcat/
├── 📜 hzk_netcat.py          # Main application  
├── 📜 README.md              # Project documentation  
├── 📜 LICENSE                # MIT License  
├── 📜 CONTRIBUTING.md        # Contribution guidelines  
└── 📜 .gitignore             # Ignored files  

## 📜 License
MIT © 2025 Oscar R. Núñez M.

