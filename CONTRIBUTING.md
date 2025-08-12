🛠️ How to Contribute to HZK_NetCat
First off, thank you for considering contributing to HZK_NetCat! Here's how to contribute effectively.

# Table of Contents
* [Quick Start](#-quick-start)
* [Contribution Areas](#-contribution-areas)
* [Responsible Disclosure Policy](#-responsible-disclosure-policy)


# 🚀 Quick Start  
bash
## Clone your fork
```bash
git clone https://github.com/ing-oscarnum/hzk_netcat.git 
``` 

```bash
cd hzk_netcat
```

## Install dev dependencies
```bash
pip install cryptography
```

# 🤝 Contribution Areas  

| Type        | Example Tasks                          | Code Reference          |
|-------------|----------------------------------------|-------------------------|
| Encryption  | Add AES-GCM mode                       | `crypt()` method        |
| Networking  | Improve error handling for UDP support | `listen()`, `send()`    |
| Security    | Implement key rotation                 | `generate_server_key()` |
| Testing     | Add unit tests for file transfers      | `test_upload_download.py` | 

# Responsible Disclosure Policy 🛡️   

**For security vulnerabilities**, please contact:   
📧 `ing.oscarnum+hzk_sec@gmail.com`   
🔐 **PGP Key**: [Download Public Key](https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x6256A439252153BFB4593713D8F9CA739FE7C1F2)

### Key Details
```text
Type:       ECC (Ed25519/CV25519)
Fingerprint: 6256 A439 2521 53BF B459 3713 D8F9 CA73 9FE7 C1F2
ID:         D8F9CA739FE7C1F2
Created:    2025-08-10
Expires:    2026-08-10

**What to include**:  
- Description of the vulnerability  
- Steps to reproduce (if possible)  
- Affected versions  

**Response Commitment**:  
- Acknowledgement within 48 hours  
- Patch timeline: 7-14 days for critical issues  

