# PasswordsSniffer

## Description
This module sniff username and password of unprotected protocols.

## Requirements
This package require:
 - python3
 - python3 Standard Library
 - Scapy

## Installation
```bash
pip install PasswordsSniffer
```

## Usages

### Command line

```bash
PasswordsSniffer
python3 -m PasswordsSniffer
python3 PasswordsSniffer.pyz

PasswordsSniffer test                        # test all available class
PasswordsSniffer -i "localhost"              # change iface
PasswordsSniffer --iface "localhost"         # change iface
PasswordsSniffer -P 2323                     # Add analysis on server response on port 2323
PasswordsSniffer --add-response-ports 2323   # Add analysis on server response on port 2323
PasswordsSniffer -p 8080                     # Add analysis on client request on port 8080
PasswordsSniffer --add-request-ports 8080    # Add analysis on client request on port 8080
PasswordsSniffer --add-string "Password: "   # Detect a packet if "Password: " is in TCP Raw content 
PasswordsSniffer -s "Password: "             # Detect a packet if "Password: " is in TCP Raw content
PasswordsSniffer -l 20                       # Change log level
PasswordsSniffer --log-level 20              # Change log level
```

### Python script

```python
from PasswordsSniffer import *
sniffer = SnifferAll()
sniffer.start()
```

```python
import PasswordsSniffer
from scapy.all import TCP

class CustomSniffer(PasswordsSniffer.SnifferTelnet):

    def __init__(self):
        super().__init__()

        self.ports = [2323]
        self.protocol = TCP
        self.strings = [b'Password: ']
        self.regexs = [r'\w:\s?$'.encode()]
        self.request_detection_ports = self.ports
        self.response_detection_ports = self.ports

sniffer = CustomSniffer()
sniffer.start()
```

## Links
 - [Pypi](https://pypi.org/project/PasswordsSniffer)
 - [Github](https://github.com/mauricelambert/PasswordsSniffer)
 - [Documentation](https://mauricelambert.github.io/info/python/security/PasswordsSniffer.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/PasswordsSniffer.pyz)

## License
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).