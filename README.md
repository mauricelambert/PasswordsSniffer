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
```

### Python script

```python
from PasswordsSniffer import *
telnet = SnifferTelnet()
telnet.start()
```

```python
import PasswordsSniffer
from scapy.all import TCP

class CustomSniffer(PasswordsSniffer.Sniffer):

    def __init__(self):
        super().__init__()

        self.ports = [123]
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