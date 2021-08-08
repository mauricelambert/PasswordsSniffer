#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module sniff username and password of unprotected protocols
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This module sniff username and password of unprotected protocols.

Protocols: FTP, Telnet, SMTP, POP3, IMAP4, HTTP, 
SNMP, LDAP, SOCKS, MSSQL, PostgreSQL, IRC, OSPF, BFD, and STUN

Version 0.0.1 available protocols: 
FTP, Telnet, SMTP, POP3, IMAP4, HTTP, IRC.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = "This module sniff username and password of unprotected protocols."
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/PasswordSniffer"

copyright = """
PasswordSniffer  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = [
    "Sniffer", 
    "SnifferAll", 
    "SnifferFTP", 
    "SnifferTelnet", 
    "SnifferSMTP", 
    "SnifferPOP3", 
    "SnifferIMAP4",
    "SnifferHTTP", 
    "SnifferIRC", 
]

print(copyright)

from scapy.all import AsyncSniffer, UDP, TCP, IP, raw, Raw, Packet, sniff
from logging import Formatter, StreamHandler, Handler, NullHandler
from argparse import ArgumentParser, Namespace
from typing import List
from re import search
import logging
import sys


class Sniffer:

    """This class sniff packets and
    return matching secrets."""

    def __init__(
        self,
        sniffer_args: dict = {"store": False},
        formatter: Formatter = None,
        handler: Handler = None,
    ):
        self.ports: List[int] = []
        self.protocol: Packet = None
        self.regexs: List[bytes] = []
        self.strings: List[bytes] = []

        self.encoding = "latin-1"
        self.sniffer_args = sniffer_args
        self.get_request: List[int] = []
        self.credentials: List[bytes] = []
        self.request_detection_ports: List[int] = []
        self.response_detection_ports: List[int] = []

        self.formatter = formatter or Formatter(
            fmt="%(asctime)s%(levelname)s(%(levelno)s) %(message)s",
            datefmt="[%Y-%m-%d %H:%M:%S] ",
        )
        self.logging_handler = handler or StreamHandler()
        handler or self.logging_handler.setFormatter(self.formatter)
        handler or self.logging_handler.setLevel(logging.NOTSET)

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(self.logging_handler)
        self.logger.setLevel(logging.NOTSET)

    def start(self) -> None:

        """This function create and launch the Sniffer."""

        sniffer = AsyncSniffer(
            lfilter=self.filter, prn=self.analysis, **self.sniffer_args
        )
        sniffer.start()

        try:
            sniffer.join()
        except KeyboardInterrupt:
            sniffer.stop()

        self.logger.removeHandler(self.logging_handler)
        del self.logger

    def filter(self, packet: Packet) -> bool:

        """Packet filter (filter on protocol and port)."""

        if (
            self.protocol in packet
            and packet.haslayer(Raw)
            and (
                packet.sport in self.response_detection_ports
                or packet.dport in self.ports
            )
        ):
            return True

        return False

    def analysis(self, packet: Packet) -> None:

        """This function call different analysis function."""

        if packet.dport in self.get_request:
            self.handle_packet(packet)

        if self.strings and self.in_strings(packet):
            self.logger.info(
                "    [-] String matching between "
                f"{packet[IP].src}:{packet[IP].sport} -> {packet[IP].dst}:{packet[IP].dport}"
            )
            self.handle_packet(packet)

        elif self.regexs and self.in_regexs(packet):
            self.logger.info(
                "    [-] Regex matching between "
                f"{packet[IP].src}:{packet[IP].sport} -> {packet[IP].dst}:{packet[IP].dport}"
            )
            self.handle_packet(packet)

    def handle_packet(self, packet: Packet) -> None:

        """This function logs credentials and detections,
        add crdentials in list and add detections."""

        data = raw(packet.lastlayer())

        if packet.dport in self.get_request:
            self.credentials.append(data)
            self.logger.critical(
                f"[+] Response: {' '.join(data.decode(self.encoding).split())} ({data})"
            )
            self.get_request.remove(packet.dport)

        if packet.sport in self.response_detection_ports:
            self.logger.warning(f"  [-] Response detection...")
            self.get_request.append(packet.sport)

        print(self.request_detection_ports)
        if packet.dport in self.request_detection_ports:
            self.credentials.append(data)
            self.logger.critical(
                f"[+] Request: {' '.join(data.decode(self.encoding).split())} ({data})"
            )

    def in_regexs(self, packet: Packet) -> bool:

        """This function checks if the packet data
        matches the predefined regex."""

        data = raw(packet.lastlayer())
        for regex in self.regexs:
            find = search(regex, data)
            if find is not None:
                self.logger.debug(f"   [*] Regex: {regex} matches with {data}")
                return True

        return False

    def in_strings(self, packet: Packet) -> bool:

        """This function checks if the packet data
        matches the predefined data."""

        data = raw(packet.lastlayer())
        return any([string in data for string in self.strings])

    def test(
        self, filenames: List[str], credentials: List[bytes], order: bool = True
    ) -> None:

        """This function test the class."""

        sniffer = AsyncSniffer(
            lfilter=self.filter, prn=self.analysis, offline=filenames
        )
        sniffer.start()

        try:
            sniffer.join()
        except KeyboardInterrupt:
            sniffer.stop()

        if order:
            assert credentials == self.credentials
            print(f"[+] {self.__class__.__name__} tested and pass !")
        else:
            assert all([c in self.credentials for c in credentials])
            print(f"[+] {self.__class__.__name__} tested and pass !")


class SnifferFTP(Sniffer):

    """This class sniff FTP password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [21]
        self.request_detection_ports = self.ports
        self.strings: List[bytes] = [b"USER ", b"PASS "]


class SnifferTelnet(Sniffer):

    """This class sniff Telnet password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [23]
        self.response_detection_ports = self.ports
        self.regexs: List[bytes] = [r"\w+:\s?$".encode()]
        # self.strings: List[bytes] = [b"login:", b"Password:"]

    def handle_packet(self, packet: Packet) -> None:

        """This function logs credentials and detections,
        add crdentials in list and add detections."""

        data = raw(packet.lastlayer())

        if packet.dport in self.get_request:
            self.current_credentials += data
        else:
            self.get_request.append(packet.sport)
            self.current_credentials = data

        if self.current_credentials.endswith(
            b"\r\n"
        ) or self.current_credentials.endswith(b"\r\x00"):

            self.credentials.append(self.current_credentials)
            self.logger.critical(
                f"[+] Request: {' '.join(self.current_credentials.decode(self.encoding).split())} ({self.current_credentials})"
            )
            self.get_request.remove(23)


class SnifferSMTP(Sniffer):

    """This class sniff SMTP password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [25]
        self.strings: List[bytes] = [b"AUTH "]
        self.request_detection_ports = self.ports

    def handle_packet(self, packet: Packet) -> None:

        """This function logs credentials and detections,
        add crdentials in list and add detections."""

        data = raw(packet.lastlayer())

        if packet.dport in self.get_request:
            self.current_credentials += data
        else:
            self.get_request.append(packet.dport)
            self.current_credentials = data

        if len(self.current_credentials.split()) == 4:
            self.credentials.append(self.current_credentials)
            self.logger.critical(
                f"[+] Request: {' '.join(self.current_credentials.decode(self.encoding).split())} ({self.current_credentials})"
            )
            self.get_request.remove(packet.dport)


class SnifferPOP3(Sniffer):

    """This class sniff POP3 password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [110]
        self.request_detection_ports = self.ports
        self.strings: List[bytes] = [b"USER ", b"PASS "]


class SnifferIMAP4(Sniffer):

    """This class sniff IMAP4 password."""

    def __init__(self):
        super().__init__()

        self.ports: List[int] = [143]
        self.strings: List[bytes] = [b"LOGIN "]
        self.request_detection_ports = self.ports
        self.protocol: Packet = TCP


class SnifferHTTP(Sniffer):

    """This class sniff HTTP password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [80]
        self.request_detection_ports = self.ports
        self.strings: List[bytes] = [b"Authorization: ", b"Cookie: "]


class SnifferIRC(Sniffer):

    """This class sniff IRC password."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [6667]
        self.request_detection_ports = self.ports
        self.strings: List[bytes] = [b"PASS ", b"USER ", b"NICK "]


class SnifferSNMP(Sniffer):

    """This class sniff SNMP password.

    unavailable."""

    def __init__(self):
        super().__init__()

        self.ports: List[int] = [161]
        self.request_detection_ports = self.ports
        self.protocol: Packet = UDP


class SnifferLDAP(Sniffer):

    """This class sniff LDAP password.

    unavailable."""

    def __init__(self):
        super().__init__()

        self.ports: List[int] = [389]
        self.request_detection_ports = self.ports
        self.protocol: Packet = TCP


class SnifferSOCKS(Sniffer):

    """This class sniff SOCKS password.

    unavailable."""


class SnifferMSSQL(Sniffer):

    """This class sniff MSSQL password.

    unavailable."""

    def __init__(self):
        super().__init__()

        self.ports: List[int] = [1433]
        self.request_detection_ports = self.ports
        self.protocol: Packet = TCP


class SnifferPostgreSQL(Sniffer):

    """This class sniff PostgreSQL password.

    unavailable."""

    def __init__(self):
        super().__init__()

        self.ports: List[int] = [5432]
        self.request_detection_ports = self.ports
        self.protocol: Packet = TCP


class SnifferOSPF(Sniffer):

    """This class sniff OSPF password.

    unavailable."""


class SnifferBFD(Sniffer):

    """This class sniff BFD password.

    unavailable."""


class SnifferSTUN(Sniffer):

    """This class sniff STDUN password.

    unavailable."""


class SnifferAll(Sniffer):

    """This class sniff FTP, Telnet, SMTP, POP3
    IMAP4, HTTP, SNMP, LDAP, SOCKS, MSSQL,
    PostgreSQL, IRC, OSPF, BFD, and STUN password.

    SNMP, LDAP, SOCKS, MSSQL, PostgreSQL,
    OSPF, BFD, and STUN is unavailable."""

    def __init__(self):
        super().__init__()

        self.protocol: Packet = TCP
        self.ports: List[int] = [21, 23, 25, 80, 110, 143, 6667]
        self.request_detection_ports = [21, 25, 80, 110, 143, 6667]
        self.response_detection_ports = [23]
        self.regexs: List[bytes] = [r"\w+:\s?$".encode()]
        self.strings: List[bytes] = [
            b"USER ",
            b"PASS ",
            b"AUTH ",
            b"NICK ",
            b"LOGIN ",
            b"Cookie: ",
            b"Authorization: ",
        ]

    def handle_packet(self, packet: Packet) -> None:

        """This function logs credentials and detections,
        add crdentials in list and add detections."""

        if packet.sport == 23 or packet.dport == 23:
            SnifferTelnet.handle_packet(self, packet)
            return

        elif packet.sport == 25 or packet.dport == 25:
            SnifferSMTP.handle_packet(self, packet)
            return

        else:
            Sniffer.handle_packet(self, packet)


def test() -> None:

    """This function launch tests."""

    logging.basicConfig(
        level=100,
        force=True,
        handlers=[NullHandler()],
    )

    telnet = SnifferTelnet()
    telnet.test(
        ["captures/telnet-cooked.pcap"],
        [b"login: fake\r\n", b"Password:user\r\n"],
    )
    telnet.credentials = []
    telnet.test(
        ["captures/telnet-raw.pcap"],
        [b'login: \xff\xfc"\xff\xfd\x01fake\r\x00', b"Password:user\r\x00"],
    )

    smtp = SnifferSMTP()
    smtp.test(
        ["captures/smtp.pcap"],
        [b"AUTH LOGIN\r\nZ3VycGFydGFwQHBhdHJpb3RzLmlu\r\ncHVuamFiQDEyMw==\r\n"],
    )

    imap = SnifferIMAP4()
    imap.test(["captures/imap.cap"], [b'a0001 LOGIN "neulingern" "XXXXXX"\r\n'])

    http = SnifferHTTP()
    http.ports = [8000]
    http.request_detection_ports = http.ports
    http.test(
        ["captures/http.pcap"],
        [
            b'POST /api/scripts/log_viewer.py HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAuthorization: Basic QWRtaW46QWRtaW4=\r\nUser-Agent: curl/7.74.0\r\nAccept: */*\r\nContent-Length: 93\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{"arguments":{"length":{"value":"10","input":false},"CRITICAL":{"value":true,"input":false}}}'
        ],
    )

    http.credentials = []
    http.test(
        ["captures/http_cookie.pcap"],
        [
            b"GET /web/ HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nReferer: http://127.0.0.1:8000/web/auth/\r\nDNT: 1\r\nConnection: keep-alive\r\nCookie: SessionID=2:54e4cffb77ec8d80ee8e766ff2bb83f555b0651d86d574f3143f32ee0311ea10c833e967f7e8f3ca50a4c95a49a150e8886e8d759d7b46019f005d635b3290df\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nCache-Control: max-age=0\r\n\r\n"
        ],
    )

    ftp = SnifferFTP()
    ftp.test(["captures/ftp.pcap"], [b"USER csanders\r\n", b"PASS echo\r\n"])

    pop3 = SnifferPOP3()
    pop3.test(
        ["captures/pop3.pcap"],
        [b"USER luguifang@prismtech.com.cn\r\n", b"PASS 123@prism\r\n"],
    )

    irc = SnifferIRC()
    irc.ports = [31337]
    irc.request_detection_ports = irc.ports
    irc.test(
        ["captures/irc.pcap"],
        [
            b"NICK Matir\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :matir\r\n",
            b"NICK andrewg\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :andrewg\r\n",
            b"NICK itsl0wk3y\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :l0w\r\n",
        ],
    )

    all_ = SnifferAll()
    all_.ports.append(8000)
    all_.request_detection_ports.append(8000)
    all_.ports.append(31337)
    all_.request_detection_ports.append(31337)
    all_.test(
        [
            "captures/telnet-cooked.pcap",
            "captures/smtp.pcap",
            "captures/imap.cap",
            "captures/http.pcap",
            "captures/ftp.pcap",
            "captures/pop3.pcap",
            "captures/irc.pcap",
        ],
        [
            b"login: fake\r\n",
            b"Password:user\r\n",
            b"AUTH LOGIN\r\nZ3VycGFydGFwQHBhdHJpb3RzLmlu\r\ncHVuamFiQDEyMw==\r\n",
            b'a0001 LOGIN "neulingern" "XXXXXX"\r\n',
            b'POST /api/scripts/log_viewer.py HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nAuthorization: Basic QWRtaW46QWRtaW4=\r\nUser-Agent: curl/7.74.0\r\nAccept: */*\r\nContent-Length: 93\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{"arguments":{"length":{"value":"10","input":false},"CRITICAL":{"value":true,"input":false}}}',
            b"USER csanders\r\n",
            b"PASS echo\r\n",
            b"USER luguifang@prismtech.com.cn\r\n",
            b"PASS 123@prism\r\n",
            b"NICK Matir\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :matir\r\n",
            b"NICK andrewg\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :andrewg\r\n",
            b"NICK itsl0wk3y\r\n",
            b"USER root-poppopret root-poppopret 10.240.0.2 :l0w\r\n",
        ],
        order=False,
    )


def port_to_int(ports: List[str]) -> None:

    """This function change a list of string to a list of port number."""

    for i, port in enumerate(ports):
        if not port.isdigit():
            print(f"ERROR: {port} is not digit (port must be a number between 0-65535)")
            sys.exit(1)

        ports[i] = port = int(port)

        if port > 65535:
            print(f"ERROR: {port} is greater than 65535")
            sys.exit(1)


def parse_args() -> Namespace:

    """This function parse command line arguments."""

    parser = ArgumentParser(
        description="This script sniff passwords (unprotected protocols)."
    )
    parser.add_argument(
        "--add-response-ports",
        "-P",
        nargs="+",
        help="Add a port to analyse the response.",
        default=[],
    )
    parser.add_argument(
        "--add-request-ports",
        "-p",
        nargs="+",
        help="Add a port to analyse the request.",
        default=[],
    )
    parser.add_argument(
        "--add-string",
        "-s",
        nargs="+",
        help="Add a string to mark the response or the request.",
        default=[],
    )
    parser.add_argument(
        "--add-regex",
        "-r",
        nargs="+",
        help="Add a regex to mark the response or the request.",
        default=[],
    )
    parser.add_argument(
        "--log-level",
        "-l",
        help="Add a regex to mark the response or the request.",
        default=0,
        type=int,
    )
    parser.add_argument(
        "--iface", "-i", help="Interface to sniff the traffic.", default=None
    )
    return parser.parse_args()


def main() -> None:

    """This function is called when this file is the main file."""

    if "test" in sys.argv:
        test()
        return

    arguments = parse_args()

    logging.basicConfig(
        level=arguments.log_level,
        force=True,
        handlers=[NullHandler()],
    )

    port_to_int(arguments.add_response_ports)
    port_to_int(arguments.add_request_ports)

    sniffer = SnifferAll()
    sniffer.ports += arguments.add_response_ports + arguments.add_request_ports
    sniffer.request_detection_ports += arguments.add_request_ports
    sniffer.response_detection_ports += arguments.add_response_ports

    sniffer.logger.warning("[*] Start sniffing...")
    try:
        sniff(
            lfilter=sniffer.filter,
            prn=sniffer.analysis,
            iface=arguments.iface,
            store=False,
        )
    except KeyboardInterrupt:
        pass

    sniffer.logger.warning("[*] End.")
    sniffer.logger.removeHandler(sniffer.logging_handler)
    del sniffer.logger


if __name__ == "__main__":
    main()
    sys.exit(0)
