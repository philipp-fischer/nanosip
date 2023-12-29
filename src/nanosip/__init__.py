"""nanosip - Simply ring a phone."""

import asyncio
import hashlib
import os
import random
import re
import string
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, NamedTuple, Optional, Union, List


class SIPError(Exception):
    """Raised when some SIP-protocol related error happens."""


class SIPAuthCreds(NamedTuple):
    """A named tuple that stores username and password for SIP authentication."""

    username: str
    password: str


class Transaction(ABC):
    """Class for a SIP transaction.

    A SIP transaction consists of a single request and any responses to
    that request, which include zero or more provisional responses and
    one or more final responses. (rfc3261#section-17).
    Note: If a request needs to be repeated for Authorization, this will
    also be handled by the same Transaction.
    """

    check_func: Optional[Callable[[], None]]
    pending_requests: list[Union[str, Any]]
    realm: Optional[str]
    nonce: Optional[str]
    errors: List[str]

    class TerminationMarker:
        """Used as a pseudo request to mark the end of a transaction.

        Note that we use the class, not an instance of it.
        """

    def __init__(
        self,
        uri_from: str,
        uri_to: str,
        uri_via: str,
        auth_creds: SIPAuthCreds,
    ) -> None:
        """Construct a Transaction object."""

        self.check_func = None  # Callback to notify Protocol of new pending requests

        self.uri_from = uri_from
        self.uri_to = uri_to
        self.uri_via = uri_via
        self.cseq = 1
        self.send_ack_unauthorized = False
        self.branch = self._generate_branch()
        self.call_id = self._generate_call_id()
        self.tag = self._generate_tag()
        self.errors = []

        self.pending_requests = []
        self.auth_creds = auth_creds
        self.realm = None
        self.nonce = None

        self.req_pending = None

        self.remaining_auth_tries = 2  # Try authorization at most 2 times.

    @abstractmethod
    def method(self) -> str:
        """Override to return the name of the implemented method."""
        raise NotImplementedError

    @abstractmethod
    def get_request(self, additional_headers: Optional[list] = None) -> str:
        """Override and return the request headers for this method."""
        raise NotImplementedError

    def get_next_request(self) -> Optional[Union[str, Any]]:
        """Return the next request this transaction wants to send if any."""

        if len(self.pending_requests) > 0:
            return self.pending_requests.pop(0)

        return None

    def handle_response(self, resp: str):
        """Upon receiving a new response, handle it."""

        status, reason, header_vals = self._parse_response_status(resp)
        if status == 401 or status == 407:  # Unauthorized
            if self.remaining_auth_tries <= 0:
                self.pending_requests.append(self.TerminationMarker)
                self.errors.append(f"{status} Unauthorized")
                raise SIPError

            self.remaining_auth_tries -= 1

            if status == 401:
                auth_header = header_vals["WWW-Authenticate"]
            else:
                auth_header = header_vals["Proxy-Authenticate"]
            match_realm = re.search(r"realm\s*=\s*\"([^\"]+)\"", auth_header)
            match_nonce = re.search(r"nonce\s*=\s*\"([^\"]+)\"", auth_header)
            assert isinstance(match_realm, re.Match), f"Cannot parse SIP realm in '{auth_header}'"
            assert isinstance(match_nonce, re.Match), f"Cannot parse SIP nonce in '{auth_header}'"
            self.realm = match_realm.group(1)
            self.nonce = match_nonce.group(1)

            # Add ACK and next request
            if self.send_ack_unauthorized:
                self.pending_requests.append(self._generate_headers(["Content-Length: 0"], method="ACK") + "\r\n\r\n")

            self.branch = self._generate_branch()
            self.cseq += 1
            auth_values = {
                "username": self.auth_creds.username,
                "realm": self.realm,
                "nonce": self.nonce,
                "uri": self.uri_to,
                "response": self._generate_authorization(self.auth_creds, self.realm, self.nonce),
            }

            if status == 401:
                auth_header_name = "Authorization"
            else:
                auth_header_name = "Proxy-Authorization"

            self.pending_requests.append(
                self.get_request(
                    [f"{auth_header_name}: Digest " + ",".join([f'{k}="{v}"' for k, v in auth_values.items()])]
                )
            )

        elif status == 487:  # Request cancelled
            # Add ACK
            self.pending_requests.append(self._generate_headers(["Content-Length: 0"], method="ACK") + "\r\n\r\n")
            # We don't store an error here, since we want to cancel the request
        elif status == 200:
            # OK
            pass
        elif status == 100:
            # Trying
            pass
        elif 180 <= status <= 183:
            # Ringing, Forwarded, Queued, Session Progress
            pass
        else:
            # Some other failure (e.g. BUSY, bad request, etc.)
            self.errors.append(f"{status} {reason}")
            raise SIPError

    def _generate_branch(self, length=32) -> str:
        branchid = "".join(random.choices(string.hexdigits, k=length - 7))
        return f"z9hG4bK{branchid}"

    def _generate_call_id(self) -> str:
        hhash = hashlib.sha256(os.urandom(32)).hexdigest()
        return f"{hhash[0:32]}"

    def _generate_tag(self) -> str:
        rand = str(os.urandom(32)).encode("utf8")
        return hashlib.md5(rand).hexdigest()[0:8]

    def _generate_headers(
        self,
        additional_headers: Optional[list] = None,
        method: Optional[str] = None,
        cseq_method: Optional[str] = None,
    ):
        if additional_headers is None:
            additional_headers = []
        if method is None:
            method = self.method()
        if cseq_method is None:
            cseq_method = method
        return "\r\n".join(
            [
                f"{method} {self.uri_to} SIP/2.0",
                f"Via: SIP/2.0/UDP {self.uri_via};rport;branch={self.branch}",
                f"To: <{self.uri_to}>",
                f"From: <{self.uri_from}>;tag={self.tag}",
                f"Contact: <{self.uri_from}>",
                f"CSeq: {self.cseq} {cseq_method}",
                f"Call-ID: {self.call_id}",
                "Max-Forwards: 70",
                "User-Agent: NanoSIP/0.1",
            ]
            + additional_headers
        )

    def _parse_response_status(self, response: str):
        lines = response.split("\r\n")
        sip_version, status_code, reason = lines[0].split(" ", maxsplit=2)
        assert sip_version == "SIP/2.0"
        header_vals = {}
        for line in lines[1:]:
            l_cont = line.strip()
            if l_cont == "":
                break
            # To be improved: This parsing is not correct. Improve
            key, val = l_cont.split(":", maxsplit=1)
            header_vals[key] = val

        return int(status_code), reason, header_vals

    def _generate_authorization(self, creds: SIPAuthCreds, realm: str, nonce: str) -> str:
        ha1 = hashlib.md5((creds.username + ":" + realm + ":" + creds.password).encode("utf8")).hexdigest()
        ha2 = hashlib.md5(("" + self.method() + ":" + self.uri_to).encode("utf8")).hexdigest()
        bytes_to_hash = (ha1 + ":" + nonce + ":" + ha2).encode("utf8")
        response = hashlib.md5(bytes_to_hash).hexdigest()
        return response


class Invite(Transaction):
    """See rfc3261#section-17.1.1."""

    def __init__(self, uri_from: str, uri_to: str, uri_via: str, auth_creds: SIPAuthCreds) -> None:
        """Construct a new Invite transaction object."""

        super().__init__(uri_from, uri_to, uri_via, auth_creds)
        self.send_ack_unauthorized = True

        self.pending_requests.append(self.get_request())

    def method(self) -> str:
        """Return that this is the INVITE method."""

        return "INVITE"

    def get_request(self, additional_headers: Optional[list] = None):
        """Generate and return the headers for an INVITE."""

        if additional_headers is None:
            additional_headers = []
        return self._generate_headers(["Content-Length: 0"] + additional_headers) + "\r\n\r\n"

    def cancel(self):
        """Cancel this INVITE."""

        self.pending_requests.append(
            self._generate_headers(["Content-Length: 0"], method="CANCEL", cseq_method="CANCEL") + "\r\n\r\n"
        )
        self.pending_requests.append(self.TerminationMarker)

        if self.check_func:
            self.check_func()


class Register(Transaction):
    """See rfc3261#section-17.1.1."""

    def __init__(
        self,
        uri_from: str,
        uri_to: str,
        uri_via: str,
        auth_creds: SIPAuthCreds,
        uri_contact: str,
    ) -> None:
        """Construct a new Register transaction object."""

        super().__init__(uri_from, uri_to, uri_via, auth_creds)
        self.uri_contact = uri_contact

        self.pending_requests.append(self.get_request())

    def method(self) -> str:
        """Return that this is the REGISTER method."""

        return "REGISTER"

    def get_request(self, additional_headers: Optional[list] = None):
        """Generate and return the headers for a REGISTER."""

        if additional_headers is None:
            additional_headers = []
        return (
            self._generate_headers(
                [f"Contact: <{self.uri_contact}>", "Expires: 60", "Content-Length: 0"] + additional_headers
            )
            + "\r\n\r\n"
        )


class TransactionProcessor:
    """Processes a given transaction and manages the connection needed for that transaction.

    Passes UDP messages in and out.
    The run method returns a list of error strings. If the list is empty, everything is ok.
    """

    transport: Optional[asyncio.DatagramTransport]

    class UDPProtocol(asyncio.DatagramProtocol):
        """Manage the UDP connection and handle incoming messages."""

        def __init__(self, transaction: Transaction, done_future) -> None:
            """Construct the UDPProtocol object."""

            self.transaction = transaction
            self.transaction.check_func = self.maybe_send_new_requests
            self.done_future = done_future
            self.transport = None

        def maybe_send_new_requests(self):
            """Send messages as long as our transaction object has new messages to send."""

            if self.done_future.done():
                return

            assert self.transport, "Need to make a connection before sending or receiving SIP datagrams."
            while True:
                next_req = self.transaction.get_next_request()
                if isinstance(next_req, str):
                    self.transport.sendto(next_req.encode())
                elif next_req is Transaction.TerminationMarker:
                    self.transport.close()
                    break
                else:
                    break

        def connection_made(self, transport):
            """Start sending messages as soon as we are connected."""

            self.transport = transport
            self.maybe_send_new_requests()

        def datagram_received(self, data, addr):
            """Handle any response we receive."""
            print("Received: ")
            print(data.decode())

            try:
                self.transaction.handle_response(data.decode())
            except SIPError:
                if self.transport:
                    self.transport.close()
                    self.transport = None
                    self.done_future.set_result(True)

            if self.transport:
                self.maybe_send_new_requests()

        def error_received(self, exc):
            """Close the connection if we receive an error."""

            if self.transport:
                self.transport.close()

            if not self.done_future.done():
                self.done_future.set_exception(exc)

        def connection_lost(self, exc):
            """If the connection is lost, let the outer loop know about it."""

            if not self.done_future.done():
                self.done_future.set_result(True)

    def __init__(self, transaction: Transaction) -> None:
        """Construct the TransactionProcessor."""

        self.transaction = transaction
        self.errors = []

    def _extract_ip(self, uri: str):
        if "@" in uri:
            return uri.split("@", maxsplit=1)[-1]

        return uri

    async def run(self):
        """Start the main loop of the transaction processor."""

        loop = asyncio.get_running_loop()
        done_future = loop.create_future()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: self.UDPProtocol(self.transaction, done_future),
            remote_addr=(self._extract_ip(self.transaction.uri_from), 5060),
        )

        udp_errors = []

        try:
            await done_future
        except OSError as e:
            # We will catch UDP Protocol related errors here.
            udp_errors = [str(e)]
        finally:
            transport.close()

        # Errors related to SIP, are stored by the Transaction object, we add them here.
        return udp_errors + self.transaction.errors


async def async_call_and_cancel(inv: Invite, duration: int):
    """Make a call and cancel it after `duration` seconds.

    Note that this simple SIP implementation is not capable of establishing
    an actual audio connection. It just rings the other phone.
    """

    tp = TransactionProcessor(inv)

    async def cancel_call(inv):
        await asyncio.sleep(duration)
        inv.cancel()

    tp_ret, _ = await asyncio.gather(tp.run(), cancel_call(inv))
    if len(tp_ret) > 0:
        raise OSError("nanosip error: " + "; ".join(tp_ret))


def call_and_cancel(inv: Invite, duration: int):
    """Make a call and cancel it after `duration` seconds.

    Note that this simple SIP implementation is not capable of establishing
    an actual audio connection. It just rings the other phone.
    """

    return asyncio.run(async_call_and_cancel(inv, duration))
