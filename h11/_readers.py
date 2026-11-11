# Code to read HTTP data
#
# Strategy: each reader is a callable which takes a ReceiveBuffer object, and
# either:
# 1) consumes some of it and returns an Event
# 2) raises a LocalProtocolError (for consistency -- e.g. we call validate()
#    and it might raise a LocalProtocolError, so simpler just to always use
#    this)
# 3) returns None, meaning "I need more data"
#
# If they have a .read_eof attribute, then this will be called if an EOF is
# received -- but this is optional. Either way, the actual ConnectionClosed
# event will be generated afterwards.
#
# READERS is a dict describing how to pick a reader. It maps states to either:
# - a reader
# - or, for body readers, a dict of per-framing reader factories

import re
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    Union,
)

from ._abnf import (
    chunk_header,
    chunk_header_strict,
    header_field,
    request_line,
    status_line,
)
from ._events import Data, EndOfMessage, InformationalResponse, Request, Response
from ._headers import _validate_content_length
from ._receivebuffer import ReceiveBuffer
from ._state import (
    CLIENT,
    CLOSED,
    DONE,
    IDLE,
    MUST_CLOSE,
    SEND_BODY,
    SEND_RESPONSE,
    SERVER,
)
from ._util import LocalProtocolError, RemoteProtocolError, Sentinel, validate

__all__ = ["READERS"]

header_field_re = re.compile(header_field.encode("ascii"))
chunk_header_strict_re = re.compile(chunk_header_strict.encode("ascii"))
obs_fold_re = re.compile(rb"[ \t]+")

# Fields that are forbidden in a trailer section. Processing these as if they
# had appeared in the header section can change how the *next* message on a
# keep-alive connection is framed, which is a classic request-smuggling trick.
_FORBIDDEN_TRAILER_FIELDS = frozenset(
    {b"host", b"content-length", b"transfer-encoding"}
)


def _obsolete_line_fold(
    lines: Iterable[bytes], *, strict: bool = False
) -> Iterable[bytes]:
    it = iter(lines)
    last: Optional[bytes] = None
    for line in it:
        match = obs_fold_re.match(line)
        if match:
            if strict:
                raise LocalProtocolError(
                    "obsolete line folding is not allowed in strict mode: {!r}".format(
                        bytes(line)
                    )
                )
            if last is None:
                raise LocalProtocolError("continuation line at start of headers")
            if not isinstance(last, bytearray):
                # Cast to a mutable type, avoiding copy on append to ensure O(n) time
                last = bytearray(last)
            last += b" "
            last += line[match.end() :]
        else:
            if last is not None:
                yield last
            last = line
    if last is not None:
        yield last


def _decode_header_lines(
    lines: Iterable[bytes],
    *,
    strict: bool = False,
) -> Iterable[Tuple[bytes, bytes]]:
    for line in _obsolete_line_fold(lines, strict=strict):
        matches = validate(header_field_re, line, "illegal header line: {!r}", line)
        yield (matches["field_name"], matches["field_value"])


def _validate_strict_request_headers(headers: Iterable[Tuple[bytes, bytes]]) -> None:
    """Apply request-framing checks that are too strict for the default mode.

    The goal is to reject any request whose boundaries different HTTP
    implementations could interpret differently (and thus smuggle a second
    request through a shared connection).
    """
    content_length_values: List[bytes] = []
    saw_transfer_encoding = False
    for name, value in headers:
        lower_name = name.lower()
        if lower_name == b"content-length":
            content_length_values.append(value)
            # A single field carrying a comma-separated list is just another
            # way of declaring multiple lengths. Reject it instead of picking
            # one of them.
            if b"," in value:
                raise LocalProtocolError(
                    "multiple Content-Length values in request: {!r}".format(value)
                )
            _validate_content_length(value)
        elif lower_name == b"transfer-encoding":
            saw_transfer_encoding = True
    if len(content_length_values) > 1:
        raise LocalProtocolError(
            "duplicate Content-Length headers in strict request: {!r}".format(
                content_length_values
            )
        )
    if content_length_values and saw_transfer_encoding:
        raise LocalProtocolError(
            "strict request mixes Transfer-Encoding and Content-Length: {!r}".format(
                content_length_values
            )
        )


def _validate_strict_trailer_headers(headers: Iterable[Tuple[bytes, bytes]]) -> None:
    for name, value in headers:
        if name.lower() in _FORBIDDEN_TRAILER_FIELDS:
            raise LocalProtocolError(
                "forbidden trailer field {!r}: {!r}".format(name, value)
            )


request_line_re = re.compile(request_line.encode("ascii"))


def maybe_read_from_IDLE_client(
    buf: ReceiveBuffer, *, strict: bool = False
) -> Optional[Request]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError("illegal request line")
        return None
    if not lines:
        raise LocalProtocolError("no request line received")
    matches = validate(
        request_line_re, lines[0], "illegal request line: {!r}", lines[0]
    )
    headers = list(_decode_header_lines(lines[1:], strict=strict))
    if strict:
        _validate_strict_request_headers(headers)
    return Request(headers=headers, _parsed=True, **matches)


def maybe_read_from_IDLE_client_strict(buf: ReceiveBuffer) -> Optional[Request]:
    return maybe_read_from_IDLE_client(buf, strict=True)


status_line_re = re.compile(status_line.encode("ascii"))


def maybe_read_from_SEND_RESPONSE_server(
    buf: ReceiveBuffer,
) -> Union[InformationalResponse, Response, None]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError("illegal request line")
        return None
    if not lines:
        raise LocalProtocolError("no response line received")
    matches = validate(status_line_re, lines[0], "illegal status line: {!r}", lines[0])
    http_version = (
        b"1.1" if matches["http_version"] is None else matches["http_version"]
    )
    reason = b"" if matches["reason"] is None else matches["reason"]
    status_code = int(matches["status_code"])
    class_: Union[Type[InformationalResponse], Type[Response]] = (
        InformationalResponse if status_code < 200 else Response
    )
    return class_(
        headers=list(_decode_header_lines(lines[1:])),
        _parsed=True,
        status_code=status_code,
        reason=reason,
        http_version=http_version,
    )


class ContentLengthReader:
    def __init__(self, length: int) -> None:
        self._length = length
        self._remaining = length

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._remaining == 0:
            return EndOfMessage()
        data = buf.maybe_extract_at_most(self._remaining)
        if data is None:
            return None
        self._remaining -= len(data)
        return Data(data=data)

    def read_eof(self) -> NoReturn:
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(received {} bytes, expected {})".format(
                self._length - self._remaining, self._length
            )
        )


chunk_header_re = re.compile(chunk_header.encode("ascii"))


class ChunkedReader:
    def __init__(self, *, strict: bool = False) -> None:
        self._strict = strict
        self._bytes_in_chunk = 0
        # After reading a chunk, we have to throw away the trailing \r\n.
        # This tracks the bytes that we need to match and throw away.
        self._bytes_to_discard = b""
        self._reading_trailer = False

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._reading_trailer:
            lines = buf.maybe_extract_lines()
            if lines is None:
                return None
            headers = list(_decode_header_lines(lines, strict=self._strict))
            if self._strict:
                _validate_strict_trailer_headers(headers)
            return EndOfMessage(headers=headers)
        if self._bytes_to_discard:
            data = buf.maybe_extract_at_most(len(self._bytes_to_discard))
            if data is None:
                return None
            if data != self._bytes_to_discard[: len(data)]:
                raise LocalProtocolError(
                    f"malformed chunk footer: {data!r} (expected {self._bytes_to_discard!r})"
                )
            self._bytes_to_discard = self._bytes_to_discard[len(data) :]
            if self._bytes_to_discard:
                return None
            # else, fall through and read some more
        assert self._bytes_to_discard == b""
        if self._bytes_in_chunk == 0:
            # We need to refill our chunk count
            chunk_header = buf.maybe_extract_next_line()
            if chunk_header is None:
                return None
            if self._strict:
                matches = validate(
                    chunk_header_strict_re,
                    chunk_header,
                    "malformed chunk header in strict request: {!r}",
                    chunk_header,
                )
            else:
                matches = validate(
                    chunk_header_re,
                    chunk_header,
                    "illegal chunk header: {!r}",
                    chunk_header,
                )
            # XX FIXME: we discard chunk extensions. Does anyone care?
            self._bytes_in_chunk = int(matches["chunk_size"], base=16)
            if self._bytes_in_chunk == 0:
                self._reading_trailer = True
                return self(buf)
            chunk_start = True
        else:
            chunk_start = False
        assert self._bytes_in_chunk > 0
        data = buf.maybe_extract_at_most(self._bytes_in_chunk)
        if data is None:
            return None
        self._bytes_in_chunk -= len(data)
        if self._bytes_in_chunk == 0:
            self._bytes_to_discard = b"\r\n"
            chunk_end = True
        else:
            chunk_end = False
        return Data(data=data, chunk_start=chunk_start, chunk_end=chunk_end)

    def read_eof(self) -> NoReturn:
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)"
        )


class Http10Reader:
    def __call__(self, buf: ReceiveBuffer) -> Optional[Data]:
        data = buf.maybe_extract_at_most(999999999)
        if data is None:
            return None
        return Data(data=data)

    def read_eof(self) -> EndOfMessage:
        return EndOfMessage()


def expect_nothing(buf: ReceiveBuffer) -> None:
    if buf:
        raise LocalProtocolError("Got data when expecting EOF")
    return None


ReadersType = Dict[
    Union[Type[Sentinel], Tuple[Type[Sentinel], Type[Sentinel]]],
    Union[Callable[..., Any], Dict[str, Callable[..., Any]]],
]

READERS: ReadersType = {
    (CLIENT, IDLE): maybe_read_from_IDLE_client,
    (SERVER, IDLE): maybe_read_from_SEND_RESPONSE_server,
    (SERVER, SEND_RESPONSE): maybe_read_from_SEND_RESPONSE_server,
    (CLIENT, DONE): expect_nothing,
    (CLIENT, MUST_CLOSE): expect_nothing,
    (CLIENT, CLOSED): expect_nothing,
    (SERVER, DONE): expect_nothing,
    (SERVER, MUST_CLOSE): expect_nothing,
    (SERVER, CLOSED): expect_nothing,
    SEND_BODY: {
        "chunked": ChunkedReader,
        "content-length": ContentLengthReader,
        "http/1.0": Http10Reader,
    },
}
