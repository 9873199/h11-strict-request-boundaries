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
    cast,
    Dict,
    Iterable,
    NoReturn,
    Optional,
    Tuple,
    Type,
    Union,
)

from ._abnf import (
    chunk_header,
    header_field,
    request_line,
    status_line,
    strict_chunk_header,
)
from ._events import Data, EndOfMessage, InformationalResponse, Request, Response
from ._headers import (
    normalize_and_validate,
    validate_strict_request_header_lines,
    validate_trailer_fields,
)
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
obs_fold_re = re.compile(rb"[ \t]+")


def _obsolete_line_fold(
    lines: Iterable[bytes], strict: bool = False
) -> Iterable[bytes]:
    it = iter(lines)
    last: Optional[bytes] = None
    for line in it:
        match = obs_fold_re.match(line)
        if match:
            if strict:
                # RFC 9112 section 2.2: line folding is deprecated and a
                # recipient that acts as a gateway MUST either reject the
                # message or replace each received obs-fold with one SP.
                # Gateways get safer behavior by rejecting outright --
                # accepting folded framing headers is a classic smuggling
                # divergence.
                raise LocalProtocolError(
                    "obsolete header line folding is not allowed "
                    "with strict request boundaries"
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
    lines: Iterable[bytes], strict: bool = False
) -> Iterable[Tuple[bytes, bytes]]:
    for line in _obsolete_line_fold(lines, strict=strict):
        matches = validate(header_field_re, line, "illegal header line: {!r}", line)
        yield (matches["field_name"], matches["field_value"])


request_line_re = re.compile(request_line.encode("ascii"))


def maybe_read_from_IDLE_client(
    buf: ReceiveBuffer, strict: bool = False
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
    if strict:
        # maybe_extract_lines yields bytearrays; copy into plain bytes for
        # the strict validation path so its types stay narrow.
        header_lines = [bytes(line) for line in lines[1:]]
        # Run the strict framing rules (single unambiguous Content-Length,
        # ...) before the Request event ever exists, so an ambiguous message
        # can never be handed to downstream code. The raw-line check comes
        # after the folding check so a folded header reports the fold rather
        # than a confusing length error.
        raw_headers = list(_decode_header_lines(header_lines, strict=True))
        validate_strict_request_header_lines(header_lines)
        headers = normalize_and_validate(raw_headers, _parsed=True, strict=True)
    else:
        raw_headers = list(_decode_header_lines(lines[1:]))
        headers = normalize_and_validate(raw_headers, _parsed=True)
    return Request(headers=headers, _parsed=True, **matches)


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
strict_chunk_header_re = re.compile(strict_chunk_header.encode("ascii"))


class ChunkedReader:
    def __init__(self, strict: bool = False) -> None:
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
            if self._strict:
                trailer_lines = [bytes(line) for line in lines]
                trailer_headers = list(
                    _decode_header_lines(trailer_lines, strict=True)
                )
                end_of_message = EndOfMessage(headers=trailer_headers)
                # Framing/routing fields are rejected here even though they
                # would survive ordinary header normalization.
                validate_trailer_fields(end_of_message.headers)
                return end_of_message
            return EndOfMessage(headers=list(_decode_header_lines(lines)))
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
                # No chunk extensions and no trailing OWS: the only accepted
                # shape is "<hex-size>\r\n". Anything else is rejected before
                # we interpret the size, so a proxy and this parser cannot
                # disagree about where the chunk data starts.
                matches = validate(
                    strict_chunk_header_re,
                    bytes(chunk_header),
                    "illegal chunk header: {!r}",
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


# Factories for the strict request-boundary mode. They take no arguments and
# return a reader callable, matching the shape of the SEND_BODY factories so
# Connection can pick them through a single code path.
def _strict_IDLE_client_reader() -> Callable[[ReceiveBuffer], Optional[Request]]:
    def read(buf: ReceiveBuffer) -> Optional[Request]:
        return maybe_read_from_IDLE_client(buf, strict=True)

    return read


def _strict_chunked_reader() -> ChunkedReader:
    return ChunkedReader(strict=True)


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

# Strict counterparts: only the readers that see inbound client requests and
# request bodies differ. Responses keep the historical lenient behavior.
_strict_body_readers: Dict[str, Callable[..., Any]] = dict(
    cast(Dict[str, Callable[..., Any]], READERS[SEND_BODY])
)
_strict_body_readers["chunked"] = _strict_chunked_reader

STRICT_READERS: ReadersType = {
    **READERS,
    (CLIENT, IDLE): _strict_IDLE_client_reader(),
    SEND_BODY: _strict_body_readers,
}
