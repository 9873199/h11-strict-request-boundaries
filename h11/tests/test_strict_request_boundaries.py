"""Protocol-security regression tests for strict request-boundary parsing.

All tests here use in-memory bytes fed to :class:`h11.Connection`; no network
or proxy is involved. The goal is to make sure that any request whose
boundaries could be interpreted differently by two HTTP implementations is
rejected deterministically, regardless of how the bytes are split when they
are handed to the parser.
"""

from typing import cast, Iterable, List, Optional, Tuple

import pytest

from .._connection import Connection, NEED_DATA, PAUSED
from .._events import (
    Data,
    EndOfMessage,
    Event,
    InformationalResponse,
    Request,
    Response,
)
from .._state import DONE, ERROR, SERVER
from .._util import RemoteProtocolError
from .helpers import normalize_data_events

# A valid request that follows the malformed one in the same received batch.
# If the bad request poisons the connection, this must never be delivered as a
# normal request.
_NEXT_REQUEST = b"GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n"


def _strict_conn() -> Connection:
    return Connection(SERVER, strict_request_boundaries=True)


# Outcome of feeding one complete input to a Connection.
_ParseResult = Tuple[List[Event], Optional[RemoteProtocolError], int]


def _consume(
    conn: Connection, data: bytes, chunks: Iterable[bytes]
) -> _ParseResult:
    """Feed *chunks* to *conn* and parse as much as possible.

    Once a RemoteProtocolError is raised we stop calling next_event, but we
    keep feeding the remaining chunks so that the reported rejection position
    can be compared across chunkings of the same input.
    """
    events: List[Event] = []
    error: Optional[RemoteProtocolError] = None
    for chunk in chunks:
        conn.receive_data(chunk)
        if error is not None:
            continue
        while True:
            try:
                event = conn.next_event()
            except RemoteProtocolError as exc:
                error = exc
                break
            if event in (NEED_DATA, PAUSED):
                break
            events.append(cast(Event, event))
    # Bytes consumed from the input form a prefix of the whole input.
    consumed = len(data) - len(conn.trailing_data[0])
    return events, error, consumed


def _chunkings(data: bytes) -> List[List[bytes]]:
    """A representative set of ways to split *data* into chunks."""
    chunkings: List[List[bytes]] = [[data]]
    chunkings.append([data[i : i + 1] for i in range(len(data))])
    for cut in {1, 2, 3, len(data) // 4, len(data) // 2, len(data) - 1}:
        if 0 < cut < len(data):
            chunkings.append([data[:cut], data[cut:]])
    first, second = len(data) // 3, 2 * len(data) // 3
    if 0 < first < second < len(data):
        chunkings.append([data[:first], data[first:second], data[second:]])
    return chunkings


def _request(header_lines: bytes) -> bytes:
    return (
        b"POST /bad HTTP/1.1\r\n"
        b"Host: bad.example\r\n" + header_lines + b"\r\n" + _NEXT_REQUEST
    )


def _bad_chunked(chunk_header_line: bytes) -> bytes:
    # chunk_header_line does not include the terminating CRLF.
    return (
        b"POST /bad HTTP/1.1\r\n"
        b"Host: bad.example\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n" + chunk_header_line + b"\r\n" + b"hello\r\n0\r\n\r\n" + _NEXT_REQUEST
    )


def _bad_trailer(trailer_lines: bytes) -> bytes:
    return (
        b"POST /bad HTTP/1.1\r\n"
        b"Host: bad.example\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nhello\r\n"
        b"0\r\n" + trailer_lines + b"\r\n" + _NEXT_REQUEST
    )


BAD_CASES = [
    pytest.param(
        _request(b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"),
        "mixes Transfer-Encoding and Content-Length",
        id="transfer-encoding-and-content-length",
    ),
    pytest.param(
        _request(b"Content-Length: 5\r\nContent-Length: 5\r\n"),
        "duplicate Content-Length headers",
        id="duplicate-content-length-same-value",
    ),
    pytest.param(
        _request(b"Content-Length: 5\r\nContent-Length: 6\r\n"),
        "duplicate Content-Length headers",
        id="duplicate-content-length-different-value",
    ),
    pytest.param(
        _request(b"Content-Length: 5, 5\r\n"),
        "multiple Content-Length values",
        id="comma-separated-content-length",
    ),
    pytest.param(
        _request(b"Content-Length: 1 0\r\n"),
        "bad Content-Length",
        id="content-length-internal-space",
    ),
    pytest.param(
        _request(b"Content-Length: 5\t5\r\n"),
        "bad Content-Length",
        id="content-length-internal-tab",
    ),
    pytest.param(
        _request(b"Content-Length: +5\r\n"),
        "bad Content-Length",
        id="content-length-plus-sign",
    ),
    pytest.param(
        _request(b"Content-Length: -5\r\n"),
        "bad Content-Length",
        id="content-length-minus-sign",
    ),
    pytest.param(
        _request(b"Content-Length: " + b"1" * 21 + b"\r\n"),
        "bad Content-Length",
        id="content-length-too-many-digits",
    ),
    pytest.param(
        b"GET /bad HTTP/1.1\r\n"
        b"Host: bad.example\r\n"
        b"X-Folded: first\r\n"
        b" second\r\n"
        b"\r\n" + _NEXT_REQUEST,
        "obsolete line folding",
        id="obs-fold-space",
    ),
    pytest.param(
        b"GET /bad HTTP/1.1\r\n"
        b"Host: bad.example\r\n"
        b"X-Folded: first\r\n"
        b"\tsecond\r\n"
        b"\r\n" + _NEXT_REQUEST,
        "obsolete line folding",
        id="obs-fold-tab",
    ),
    pytest.param(
        _bad_chunked(b"5;"),
        "malformed chunk header",
        id="chunk-ext-empty",
    ),
    pytest.param(
        _bad_chunked(b"5;foo="),
        "malformed chunk header",
        id="chunk-ext-missing-value",
    ),
    pytest.param(
        _bad_chunked(b'5;foo="unterminated'),
        "malformed chunk header",
        id="chunk-ext-unterminated-quote",
    ),
    pytest.param(
        _bad_chunked(b"5;foo bar"),
        "malformed chunk header",
        id="chunk-ext-space-in-name",
    ),
    pytest.param(
        _bad_chunked(b"5;foo=bar baz"),
        "malformed chunk header",
        id="chunk-ext-space-in-value",
    ),
    pytest.param(
        _bad_chunked(b'5;foo="a"junk'),
        "malformed chunk header",
        id="chunk-ext-junk-after-quote",
    ),
    pytest.param(
        _bad_chunked(b"5 ;foo=bar"),
        "malformed chunk header",
        id="chunk-ext-space-before-semicolon",
    ),
    pytest.param(
        _bad_trailer(b"Host: evil.example\r\n"),
        "forbidden trailer field",
        id="trailer-host",
    ),
    pytest.param(
        _bad_trailer(b"Content-Length: 10\r\n"),
        "forbidden trailer field",
        id="trailer-content-length",
    ),
    pytest.param(
        _bad_trailer(b"Transfer-Encoding: chunked\r\n"),
        "forbidden trailer field",
        id="trailer-transfer-encoding",
    ),
    pytest.param(
        _bad_trailer(b"X-Folded: first\r\n second\r\n"),
        "obsolete line folding",
        id="trailer-obs-fold",
    ),
]


@pytest.mark.parametrize("data, message", BAD_CASES)
def test_strict_mode_rejects_ambiguous_request(data: bytes, message: str) -> None:
    conn = _strict_conn()
    events, error, _ = _consume(conn, data, [data])

    assert error is not None
    assert message in str(error)
    assert conn.their_state is ERROR

    # The request that follows the bad one must never be delivered. Even
    # though its bytes may still be sitting in the receive buffer, asking for
    # another event can only fail.
    assert not any(
        type(event) is Request and event.target == b"/next" for event in events
    )
    # The bytes of the following request are still buffered, but the
    # connection is poisoned so they can never become events.
    assert b"GET /next" in conn.trailing_data[0]
    with pytest.raises(RemoteProtocolError):
        conn.next_event()


@pytest.mark.parametrize("data, message", BAD_CASES)
def test_byte_by_byte_feeding_reaches_the_same_rejection(
    data: bytes, message: str
) -> None:
    conn_all = _strict_conn()
    events_all, error_all, position_all = _consume(conn_all, data, [data])

    conn_byte = _strict_conn()
    events_byte, error_byte, position_byte = _consume(
        conn_byte, data, [data[i : i + 1] for i in range(len(data))]
    )

    assert error_all is not None
    assert error_byte is not None
    assert str(error_byte) == str(error_all)
    assert position_byte == position_all
    # The events produced before the rejection are identical. Data events may
    # be split differently depending on how the bytes arrived, so normalize
    # adjacent Data events before comparing.
    assert normalize_data_events(events_byte) == normalize_data_events(events_all)


@pytest.mark.parametrize("data, message", BAD_CASES)
def test_rejection_position_does_not_depend_on_split_points(
    data: bytes, message: str
) -> None:
    positions = set()
    for chunks in _chunkings(data):
        conn = _strict_conn()
        _, error, position = _consume(conn, data, chunks)
        assert error is not None
        assert message in str(error)
        assert conn.their_state is ERROR
        positions.add(position)

    # Every chunking must reject at the same byte offset. In particular, a
    # parser must not consume part of a following request before discovering
    # that the current one is ambiguous.
    assert len(positions) == 1, positions


_LEGAL_CHUNKED_REQUEST = (
    b"POST /ok HTTP/1.1\r\n"
    b"Host: ok.example\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
    b'5;foo=bar;quoted="a b"\r\n'
    b"hello\r\n"
    b"4;flag\r\n"
    b"body\r\n"
    b"0;end\r\n"
    b"Some-Trailer: yes\r\n"
    b"\r\n"
)


@pytest.mark.parametrize(
    "chunks",
    [
        pytest.param([_LEGAL_CHUNKED_REQUEST], id="single-feed"),
        pytest.param(
            [
                _LEGAL_CHUNKED_REQUEST[i : i + 1]
                for i in range(len(_LEGAL_CHUNKED_REQUEST))
            ],
            id="byte-by-byte",
        ),
    ],
)
def test_strict_mode_accepts_legal_chunked_request(chunks: Iterable[bytes]) -> None:
    conn = _strict_conn()
    events, error, position = _consume(conn, _LEGAL_CHUNKED_REQUEST, chunks)

    assert error is None
    assert position == len(_LEGAL_CHUNKED_REQUEST)
    # Data events may be split differently depending on how the bytes arrived,
    # so normalize adjacent Data events before comparing.
    assert normalize_data_events(events) == [
        Request(
            method="POST",
            target="/ok",
            headers=[
                ("Host", "ok.example"),
                ("Transfer-Encoding", "chunked"),
            ],
        ),
        Data(data=b"hellobody"),
        EndOfMessage(headers=[("Some-Trailer", "yes")]),
    ]
    assert conn.their_state is DONE


def test_strict_mode_accepts_100_continue() -> None:
    conn = _strict_conn()
    conn.receive_data(
        b"POST /upload HTTP/1.1\r\n"
        b"Host: upload.example\r\n"
        b"Content-Length: 4\r\n"
        b"Expect: 100-continue\r\n"
        b"\r\n"
    )

    assert conn.next_event() == Request(
        method="POST",
        target="/upload",
        headers=[
            ("Host", "upload.example"),
            ("Content-Length", "4"),
            ("Expect", "100-continue"),
        ],
    )
    assert conn.they_are_waiting_for_100_continue

    assert (
        conn.send(InformationalResponse(status_code=100, headers=[]))
        == b"HTTP/1.1 100 \r\n\r\n"
    )
    assert not conn.they_are_waiting_for_100_continue

    conn.receive_data(b"body")
    assert conn.next_event() == Data(data=b"body")
    assert conn.next_event() == EndOfMessage()


def test_strict_mode_accepts_two_pipelined_requests() -> None:
    # Control case: a strict connection must not reject ordinary keep-alive
    # reuse. Two complete requests arrive in one batch.
    conn = _strict_conn()
    conn.receive_data(
        b"GET /1 HTTP/1.1\r\nHost: one.example\r\n\r\n"
        b"GET /2 HTTP/1.1\r\nHost: two.example\r\n\r\n"
    )

    assert conn.next_event() == Request(
        method="GET", target="/1", headers=[("Host", "one.example")]
    )
    assert conn.next_event() == EndOfMessage()
    assert conn.their_state is DONE
    assert conn.next_event() is PAUSED

    conn.send(
        # A response body is required because the response has no explicit
        # framing headers.
        Response(status_code=200, headers=[])
    )
    conn.send(EndOfMessage())
    conn.start_next_cycle()

    # The reader is rebuilt for the new cycle and must still be in strict mode.
    assert conn.next_event() == Request(
        method="GET", target="/2", headers=[("Host", "two.example")]
    )
    assert conn.next_event() == EndOfMessage()
    assert conn.their_state is DONE


def test_default_mode_still_accepts_transfer_encoding_and_content_length() -> None:
    # Strict checking is opt-in; the historical behavior must be unchanged.
    # (Transfer-Encoding wins over Content-Length here.)
    conn = Connection(SERVER)
    data = (
        b"POST / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
        b"GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n"
    )
    events, error, _ = _consume(conn, data, [data])

    assert error is None
    assert events == [
        Request(
            method="POST",
            target="/",
            headers=[
                ("Host", "example.com"),
                ("Content-Length", "5"),
                ("Transfer-Encoding", "chunked"),
            ],
        ),
        EndOfMessage(),
    ]
    assert conn.their_state is DONE
