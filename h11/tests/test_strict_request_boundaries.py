"""Regression tests for the opt-in strict request boundary mode.

These tests are deliberately protocol-only: every byte comes from in-memory
buffers, there is no socket or proxy involved. The central security property
under test is that an ambiguous or malformed request is rejected at a fixed
point in the byte stream, no matter how the bytes are chunked when they
arrive, and that data pipelined behind the bad request can never be handed
out as a fresh request.
"""

from typing import List, Optional, Tuple

import pytest

import h11
from .._events import (
    Data,
    EndOfMessage,
    Event,
    InformationalResponse,
    Request,
    Response,
)
from .._readers import ChunkedReader, maybe_read_from_IDLE_client
from .._receivebuffer import ReceiveBuffer
from .._state import ERROR, SERVER
from .._util import LocalProtocolError, RemoteProtocolError

# A perfectly ordinary second request, used to prove that bytes pipelined
# behind a rejected request never escape as a new request.
PIPELINED_GET = b"GET /next HTTP/1.1\r\nHost: next.example\r\n\r\n"

HOST = b"Host: example.com\r\n"


def _strict_server() -> h11.Connection:
    return h11.Connection(h11.SERVER, strict_request_boundaries=True)


def _lenient_server() -> h11.Connection:
    return h11.Connection(h11.SERVER)


def _pump(conn: h11.Connection) -> List[Event]:
    """Drain every currently-parseable event out of the connection."""
    events: List[Event] = []
    while True:
        event = conn.next_event()
        if event in (h11.NEED_DATA, h11.PAUSED):
            return events
        assert isinstance(event, Event)
        events.append(event)


class Rejection(Exception):
    def __init__(self, offset: int, message: str, events: List[Event]) -> None:
        self.offset = offset
        self.message = message
        self.events = events


def _feed_chunks(chunks: List[bytes]) -> Tuple[h11.Connection, Rejection]:
    """Feed the given chunks one at a time, pumping after each.

    Returns the connection together with a :class:`Rejection` describing the
    first error. Its offset is the number of bytes the parser had *consumed*
    when it refused the stream (bytes delivered but still sitting in the
    receive buffer are excluded), which makes the position independent of how
    the bytes were split across calls.
    """
    conn = _strict_server()
    fed = 0
    events: List[Event] = []
    for chunk in chunks:
        # An empty chunk would signal EOF to receive_data; nothing here uses
        # that mechanism.
        if not chunk:
            continue
        conn.receive_data(chunk)
        fed += len(chunk)
        # Pump event-by-event rather than through a helper that builds a
        # list: an event already returned by next_event() must be recorded
        # even if a later next_event() in the same drain raises, otherwise
        # the recorded events would depend on how the bytes were chunked.
        while True:
            try:
                event = conn.next_event()
            except RemoteProtocolError as exc:
                consumed = fed - len(conn.trailing_data[0])
                return conn, Rejection(consumed, str(exc), events)
            if event in (h11.NEED_DATA, h11.PAUSED):
                break
            assert isinstance(event, Event)
            events.append(event)
    raise AssertionError("stream was accepted, expected a rejection")


def _event_type_names(events: List[Event]) -> List[str]:
    return [type(event).__name__ for event in events]


# ---------------------------------------------------------------------------
# The rejection table
# ---------------------------------------------------------------------------

# Each entry is (id, bad request bytes). Every entry must be rejected in
# strict mode, at a position independent of how the bytes are split up.
BAD_REQUESTS = [
    (
        "te_and_content_length",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n"
        + b"Content-Length: 5\r\n\r\n"
        + b"0\r\n\r\n",
    ),
    (
        "content_length_and_te",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5\r\n"
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"0\r\n\r\n",
    ),
    (
        "duplicate_content_length_same_value",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5\r\n"
        + b"Content-Length: 5\r\n\r\n"
        + b"hello",
    ),
    (
        "duplicate_content_length_different_values",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5\r\n"
        + b"Content-Length: 6\r\n\r\n"
        + b"hello!",
    ),
    (
        "obsolete_line_fold",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length:\r\n"
        + b" 5\r\n\r\n"
        + b"hello",
    ),
    (
        "obsolete_line_fold_unrelated_header",
        b"GET / HTTP/1.1\r\n"
        + HOST
        + b"X-Multi:\r\n"
        + b" one\r\n"
        + b" two\r\n\r\n",
    ),
    (
        "chunk_extension",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5; name=value\r\n"
        + b"hello\r\n"
        + b"0\r\n\r\n",
    ),
    (
        "chunk_header_trailing_whitespace",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5   \r\n"
        + b"hello\r\n"
        + b"0\r\n\r\n",
    ),
    (
        "trailer_host",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"0\r\n"
        + b"Host: evil.example\r\n\r\n",
    ),
    (
        "trailer_content_length",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"0\r\n"
        + b"Content-Length: 3\r\n\r\n",
    ),
    (
        "trailer_transfer_encoding",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"0\r\n"
        + b"Transfer-Encoding: chunked\r\n\r\n",
    ),
    (
        "content_length_trailing_whitespace",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5 \r\n\r\n"
        + b"hello",
    ),
    (
        "content_length_embedded_whitespace",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 1 2\r\n\r\n",
    ),
    (
        "content_length_plus_sign",
        b"POST / HTTP/1.1\r\n" + HOST + b"Content-Length: +5\r\n\r\n" + b"hello",
    ),
    (
        "content_length_comma_list",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5, 5\r\n\r\n"
        + b"hello",
    ),
    (
        "content_length_overlong_decimal",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: "
        + b"1" * 21
        + b"\r\n\r\n",
    ),
    (
        "content_length_hex",
        b"POST / HTTP/1.1\r\n" + HOST + b"Content-Length: 0x5\r\n\r\n" + b"hello",
    ),
]


@pytest.mark.parametrize(
    "case_id,data", BAD_REQUESTS, ids=[item[0] for item in BAD_REQUESTS]
)
def test_strict_rejects_each_framing_violation(case_id: str, data: bytes) -> None:
    # Whole-stream delivery: the message must be refused, not parsed.
    conn, rejection = _feed_chunks([data + PIPELINED_GET])
    assert conn.their_state is ERROR
    assert rejection.message
    # Header-section violations must not produce a Request event at all; body
    # violations may produce the Request for the bad message, but must never
    # surface the pipelined GET.
    for event in rejection.events:
        assert not (
            isinstance(event, Request) and event.target == b"/next"
        ), "pipelined request leaked out after a framing violation"


@pytest.mark.parametrize(
    "case_id,data", BAD_REQUESTS, ids=[item[0] for item in BAD_REQUESTS]
)
def test_rejection_position_is_split_independent(case_id: str, data: bytes) -> None:
    # Reference: feed one byte at a time and record exactly how many bytes
    # have been received when the parser first refuses.
    bytewise_conn, bytewise = _feed_chunks([bytes([byte]) for byte in data])
    canonical_offset = bytewise.offset
    assert 0 < canonical_offset <= len(data)

    # Now re-run with every possible two-chunk split.
    for split in range(len(data) + 1):
        conn, rejection = _feed_chunks([data[:split], data[split:]])
        assert conn.their_state is ERROR
        assert rejection.message == bytewise.message, (
            f"split {split}: error message changed",
        )
        # The parser always consumes the same number of bytes before it
        # refuses the stream, regardless of where the delivery was split.
        assert rejection.offset == canonical_offset, (
            f"split {split}: rejection position drifted "
            f"({rejection.offset} != {canonical_offset})"
        )
        assert _event_type_names(rejection.events) == _event_type_names(
            bytewise.events
        ), f"split {split}: events before the error differ"

        # Splits strictly before the fatal offset must not fail early.
        if split < canonical_offset:
            early = _strict_server()
            early.receive_data(data[:split])
            assert early.their_state is not ERROR
            _pump(early)
            assert early.their_state is not ERROR


@pytest.mark.parametrize(
    "case_id,data", BAD_REQUESTS, ids=[item[0] for item in BAD_REQUESTS]
)
def test_pipelined_request_after_bad_one_is_never_delivered(
    case_id: str, data: bytes
) -> None:
    stream = data + PIPELINED_GET
    conn, rejection = _feed_chunks([stream])

    assert conn.their_state is ERROR
    delivered_targets = [
        event.target for event in rejection.events if isinstance(event, Request)
    ]
    assert b"/next" not in delivered_targets

    # Everything unprocessed stays in the buffer instead of becoming events.
    trailing, closed = conn.trailing_data
    assert not closed
    assert PIPELINED_GET in trailing

    # The connection is poisoned: further calls keep failing, and it cannot
    # be recycled for another cycle.
    with pytest.raises(RemoteProtocolError):
        conn.next_event()
    with pytest.raises(LocalProtocolError):
        conn.start_next_cycle()


def test_byte_by_byte_feed_matches_whole_stream() -> None:
    # Explicit spot-check of the motivating TE/CL smuggling prefix, with the
    # second GET glued directly to it, fed a single byte per call.
    data = (
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n"
        + b"Content-Length: 5\r\n\r\n"
        + b"0\r\n\r\n"
        + PIPELINED_GET
    )
    conn = _strict_server()
    saw_error: Optional[RemoteProtocolError] = None
    for byte in data:
        conn.receive_data(bytes([byte]))
        if saw_error is None:
            try:
                _pump(conn)
            except RemoteProtocolError as exc:
                saw_error = exc
    assert saw_error is not None
    assert "Transfer-Encoding and Content-Length" in str(saw_error)
    assert conn.their_state is ERROR
    # The GET was still in the buffer when the connection died.
    assert PIPELINED_GET in conn.trailing_data[0]


# ---------------------------------------------------------------------------
# Positive controls: legal traffic must keep working in strict mode
# ---------------------------------------------------------------------------


def test_strict_accepts_valid_chunked_request() -> None:
    data = (
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5\r\nhello\r\n"
        + b"6\r\n, worl\r\n"
        + b"1\r\nd\r\n"
        + b"0\r\n"
        + b'Etag: "abc"\r\n\r\n'
    )
    conn = _strict_server()
    conn.receive_data(data)
    events = _pump(conn)

    assert isinstance(events[0], Request)
    assert events[0].target == b"/"
    body = b"".join(bytes(event.data) for event in events if isinstance(event, Data))
    assert body == b"hello, world"
    end = events[-1]
    assert isinstance(end, EndOfMessage)
    assert end.headers == [(b"etag", b'"abc"')]
    assert conn.their_state is h11.DONE


def test_strict_accepts_content_length_request() -> None:
    # Leading OWS after the colon is grammar-legal and must stay accepted.
    data = (
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length:\t5\r\n\r\n"
        + b"hello"
    )
    conn = _strict_server()
    conn.receive_data(data)
    events = _pump(conn)
    assert isinstance(events[0], Request)
    assert isinstance(events[1], Data)
    assert bytes(events[1].data) == b"hello"
    assert isinstance(events[2], EndOfMessage)


def test_strict_accepts_empty_body_get() -> None:
    conn = _strict_server()
    conn.receive_data(b"GET / HTTP/1.1\r\n" + HOST + b"\r\n")
    events = _pump(conn)
    assert isinstance(events[0], Request)
    assert isinstance(events[1], EndOfMessage)
    assert conn.their_state is h11.DONE


def test_strict_100_continue_flow() -> None:
    data = (
        b"POST /upload HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5\r\n"
        + b"Expect: 100-continue\r\n\r\n"
        + b"hello"
    )
    conn = _strict_server()
    conn.receive_data(data)
    request = conn.next_event()
    assert isinstance(request, Request)
    assert conn.they_are_waiting_for_100_continue

    conn.send(InformationalResponse(status_code=100, headers=[]))
    events = _pump(conn)
    assert isinstance(events[0], Data)
    assert bytes(events[0].data) == b"hello"
    assert isinstance(events[1], EndOfMessage)


def test_strict_pipelining_two_valid_requests_share_connection() -> None:
    # Control counterpart to the bad-request tests: two ordinary requests
    # on one connection must both parse cleanly.
    first = (
        b"POST /1 HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5\r\nhello\r\n"
        + b"0\r\n\r\n"
    )
    second = b"GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    conn = _strict_server()
    conn.receive_data(first + second)

    first_events = _pump(conn)
    assert isinstance(first_events[0], Request)
    assert first_events[0].target == b"/1"
    assert isinstance(first_events[-1], EndOfMessage)
    assert conn.next_event() is h11.PAUSED

    conn.send(Response(status_code=200, headers=[]))
    conn.send(EndOfMessage())
    conn.start_next_cycle()

    second_events = _pump(conn)
    assert isinstance(second_events[0], Request)
    assert second_events[0].target == b"/2"
    assert isinstance(second_events[1], EndOfMessage)

    conn.send(Response(status_code=200, headers=[]))
    conn.send(EndOfMessage())
    assert conn.their_state is h11.DONE


def test_strict_pipelining_byte_feeds() -> None:
    # Same two-request stream, but delivered one byte at a time.
    first = b"GET /1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n12345"
    second = b"GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    conn = _strict_server()
    for byte in first + second:
        conn.receive_data(bytes([byte]))
    events = _pump(conn)
    assert [type(event) for event in events] == [Request, Data, EndOfMessage]
    assert isinstance(events[0], Request)
    assert events[0].target == b"/1"

    conn.send(Response(status_code=200, headers=[]))
    conn.send(EndOfMessage())
    conn.start_next_cycle()
    events = _pump(conn)
    assert [type(event) for event in events] == [Request, EndOfMessage]
    assert isinstance(events[0], Request)
    assert events[0].target == b"/2"


# ---------------------------------------------------------------------------
# Default behavior stays compatible
# ---------------------------------------------------------------------------

# Inputs that strict mode newly rejects but the historical parser accepts.
LENIENT_CASES = [
    (
        "te_and_content_length",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n"
        + b"Content-Length: 5\r\n\r\n"
        + b"0\r\n\r\n",
    ),
    (
        "duplicate_content_length_same_value",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
    ),
    (
        "obsolete_line_fold",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length:\r\n 5\r\n\r\nhello",
    ),
    (
        "chunk_extension",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5; name=value\r\nhello\r\n0\r\n\r\n",
    ),
    (
        "chunk_header_trailing_whitespace",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"5   \r\nhello\r\n0\r\n\r\n",
    ),
    (
        "trailer_host",
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"0\r\nHost: evil.example\r\n\r\n",
    ),
    (
        "content_length_trailing_whitespace",
        b"POST / HTTP/1.1\r\n" + HOST + b"Content-Length: 5 \r\n\r\nhello",
    ),
]


@pytest.mark.parametrize(
    "case_id,data", LENIENT_CASES, ids=[item[0] for item in LENIENT_CASES]
)
def test_default_connection_keeps_legacy_behavior(case_id: str, data: bytes) -> None:
    conn = _lenient_server()
    conn.receive_data(data)
    events = _pump(conn)
    assert conn.their_state is not ERROR
    assert any(isinstance(event, Request) for event in events)
    assert isinstance(events[-1], EndOfMessage)


def test_default_and_strict_agree_on_unconditionally_bad_lengths() -> None:
    # These were already invalid before strict mode existed; both modes must
    # refuse them rather than picking different interpretations.
    bad_values = [b"+5", b"0x5", b"1" * 21, b"1 2"]
    for value in bad_values:
        data = (
            b"POST / HTTP/1.1\r\n"
            + HOST
            + b"Content-Length: "
            + value
            + b"\r\n\r\n"
        )
        for strict in (False, True):
            conn = h11.Connection(h11.SERVER, strict_request_boundaries=strict)
            conn.receive_data(data)
            with pytest.raises(RemoteProtocolError):
                _pump(conn)
            assert conn.their_state is ERROR


def test_strict_additionally_rejects_comma_separated_lengths() -> None:
    # Legacy parsing treats "5, 5" as a repeated identical length; strict
    # mode rejects the comma list on the wire. Both routes must reach a
    # single verdict inside each mode.
    data = (
        b"POST / HTTP/1.1\r\n"
        + HOST
        + b"Content-Length: 5, 5\r\n\r\nhello"
    )

    legacy = _lenient_server()
    legacy.receive_data(data)
    events = _pump(legacy)
    assert isinstance(events[0], Request)
    assert events[0].headers == [(b"host", b"example.com"), (b"content-length", b"5")]

    strict = _strict_server()
    strict.receive_data(data)
    with pytest.raises(RemoteProtocolError):
        _pump(strict)
    assert strict.their_state is ERROR


# ---------------------------------------------------------------------------
# The flag is inbound-only and server-side only
# ---------------------------------------------------------------------------


def test_strict_flag_on_client_does_not_change_response_parsing() -> None:
    # A client with the flag set still uses the lenient response readers.
    conn = h11.Connection(h11.CLIENT, strict_request_boundaries=True)
    conn.receive_data(
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"0\r\n\r\n"
    )
    events = _pump(conn)
    assert isinstance(events[0], Response)
    assert isinstance(events[-1], EndOfMessage)
    assert conn.their_state is h11.DONE


def test_strict_flag_does_not_affect_sending() -> None:
    # Outbound serialization keeps the historical Transfer-Encoding-wins
    # behavior even when the flag is enabled.
    conn = h11.Connection(h11.CLIENT, strict_request_boundaries=True)
    wire = conn.send(
        Request(
            method="POST",
            target="/",
            headers=[
                ("Host", "example.com"),
                ("Transfer-Encoding", "chunked"),
                ("Content-Length", "5"),
            ],
        )
    )
    assert b"Transfer-Encoding: chunked" in wire
    assert b"Content-Length: 5" in wire


# ---------------------------------------------------------------------------
# Reader-level checks
# ---------------------------------------------------------------------------


def test_strict_chunked_reader_rejects_extension_bytewise() -> None:
    data = b"5; name=value\r\nhello\r\n0\r\n\r\n"
    reader = ChunkedReader(strict=True)
    buf = ReceiveBuffer()
    with pytest.raises(LocalProtocolError):
        for i in range(len(data)):
            reader(buf)
            buf += data[i : i + 1]
        reader(buf)


def test_strict_chunked_reader_accepts_plain_chunks_bytewise() -> None:
    data = b"5\r\nhello\r\n0\r\n\r\n"
    reader = ChunkedReader(strict=True)
    buf = ReceiveBuffer()
    events: List[Event] = []
    for i in range(len(data)):
        event = reader(buf)
        if event is not None:
            events.append(event)
        buf += data[i : i + 1]
    event = reader(buf)
    if event is not None:
        events.append(event)
    body = b"".join(bytes(event.data) for event in events if isinstance(event, Data))
    assert body == b"hello"
    assert isinstance(events[-1], EndOfMessage)


def test_strict_request_reader_rejects_folding() -> None:
    buf = ReceiveBuffer()
    buf += (
        b"GET / HTTP/1.1\r\n"
        + HOST
        + b"X-Multi:\r\n one\r\n\r\n"
    )
    with pytest.raises(LocalProtocolError):
        maybe_read_from_IDLE_client(buf, strict=True)


def test_strict_request_reader_accepts_normal_headers() -> None:
    buf = ReceiveBuffer()
    buf += b"GET / HTTP/1.1\r\n" + HOST + b"Accept: text/plain\r\n\r\n"
    request = maybe_read_from_IDLE_client(buf, strict=True)
    assert isinstance(request, Request)
    assert request.headers == [
        (b"host", b"example.com"),
        (b"accept", b"text/plain"),
    ]


def test_constructor_rejects_bad_role() -> None:
    with pytest.raises(ValueError):
        h11.Connection(
            object(), strict_request_boundaries=True  # type: ignore[arg-type]
        )
