"""Verify precise byte consumption at identical malformed boundaries across feed splits."""
import h11,pytest
PREFIX=b'POST /upload HTTP/1.1\r\nHost: local\r\n'
NEXT=b'GET /must-not-run HTTP/1.1\r\nHost: local\r\n\r\n'
WIRES={
 'te-cl':PREFIX+b'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n',
 'duplicate-cl':PREFIX+b'Content-Length: 1\r\nContent-Length: 1\r\n\r\nx',
 'bad-extension':PREFIX+b'Transfer-Encoding: chunked\r\n\r\n1;key==value\r\nx\r\n0\r\n\r\n',
 'forbidden-trailer':PREFIX+b'Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nHost: bad\r\n\r\n',
}
def rejection(parts):
    client=h11.Connection(h11.SERVER,strict_request_boundaries=True);fed=0;targets=[]
    for part in parts:
        if not part:continue  # Empty receive_data is EOF, not a no-op chunk.
        fed+=len(part)
        try:
            client.receive_data(part)
            for _ in range(64):
                event=client.next_event()
                if event in (h11.NEED_DATA,h11.PAUSED) or isinstance(event,h11.ConnectionClosed):break
                if isinstance(event,h11.Request):targets.append(event.target)
            else:pytest.fail('Event pump failed to reach input boundary')
        except h11.RemoteProtocolError as exc:
            assert client.their_state is h11.ERROR and b'/must-not-run' not in targets
            return (fed-len(client.trailing_data[0]),type(exc).__name__,str(exc))
    pytest.fail('Malformed boundary was not rejected')

@pytest.mark.parametrize('name',list(WIRES))
def test_consumed_error_position_same_for_every_cut(name):
    wire=WIRES[name]+NEXT;expected=rejection([wire])
    assert rejection([bytes([b]) for b in wire])==expected
    for cut in range(len(wire)+1):assert rejection([wire[:cut],wire[cut:]])==expected,(name,cut)

def test_eof_event_pump_is_finite():
    client=h11.Connection(h11.SERVER,strict_request_boundaries=True);client.receive_data(b'')
    assert isinstance(client.next_event(),h11.ConnectionClosed)
